//! The vault open/save orchestration — ties every layer together (the v0 `vault-core` API).
//!
//! Open:  parse header (C7/C8/C9 hash, C2 ceiling) → unwrap the data key from the password stanza
//!        (C5) → verify the data-key-keyed header HMAC (C9/G0.2) → de-frame the HmacBlockStream
//!        (C10) → STREAM-decrypt the body (C1) → parse the payload (C16/C18).
//! Save:  regenerate `master_seed` + `nonce_prefix` (a body-writing save — C8/C1), bump
//!        `vault_version` (C16), serialize → STREAM-encrypt → HmacBlockStream-frame → seal header.
//!
//! NOTE (C19): the inner-stream layer is fully applied (see `format::inner_stream`). Protected field
//! values are ChaCha20 stream-encrypted under the per-save `inner_stream_key` inside the AEAD payload
//! (double-encrypted at rest), and after open they stay **encrypted in RAM** (`Protected::Sealed`),
//! decrypted only on field access. Confidentiality at rest is anchored by the outer AEAD (C1); the
//! inner stream is defense-in-depth there and the primary defense in memory (a swap leak or partial
//! heap disclosure of the payload does not directly expose secret bytes).

use secrecy::ExposeSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    stream, ARGON2_DEFAULT_M_COST_KIB, ARGON2_DEFAULT_P_COST, ARGON2_DEFAULT_T_COST,
};
use crate::envelope;
use crate::format::entry::{Entry, Protected};
use crate::format::header::KDF_ALGORITHM_ARGON2ID;
use crate::format::payload::INNER_STREAM_KEY_LEN;
use crate::format::stanza::kind;
use crate::format::{block_stream, Header, KdfParams, Payload};
use crate::memory::DataKey;
use crate::{Error, Result, FORMAT_VERSION};

/// A YubiKey HMAC responder: given the 32-byte challenge stored in a 2FA stanza, it returns the
/// key's HMAC-SHA1 response (the physical-tap step). Lives behind a `dyn` so `vault-core` never
/// depends on the USB layer (the CLI/GUI supply the closure; `vault-hardware` does the I/O).
type HwResponder<'a> = &'a mut dyn FnMut(&[u8; 32]) -> Result<Zeroizing<Vec<u8>>>;

/// An opened (unlocked) vault: the plaintext header, the unwrapped data key, and the decrypted
/// payload. Secrets live in zeroizing/`Secret` types (C11).
#[derive(Debug)]
pub struct Vault {
    header: Header,
    data_key: DataKey,
    payload: Payload,
}

fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Crypto)
}

impl Vault {
    /// Create a new, empty vault protected by `password` with the given Argon2id parameters.
    pub fn create(password: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Vault> {
        let mut vault_id = [0u8; 16];
        let mut salt = [0u8; 32];
        let mut master_seed = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        let mut inner = [0u8; INNER_STREAM_KEY_LEN];
        random_bytes(&mut vault_id)?;
        random_bytes(&mut salt)?;
        random_bytes(&mut master_seed)?;
        random_bytes(&mut nonce_prefix)?;
        random_bytes(&mut inner)?;

        let data_key = envelope::generate_data_key()?;
        let stanza = envelope::wrap_password_stanza(
            data_key.expose_secret(),
            password,
            &salt,
            &vault_id,
            m_cost,
            t_cost,
            p_cost,
        )?;

        let header = Header {
            format_version: FORMAT_VERSION,
            vault_id,
            kdf: KdfParams {
                algorithm: KDF_ALGORITHM_ARGON2ID,
                m_cost,
                t_cost,
                p_cost,
                salt,
            },
            master_seed,
            nonce_prefix,
            stanzas: vec![stanza],
            header_hash: [0; 32],
            header_hmac: [0; 32],
        };
        let payload = Payload {
            inner_stream_key: Protected::new(inner.to_vec()),
            pad_mode: crate::pad::PadMode::None,
            vault_version: 0,
            entries: Vec::new(),
            usage: crate::frecency::FrecencyStore::new(),
        };
        inner.zeroize();
        Ok(Vault {
            header,
            data_key,
            payload,
        })
    }

    /// Create a new vault with the recommended default Argon2id parameters (C2).
    pub fn create_default(password: &[u8]) -> Result<Vault> {
        Vault::create(
            password,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
        )
    }

    /// Open and unlock a vault from its raw bytes with `password`.
    ///
    /// A wrong password (or a tampered wrapped key) fails at the stanza unwrap with the ambiguous
    /// [`Error::HeaderAuth`]; a tampered header field after a valid unwrap fails the keyed HMAC with
    /// [`Error::HeaderTampered`]; body tampering fails with [`Error::BodyAuth`]. No plaintext is
    /// released before every layer's tag verifies.
    pub fn open(bytes: &[u8], password: &[u8]) -> Result<Vault> {
        Self::open_inner(bytes, password, None, None)
    }

    /// Open a vault that may be protected by a YubiKey second factor (UC-09 AND model).
    ///
    /// If the file has a composite 2FA stanza, `respond` is called with the stored 32-byte challenge
    /// and must return the YubiKey's HMAC-SHA1 response (the physical-tap step); both the password
    /// and that response are required. For a password-only vault `respond` is never invoked, so this
    /// is a safe superset of [`Vault::open`].
    pub fn open_2fa(
        bytes: &[u8],
        password: &[u8],
        mut respond: impl FnMut(&[u8; 32]) -> Result<Zeroizing<Vec<u8>>>,
    ) -> Result<Vault> {
        Self::open_inner(bytes, password, Some(&mut respond), None)
    }

    /// Open a vault protected by a **keyfile** second factor: both the password and the exact
    /// keyfile bytes are required. A safe superset of [`Vault::open`] for non-keyfile vaults.
    pub fn open_keyfile(bytes: &[u8], password: &[u8], keyfile: &[u8]) -> Result<Vault> {
        Self::open_inner(bytes, password, None, Some(keyfile))
    }

    fn open_inner(
        bytes: &[u8],
        password: &[u8],
        hw: Option<HwResponder<'_>>,
        keyfile: Option<&[u8]>,
    ) -> Result<Vault> {
        let header = Header::parse(bytes)?;
        let data_key = Self::unwrap_data_key(&header, password, hw, keyfile)?;

        // C9 step 4: the factor is now proven valid, so a header HMAC mismatch is real tampering.
        header.verify_hmac(data_key.expose_secret())?;

        let body = &bytes[header.on_disk_len()..];
        let stream_ct = block_stream::read(data_key.expose_secret(), &header.master_seed, body)?;
        let plaintext =
            stream::decrypt(data_key.expose_secret(), &header.nonce_prefix, &stream_ct)?;
        // Lock the decrypted payload's pages off swap while it is in plaintext (C12).
        let _payload_lock = crate::memory::PageLock::new(&plaintext);
        let payload = Payload::parse(&plaintext)?;

        Ok(Vault {
            header,
            data_key,
            payload,
        })
    }

    /// Recover the data key from the appropriate stanza: the composite 2FA stanza when a hardware
    /// responder is available, otherwise a password stanza (a normal vault, or the recovery stanza
    /// of a 2FA vault unlocked by its recovery code passed as `password`).
    fn unwrap_data_key(
        header: &Header,
        password: &[u8],
        hw: Option<HwResponder<'_>>,
        keyfile: Option<&[u8]>,
    ) -> Result<DataKey> {
        let (m, t, p) = (header.kdf.m_cost, header.kdf.t_cost, header.kdf.p_cost);
        if let Some(respond) = hw {
            if let Some(s) = header
                .stanzas
                .iter()
                .find(|s| s.stanza_type == kind::PW_YUBIKEY)
            {
                let challenge = envelope::yubikey_challenge(s)?;
                let resp = respond(&challenge)?;
                return envelope::unwrap_yubikey_2fa_stanza(
                    s,
                    password,
                    &resp,
                    &header.kdf.salt,
                    &header.vault_id,
                    m,
                    t,
                    p,
                );
            }
        }
        if let Some(kf) = keyfile {
            if let Some(s) = header
                .stanzas
                .iter()
                .find(|s| s.stanza_type == kind::PW_KEYFILE)
            {
                return envelope::unwrap_keyfile_2fa_stanza(
                    s,
                    password,
                    kf,
                    &header.kdf.salt,
                    &header.vault_id,
                    m,
                    t,
                    p,
                );
            }
        }
        let s = header
            .stanzas
            .iter()
            .find(|s| s.stanza_type == kind::PASSWORD)
            .ok_or(Error::HeaderAuth)?;
        envelope::unwrap_password_stanza(s, password, &header.kdf.salt, &header.vault_id, m, t, p)
    }

    /// Whether opening this serialized vault requires a YubiKey (it carries a composite 2FA stanza).
    pub fn requires_yubikey(bytes: &[u8]) -> bool {
        Header::parse(bytes)
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::PW_YUBIKEY))
            .unwrap_or(false)
    }

    /// Whether opening this serialized vault requires a keyfile second factor.
    pub fn requires_keyfile(bytes: &[u8]) -> bool {
        Header::parse(bytes)
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::PW_KEYFILE))
            .unwrap_or(false)
    }

    /// Whether this opened vault is protected by any second factor (YubiKey or keyfile).
    pub fn is_2fa(&self) -> bool {
        self.header
            .stanzas
            .iter()
            .any(|s| matches!(s.stanza_type, kind::PW_YUBIKEY | kind::PW_KEYFILE))
    }

    /// Enroll a YubiKey as a **required** second factor (UC-09 AND model). Replaces the password
    /// stanza with a composite password+YubiKey stanza, plus a recovery-code stanza (anti-lockout).
    ///
    /// `password` is the current master password (re-wrapped into the composite), `hw_response` the
    /// key's HMAC of `challenge`, and `recovery_code` a high-entropy fallback the caller shows the
    /// user exactly once. The caller MUST `save()` afterward.
    pub fn enroll_yubikey_2fa(
        &mut self,
        password: &[u8],
        hw_response: &[u8],
        challenge: &[u8; 32],
        recovery_code: &[u8],
    ) -> Result<()> {
        let salt = self.header.kdf.salt;
        let vid = self.header.vault_id;
        let (m, t, p) = (
            self.header.kdf.m_cost,
            self.header.kdf.t_cost,
            self.header.kdf.p_cost,
        );
        let dk = Zeroizing::new(*self.data_key.expose_secret());
        let yubikey = envelope::wrap_yubikey_2fa_stanza(
            &dk,
            password,
            hw_response,
            challenge,
            &salt,
            &vid,
            m,
            t,
            p,
        )?;
        let recovery = envelope::wrap_password_stanza(&dk, recovery_code, &salt, &vid, m, t, p)?;
        self.header.stanzas = vec![yubikey, recovery];
        Ok(())
    }

    /// Enroll a **keyfile** as a required second factor. Replaces the password stanza with a
    /// composite password+keyfile stanza plus a recovery-code stanza (anti-lockout). The caller MUST
    /// `save()` afterward.
    pub fn enroll_keyfile_2fa(
        &mut self,
        password: &[u8],
        keyfile: &[u8],
        recovery_code: &[u8],
    ) -> Result<()> {
        let salt = self.header.kdf.salt;
        let vid = self.header.vault_id;
        let (m, t, p) = (
            self.header.kdf.m_cost,
            self.header.kdf.t_cost,
            self.header.kdf.p_cost,
        );
        let dk = Zeroizing::new(*self.data_key.expose_secret());
        let kf = envelope::wrap_keyfile_2fa_stanza(&dk, password, keyfile, &salt, &vid, m, t, p)?;
        let recovery = envelope::wrap_password_stanza(&dk, recovery_code, &salt, &vid, m, t, p)?;
        self.header.stanzas = vec![kf, recovery];
        Ok(())
    }

    /// Serialize and encrypt the vault to its on-disk bytes (a body-writing save).
    ///
    /// Regenerates `master_seed` and `nonce_prefix` (so the keystream and block-HMAC salts are
    /// fresh — C1/C8/C1-keystream-reuse fix) and the inner-stream key (C19), and increments
    /// `vault_version` by one (C16).
    pub fn save(&mut self) -> Result<Vec<u8>> {
        random_bytes(&mut self.header.master_seed)?;
        random_bytes(&mut self.header.nonce_prefix)?;
        let mut inner = [0u8; INNER_STREAM_KEY_LEN];
        random_bytes(&mut inner)?;
        self.payload.inner_stream_key = Protected::new(inner.to_vec());
        inner.zeroize();
        self.payload.vault_version += 1;

        // Serialize, then (UC-07 §3.2) pad the plaintext to its size bucket *inside* the AEAD: the
        // padding bytes follow the END marker (which the parser ignores) and are encrypted +
        // authenticated, so the on-disk size leaks only O(log log L) bits.
        let mut plaintext = Zeroizing::new(self.payload.serialize());
        let target = self.payload.pad_mode.padded_len(plaintext.len());
        plaintext.resize(target, 0u8);
        // Lock the serialized plaintext's pages off swap while it exists (C12).
        let _payload_lock = crate::memory::PageLock::new(&plaintext);
        let stream_ct = stream::encrypt(
            self.data_key.expose_secret(),
            &self.header.nonce_prefix,
            &plaintext,
        )?;
        let body = block_stream::frame(
            self.data_key.expose_secret(),
            &self.header.master_seed,
            &stream_ct,
        );

        self.header.seal(self.data_key.expose_secret());
        let mut out = self.header.serialize();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// The current monotonic version counter (C16).
    pub fn version(&self) -> u64 {
        self.payload.vault_version
    }

    /// The 16-byte random vault id (stable for the life of the vault) — used to locate the local
    /// rollback anchor (C16) without exposing any other header field.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.header.vault_id
    }

    /// The payload size-padding policy (UC-07 §3.2).
    pub fn padding(&self) -> crate::pad::PadMode {
        self.payload.pad_mode
    }

    /// Set the payload size-padding policy; it takes effect on the next [`Vault::save`] and is
    /// persisted inside the encrypted payload (UC-07 §3.2).
    pub fn set_padding(&mut self, mode: crate::pad::PadMode) {
        self.payload.pad_mode = mode;
    }

    /// All entries (after unlock).
    pub fn entries(&self) -> &[Entry] {
        &self.payload.entries
    }

    /// Append an entry.
    pub fn add_entry(&mut self, entry: Entry) {
        self.payload.entries.push(entry);
    }

    /// Case-insensitive substring search over entry titles and tags (in-memory only — SC2/C18).
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let q = query.to_lowercase();
        self.payload
            .entries
            .iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// UC-19 fuzzy omni-search: rank entries by fuzzy match over **non-secret metadata only**
    /// (title/username/url/tags — constraint C35), nudged by per-entry usage (frecency, P6). `now`
    /// is unix seconds, used for recency. Returns hits best-first; an empty query lists all entries
    /// (recent/frequent first). In-memory only — no index is read or written (C36).
    pub fn find(&self, query: &str, now: u64) -> Vec<crate::search::Hit<'_>> {
        let mut engine = crate::search::Engine::new();
        let hits = engine.search(&self.payload.entries, query);
        crate::search::blend_frecency(hits, |id| self.payload.usage.score(id, now))
    }

    /// Record that the entry `id` was used (selected/copied) at `now` (unix seconds): bumps its
    /// frecency so it ranks higher next time. Persisted on the next [`Vault::save`], inside the
    /// encrypted payload (C36). No-op effect on disk until saved.
    pub fn record_use(&mut self, id: [u8; 16], now: u64) {
        self.payload.usage.record(id, now);
    }

    /// Find an entry by exact (case-insensitive) title.
    pub fn get(&self, title: &str) -> Option<&Entry> {
        let t = title.to_lowercase();
        self.payload
            .entries
            .iter()
            .find(|e| e.title.to_lowercase() == t)
    }

    /// Find an entry by exact (case-insensitive) title, mutably (for `edit`).
    pub fn entry_mut(&mut self, title: &str) -> Option<&mut Entry> {
        let t = title.to_lowercase();
        self.payload
            .entries
            .iter_mut()
            .find(|e| e.title.to_lowercase() == t)
    }

    /// Remove an entry by exact (case-insensitive) title. Returns whether one was removed. Also
    /// drops the removed entry's usage record so the frecency store stays bounded (UC-19).
    pub fn remove(&mut self, title: &str) -> bool {
        let t = title.to_lowercase();
        let before = self.payload.entries.len();
        let mut removed_ids = Vec::new();
        self.payload.entries.retain(|e| {
            let keep = e.title.to_lowercase() != t;
            if !keep {
                removed_ids.push(e.id);
            }
            keep
        });
        for id in &removed_ids {
            self.payload.usage.forget(id);
        }
        self.payload.entries.len() != before
    }

    /// Classify the stored Argon2id parameters against policy (constraint C2). `BelowFloor` means
    /// the caller should warn and offer `upgrade-kdf`.
    pub fn kdf_strength(&self) -> crate::crypto::KdfStrength {
        crate::crypto::validate_kdf_params(
            self.header.kdf.m_cost,
            self.header.kdf.t_cost,
            self.header.kdf.p_cost,
        )
        .unwrap_or(crate::crypto::KdfStrength::BelowFloor)
    }

    /// Re-wrap the password stanza under new Argon2id parameters (constraint C2 `upgrade-kdf`).
    ///
    /// The data key and salt are unchanged (so the payload need not be re-encrypted for the key to
    /// stay valid), but the caller MUST `save()` afterward — a full body-writing save that bumps the
    /// version counter (G0.3) so a sync backend cannot serve the old weak-KDF file undetected.
    /// Requires the current password to re-derive the wrapping key.
    pub fn change_kdf(
        &mut self,
        password: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<()> {
        let new_stanza = envelope::wrap_password_stanza(
            self.data_key.expose_secret(),
            password,
            &self.header.kdf.salt,
            &self.header.vault_id,
            m_cost,
            t_cost,
            p_cost,
        )?;
        for s in &mut self.header.stanzas {
            if s.stanza_type == kind::PASSWORD {
                *s = new_stanza;
                break;
            }
        }
        self.header.kdf.m_cost = m_cost;
        self.header.kdf.t_cost = t_cost;
        self.header.kdf.p_cost = p_cost;
        Ok(())
    }

    /// Enrolled unlock stanzas (types only — no secret material; C21 `vault stanzas list`).
    pub fn stanzas(&self) -> &[crate::format::Stanza] {
        &self.header.stanzas
    }

    /// Remove every stanza of `stanza_type`. Password stanzas are irremovable (C5).
    pub fn remove_stanza_type(&mut self, stanza_type: u8) -> Result<()> {
        if stanza_type == kind::PASSWORD {
            return Err(Error::Hardware(
                "password stanza cannot be removed (constraint C5)".into(),
            ));
        }
        let before = self.header.stanzas.len();
        self.header
            .stanzas
            .retain(|s| s.stanza_type != stanza_type);
        if self.header.stanzas.len() == before {
            return Err(Error::Hardware(format!(
                "no {:?} stanza enrolled",
                crate::format::stanza::kind_name(stanza_type)
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::entry::Entry;

    // Fast Argon2id params for tests.
    const M: u32 = 64;
    const T: u32 = 1;
    const P: u32 = 1;

    fn entry(title: &str, pw: &[u8]) -> Entry {
        Entry {
            id: [0; 16],
            title: title.into(),
            username: "u".into(),
            password: Protected::new(pw.to_vec()),
            url: String::new(),
            notes: String::new(),
            tags: vec!["work".into()],
            otp_secret: None,
            created_at: 0,
            modified_at: 0,
            expires_at: None,
            custom_fields: vec![],
        }
    }

    #[test]
    fn create_save_open_round_trip() {
        let mut v = Vault::create(b"hunter2", M, T, P).unwrap();
        v.add_entry(entry("github", b"ghp_secret"));
        v.add_entry(entry("aws-prod", b"AKIA_secret"));
        let bytes = v.save().unwrap();

        let opened = Vault::open(&bytes, b"hunter2").unwrap();
        assert_eq!(opened.version(), 1);
        assert_eq!(opened.entries().len(), 2);
        let e = opened.get("github").unwrap();
        assert_eq!(&e.password.expose()[..], b"ghp_secret");
    }

    #[test]
    fn find_ranks_fuzzy_then_frecency_and_persists() {
        // Distinct ids so frecency keys don't collide (the shared `entry()` helper uses [0;16]).
        fn e(id: u8, title: &str) -> Entry {
            let mut x = entry(title, b"pw");
            x.id = [id; 16];
            x.tags = vec![]; // keep "git" from matching the default "work" tag
            x
        }
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(e(1, "github"));
        v.add_entry(e(2, "gitlab"));
        v.add_entry(e(3, "aws-prod"));

        // Fuzzy filters to the two git* entries; equal-quality prefix → deterministic alpha order.
        let hits = v.find("git", 10_000);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].entry.title, "github");

        // Use gitlab repeatedly → its frecency nudge lifts it above the equal-fuzzy github (P6).
        for _ in 0..3 {
            v.record_use([2u8; 16], 10_000);
        }
        assert_eq!(v.find("git", 10_050)[0].entry.title, "gitlab");

        // Usage is persisted inside the encrypted payload and survives save/open (C36).
        let bytes = v.save().unwrap();
        let opened = Vault::open(&bytes, b"pw").unwrap();
        assert_eq!(opened.find("git", 10_050)[0].entry.title, "gitlab");

        // Empty query = browse mode: every entry, most-used first.
        let all = opened.find("", 10_050);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].entry.title, "gitlab");
    }

    #[test]
    fn wrong_password_fails() {
        let mut v = Vault::create(b"right", M, T, P).unwrap();
        v.add_entry(entry("x", b"s"));
        let bytes = v.save().unwrap();
        assert!(matches!(
            Vault::open(&bytes, b"wrong"),
            Err(Error::HeaderAuth)
        ));
    }

    #[test]
    fn zero_plaintext_on_disk() {
        // C18 end-to-end: no entry content (title, secret) is readable in the encrypted file.
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(entry("github-prod", b"supersecret123"));
        let bytes = v.save().unwrap();
        let needle_title = b"github-prod";
        let needle_secret = b"supersecret123";
        assert!(!bytes.windows(needle_title.len()).any(|w| w == needle_title));
        assert!(!bytes
            .windows(needle_secret.len())
            .any(|w| w == needle_secret));
    }

    #[test]
    fn body_tamper_detected() {
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(entry("x", b"s"));
        let mut bytes = v.save().unwrap();
        let n = bytes.len();
        // Flip a byte inside the final block's HMAC (last 36 bytes = [hmac 32][size 4]); the size
        // field is the last 4, so n-20 lands in the HMAC → authentication failure, not malformed.
        bytes[n - 20] ^= 0x01;
        assert!(matches!(Vault::open(&bytes, b"pw"), Err(Error::BodyAuth)));
    }

    #[test]
    fn each_save_reencrypts_with_fresh_nonce_prefix() {
        // C1 cross-save independence: same content, two saves → different ciphertext bodies.
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(entry("x", b"s"));
        let a = v.save().unwrap();
        let b = v.save().unwrap();
        assert_ne!(a, b);
        // both still open and the version advanced
        assert_eq!(Vault::open(&b, b"pw").unwrap().version(), 2);
    }

    #[test]
    fn search_and_get() {
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(entry("GitHub-Work", b"a"));
        v.add_entry(entry("gitlab", b"b"));
        assert_eq!(v.search("git").len(), 2);
        assert_eq!(v.search("hub").len(), 1);
        assert!(v.get("github-work").is_some()); // case-insensitive
        assert!(v.get("nope").is_none());
    }

    #[test]
    fn change_kdf_rewraps_and_reopens() {
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(entry("x", b"s"));
        let _ = v.save().unwrap();
        v.change_kdf(b"pw", 128, 2, 1).unwrap(); // new params (m >= 8p)
        let bytes = v.save().unwrap();
        let opened = Vault::open(&bytes, b"pw").unwrap();
        assert_eq!(
            opened.kdf_strength(),
            crate::crypto::KdfStrength::BelowFloor
        );
        assert_eq!(&opened.get("x").unwrap().password.expose()[..], b"s");
        assert!(matches!(
            Vault::open(&bytes, b"wrong"),
            Err(Error::HeaderAuth)
        ));
    }

    #[test]
    fn edit_and_remove_persist() {
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(entry("svc", b"old"));
        // edit in place
        v.entry_mut("SVC").unwrap().password = Protected::new(b"new".to_vec());
        // remove a missing entry → false; existing → true
        assert!(!v.remove("nope"));
        let bytes = v.save().unwrap();

        let mut opened = Vault::open(&bytes, b"pw").unwrap();
        assert_eq!(&opened.get("svc").unwrap().password.expose()[..], b"new");
        assert!(opened.remove("svc"));
        assert!(opened.get("svc").is_none());
    }

    #[test]
    fn padding_is_sticky_and_round_trips() {
        use crate::pad::PadMode;
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        for i in 0..5 {
            v.add_entry(entry(&format!("svc{i}"), b"secret-value-xyz-1234567890"));
        }
        assert_eq!(v.padding(), PadMode::None);
        let unpadded = v.save().unwrap();

        v.set_padding(PadMode::Padme);
        let padded = v.save().unwrap();
        assert!(
            padded.len() >= unpadded.len(),
            "padding must not shrink the file"
        );

        // The padding policy is persisted inside the AEAD and entries survive the round-trip.
        let opened = Vault::open(&padded, b"pw").unwrap();
        assert_eq!(opened.padding(), PadMode::Padme);
        assert_eq!(opened.entries().len(), 5);
        assert_eq!(
            &opened.get("svc0").unwrap().password.expose()[..],
            b"secret-value-xyz-1234567890"
        );
    }

    #[test]
    fn yubikey_2fa_enroll_open_and_recovery() {
        let hw: &[u8] = b"mock-yubikey-hmac-response";
        let challenge = [0x55u8; 32];
        let recovery: &[u8] = b"RECOVERY-CODE-high-entropy-7f3a91";

        let mut v = Vault::create(b"masterpw", M, T, P).unwrap();
        v.add_entry(entry("svc", b"s3cr3t"));
        let _ = v.save().unwrap(); // password-only so far
        v.enroll_yubikey_2fa(b"masterpw", hw, &challenge, recovery)
            .unwrap();
        assert!(v.is_2fa());
        let bytes = v.save().unwrap();
        assert!(Vault::requires_yubikey(&bytes));

        // password + the (mock) key response → opens; the responder gets the stored challenge.
        let opened = Vault::open_2fa(&bytes, b"masterpw", |c| {
            assert_eq!(c, &challenge);
            Ok(Zeroizing::new(hw.to_vec()))
        })
        .unwrap();
        assert_eq!(
            opened.get("svc").unwrap().password.expose().as_slice(),
            b"s3cr3t"
        );

        // password ALONE (no key) → fails: true 2FA.
        assert!(matches!(
            Vault::open(&bytes, b"masterpw"),
            Err(Error::HeaderAuth)
        ));
        // wrong key response → fails.
        assert!(matches!(
            Vault::open_2fa(&bytes, b"masterpw", |_| Ok(Zeroizing::new(
                b"wrong".to_vec()
            ))),
            Err(Error::HeaderAuth)
        ));
        // recovery code (via the password path) → opens, for anti-lockout.
        let rec = Vault::open(&bytes, recovery).unwrap();
        assert_eq!(
            rec.get("svc").unwrap().password.expose().as_slice(),
            b"s3cr3t"
        );
    }

    #[test]
    fn keyfile_2fa_enroll_open_and_recovery() {
        let keyfile = b"random-keyfile-bytes-kept-on-a-separate-usb-stick";
        let recovery: &[u8] = b"KEYFILE-RECOVERY-code-2b8e10";

        let mut v = Vault::create(b"masterpw", M, T, P).unwrap();
        v.add_entry(entry("svc", b"s3cr3t"));
        let _ = v.save().unwrap();
        v.enroll_keyfile_2fa(b"masterpw", keyfile, recovery)
            .unwrap();
        assert!(v.is_2fa());
        let bytes = v.save().unwrap();
        assert!(Vault::requires_keyfile(&bytes));
        assert!(!Vault::requires_yubikey(&bytes));

        // password + correct keyfile → opens
        let opened = Vault::open_keyfile(&bytes, b"masterpw", keyfile).unwrap();
        assert_eq!(
            opened.get("svc").unwrap().password.expose().as_slice(),
            b"s3cr3t"
        );
        // password ALONE → fails (true 2FA)
        assert!(matches!(
            Vault::open(&bytes, b"masterpw"),
            Err(Error::HeaderAuth)
        ));
        // wrong keyfile → fails
        assert!(matches!(
            Vault::open_keyfile(&bytes, b"masterpw", b"a-different-keyfile"),
            Err(Error::HeaderAuth)
        ));
        // recovery code → opens (anti-lockout)
        let rec = Vault::open(&bytes, recovery).unwrap();
        assert_eq!(
            rec.get("svc").unwrap().password.expose().as_slice(),
            b"s3cr3t"
        );
    }
}
