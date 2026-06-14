//! The vault open/save orchestration — ties every layer together (the v0 `vault-core` API).
//!
//! Open:  parse header (C7/C8/C9 hash, C2 ceiling) → unwrap the data key from the password stanza
//!        (C5) → verify the data-key-keyed header HMAC (C9/G0.2) → de-frame the HmacBlockStream
//!        (C10) → STREAM-decrypt the body (C1) → parse the payload (C16/C18).
//! Save:  regenerate `master_seed` + `nonce_prefix` (a body-writing save — C8/C1), bump
//!        `vault_version` (C16), serialize → STREAM-encrypt → HmacBlockStream-frame → seal header.
//!
//! NOTE (C19, deferred): Protected fields are serialized inside the AEAD payload but the inner
//! ChaCha20 stream pass is not yet applied — confidentiality at rest is provided by the outer AEAD
//! (C1); C19's in-memory defense-in-depth lands in a later segment.

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
            vault_version: 0,
            entries: Vec::new(),
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
        let header = Header::parse(bytes)?;

        let pw_stanza = header
            .stanzas
            .iter()
            .find(|s| s.stanza_type == kind::PASSWORD)
            .ok_or(Error::HeaderAuth)?;
        let data_key = envelope::unwrap_password_stanza(
            pw_stanza,
            password,
            &header.kdf.salt,
            &header.vault_id,
            header.kdf.m_cost,
            header.kdf.t_cost,
            header.kdf.p_cost,
        )?;

        // C9 step 4: the factor is now proven valid, so a header HMAC mismatch is real tampering.
        header.verify_hmac(data_key.expose_secret())?;

        let body = &bytes[header.on_disk_len()..];
        let stream_ct = block_stream::read(data_key.expose_secret(), &header.master_seed, body)?;
        let plaintext =
            stream::decrypt(data_key.expose_secret(), &header.nonce_prefix, &stream_ct)?;
        let payload = Payload::parse(&plaintext)?;

        Ok(Vault {
            header,
            data_key,
            payload,
        })
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

        let plaintext = Zeroizing::new(self.payload.serialize());
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

    /// Remove an entry by exact (case-insensitive) title. Returns whether one was removed.
    pub fn remove(&mut self, title: &str) -> bool {
        let t = title.to_lowercase();
        let before = self.payload.entries.len();
        self.payload.entries.retain(|e| e.title.to_lowercase() != t);
        self.payload.entries.len() != before
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
        assert_eq!(e.password.expose(), b"ghp_secret");
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
    fn edit_and_remove_persist() {
        let mut v = Vault::create(b"pw", M, T, P).unwrap();
        v.add_entry(entry("svc", b"old"));
        // edit in place
        v.entry_mut("SVC").unwrap().password = Protected::new(b"new".to_vec());
        // remove a missing entry → false; existing → true
        assert!(!v.remove("nope"));
        let bytes = v.save().unwrap();

        let mut opened = Vault::open(&bytes, b"pw").unwrap();
        assert_eq!(opened.get("svc").unwrap().password.expose(), b"new");
        assert!(opened.remove("svc"));
        assert!(opened.get("svc").is_none());
    }
}
