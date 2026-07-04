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
    stream, validate_kdf_params, ARGON2_DEFAULT_M_COST_KIB, ARGON2_DEFAULT_P_COST,
    ARGON2_DEFAULT_T_COST,
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

/// Warning for graceful-mode saves when the YubiKey stanza was not refreshed (constraint C5).
pub const YUBIKEY_STALE_WARNING: &str =
    "WARNING: yubikey stanza not refreshed (key absent); insert it and save to restore challenge rotation.";

/// Options for a body-writing save on a YubiKey 2FA vault (constraint C5).
#[derive(Default)]
pub struct SaveOptions<'a> {
    /// Master password — required to re-wrap the composite YubiKey stanza when the key is present.
    pub password: Option<&'a [u8]>,
    /// Override the per-vault strict flag for this save. When `None`, uses [`Vault::yubikey_strict`].
    pub yubikey_strict: Option<bool>,
    /// YubiKey challenge-response callback. When absent and refresh is required, strict mode aborts.
    pub yubikey_respond: Option<HwResponder<'a>>,
}

impl std::fmt::Debug for SaveOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaveOptions")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("yubikey_strict", &self.yubikey_strict)
            .field(
                "yubikey_respond",
                &self.yubikey_respond.is_some().then_some("<fn>"),
            )
            .finish()
    }
}

/// Outcome of a body-writing save — includes whether the YubiKey stanza was left stale (C5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveReport {
    /// Serialized vault bytes ready to write.
    pub bytes: Vec<u8>,
    /// True when the vault has YubiKey 2FA and the stanza was not refreshed (graceful mode only).
    pub yubikey_stale: bool,
}

/// Options for [`Vault::rotate_data_key`] (gap C2 — forward secrecy after compromise).
pub struct RotateDataKeyOptions<'a> {
    /// Master password — re-wraps the primary unlock path (password or 2FA composite).
    pub password: &'a [u8],
    /// Recovery code for the anti-lockout password stanza on 2FA vaults (required when present).
    pub recovery_code: Option<&'a [u8]>,
    /// Keyfile bytes for `pw-keyfile` vaults.
    pub keyfile: Option<&'a [u8]>,
    /// YubiKey challenge-response callback for `pw-yubikey` vaults.
    pub yubikey_respond: Option<HwResponder<'a>>,
}

impl std::fmt::Debug for RotateDataKeyOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateDataKeyOptions")
            .field("password", &"<redacted>")
            .field(
                "recovery_code",
                &self.recovery_code.as_ref().map(|_| "<redacted>"),
            )
            .field("keyfile", &self.keyfile.as_ref().map(|k| k.len()))
            .field(
                "yubikey_respond",
                &self.yubikey_respond.is_some().then_some("<fn>"),
            )
            .finish()
    }
}

fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Crypto)
}

impl Vault {
    /// Create a new, empty vault protected by `password` with the given Argon2id parameters.
    ///
    /// Rejects below-floor params unless `allow_weak_kdf` (init escape hatch for tests/scripts).
    pub fn create(
        password: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        allow_weak_kdf: bool,
    ) -> Result<Vault> {
        validate_kdf_params(m_cost, t_cost, p_cost)?;
        if !allow_weak_kdf {
            crate::crypto::reject_kdf_below_floor(m_cost, t_cost, p_cost)?;
        }
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
            magic: crate::MAGIC,
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
            yubikey_strict: false,
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

    /// Whether this vault carries an offline recovery-code stanza (init optional path or 2FA enroll).
    pub fn has_recovery_stanza(&self) -> bool {
        let password_stanzas = self
            .header
            .stanzas
            .iter()
            .filter(|s| s.stanza_type == kind::PASSWORD)
            .count();
        password_stanzas > 1 || (self.is_2fa() && password_stanzas == 1)
    }

    /// Add a second password stanza wrapping the data key under `recovery_code` (gap C3).
    ///
    /// For password-only vaults at init — distinct from 2FA enrollment, which supplies its own
    /// recovery stanza. Refuses if a recovery stanza already exists.
    pub fn add_recovery_stanza(&mut self, recovery_code: &[u8]) -> Result<()> {
        if self.is_2fa() {
            return Err(Error::Hardware(
                "2FA vaults already have a recovery stanza from enrollment".into(),
            ));
        }
        let password_stanzas = self
            .header
            .stanzas
            .iter()
            .filter(|s| s.stanza_type == kind::PASSWORD)
            .count();
        if password_stanzas >= 2 {
            return Err(Error::Hardware("recovery stanza already present".into()));
        }
        let stanza = envelope::wrap_password_stanza(
            self.data_key.expose_secret(),
            recovery_code,
            &self.header.kdf.salt,
            &self.header.vault_id,
            self.header.kdf.m_cost,
            self.header.kdf.t_cost,
            self.header.kdf.p_cost,
        )?;
        self.header.stanzas.push(stanza);
        Ok(())
    }

    /// Create a new vault with the recommended default Argon2id parameters (C2).
    pub fn create_default(password: &[u8]) -> Result<Vault> {
        Vault::create(
            password,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
            false,
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

    /// Open via FIDO2 OR stanza (UC-09 additive factor — password stanza not required).
    pub fn open_fido2(bytes: &[u8], prf_output: &[u8; 32]) -> Result<Vault> {
        Self::open_hw_or(bytes, |header| {
            let s = header
                .stanzas
                .iter()
                .find(|s| s.stanza_type == kind::FIDO2)
                .ok_or(Error::HeaderAuth)?;
            envelope::fido2::unwrap_fido2_stanza(s, prf_output, &header.vault_id)
        })
    }

    /// Open via TPM OR stanza (UC-09 additive factor).
    pub fn open_tpm(bytes: &[u8], tpm_ikm: &[u8; 32]) -> Result<Vault> {
        Self::open_hw_or(bytes, |header| {
            let s = header
                .stanzas
                .iter()
                .find(|s| s.stanza_type == kind::TPM)
                .ok_or(Error::HeaderAuth)?;
            envelope::tpm::unwrap_tpm_stanza(s, tpm_ikm, &header.vault_id)
        })
    }

    fn open_hw_or<F>(bytes: &[u8], unwrap: F) -> Result<Vault>
    where
        F: FnOnce(&Header) -> Result<DataKey>,
    {
        let header = Header::parse(bytes)?;
        if header.kind() != crate::ContainerKind::Vault {
            return Err(Error::WrongContainerKind);
        }
        let data_key = unwrap(&header)?;
        header.verify_hmac(data_key.expose_secret())?;
        let body = &bytes[header.on_disk_len()..];
        let stream_ct = block_stream::read(data_key.expose_secret(), &header.master_seed, body)?;
        let payload = Payload::parse_from_stream_ciphertext(
            data_key.expose_secret(),
            &header.nonce_prefix,
            &stream_ct,
        )?;
        Ok(Vault {
            header,
            data_key,
            payload,
        })
    }

    fn open_inner(
        bytes: &[u8],
        password: &[u8],
        hw: Option<HwResponder<'_>>,
        keyfile: Option<&[u8]>,
    ) -> Result<Vault> {
        let header = Header::parse(bytes)?;
        if header.kind() != crate::ContainerKind::Vault {
            return Err(Error::WrongContainerKind);
        }
        let data_key = Self::unwrap_data_key(&header, password, hw, keyfile)?;

        // C9 step 4: the factor is now proven valid, so a header HMAC mismatch is real tampering.
        header.verify_hmac(data_key.expose_secret())?;

        let body = &bytes[header.on_disk_len()..];
        let stream_ct = block_stream::read(data_key.expose_secret(), &header.master_seed, body)?;
        // Streaming open: no full outer plaintext buffer (C19).
        let payload = Payload::parse_from_stream_ciphertext(
            data_key.expose_secret(),
            &header.nonce_prefix,
            &stream_ct,
        )?;

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
            .filter(|s| s.stanza_type == kind::PASSWORD)
            .collect::<Vec<_>>();
        if s.is_empty() {
            return Err(Error::HeaderAuth);
        }
        let mut last = Error::HeaderAuth;
        for stanza in s {
            match envelope::unwrap_password_stanza(
                stanza,
                password,
                &header.kdf.salt,
                &header.vault_id,
                m,
                t,
                p,
            ) {
                Ok(dk) => return Ok(dk),
                Err(e) => last = e,
            }
        }
        Err(last)
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
        self.payload.yubikey_strict = true;
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

    /// Add a FIDO2 OR stanza (additive — password stanza stays). Caller MUST `save()` afterward.
    pub fn add_fido2_stanza(
        &mut self,
        prf_output: &[u8; 32],
        extra: envelope::fido2::Fido2Extra,
    ) -> Result<()> {
        if self.header.stanzas.len() >= crate::format::MAX_STANZAS as usize {
            return Err(Error::Hardware("stanza limit reached (max 8)".into()));
        }
        if self
            .header
            .stanzas
            .iter()
            .any(|s| s.stanza_type == kind::FIDO2)
        {
            return Err(Error::Hardware("FIDO2 stanza already enrolled".into()));
        }
        let dk = Zeroizing::new(*self.data_key.expose_secret());
        let stanza =
            envelope::fido2::wrap_fido2_stanza(&dk, prf_output, &self.header.vault_id, &extra)?;
        self.header.stanzas.push(stanza);
        Ok(())
    }

    /// Add or replace the TPM OR stanza. Caller MUST `save()` afterward.
    pub fn set_tpm_stanza(
        &mut self,
        tpm_ikm: &[u8; 32],
        extra: envelope::tpm::TpmExtra,
    ) -> Result<()> {
        let dk = Zeroizing::new(*self.data_key.expose_secret());
        let stanza = envelope::tpm::wrap_tpm_stanza(&dk, tpm_ikm, &self.header.vault_id, &extra)?;
        if let Some(idx) = self
            .header
            .stanzas
            .iter()
            .position(|s| s.stanza_type == kind::TPM)
        {
            self.header.stanzas[idx] = stanza;
        } else {
            if self.header.stanzas.len() >= crate::format::MAX_STANZAS as usize {
                return Err(Error::Hardware("stanza limit reached (max 8)".into()));
            }
            self.header.stanzas.push(stanza);
        }
        Ok(())
    }

    /// Whether the serialized vault has a FIDO2 OR stanza.
    pub fn has_fido2_stanza(bytes: &[u8]) -> bool {
        Header::parse(bytes)
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::FIDO2))
            .unwrap_or(false)
    }

    /// Whether the serialized vault has a TPM OR stanza.
    pub fn has_tpm_stanza(bytes: &[u8]) -> bool {
        Header::parse(bytes)
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::TPM))
            .unwrap_or(false)
    }

    /// Whether this opened vault uses composite password+YubiKey 2FA.
    pub fn has_yubikey_2fa(&self) -> bool {
        self.header
            .stanzas
            .iter()
            .any(|s| s.stanza_type == kind::PW_YUBIKEY)
    }

    /// Per-vault strict save policy (default `true` after YubiKey enrollment; absent in old files → false).
    pub fn yubikey_strict(&self) -> bool {
        self.payload.yubikey_strict
    }

    /// Set strict save policy (e.g. `--graceful-yubikey` at enrollment opts out).
    pub fn set_yubikey_strict(&mut self, strict: bool) {
        self.payload.yubikey_strict = strict;
    }

    /// Serialize and encrypt the vault to its on-disk bytes (a body-writing save).
    ///
    /// Password-only vaults: equivalent to [`Vault::save_with`] with default options. YubiKey 2FA
    /// vaults with strict mode require [`Vault::save_with`] and a YubiKey responder — use the CLI
    /// helper or pass [`SaveOptions`].
    pub fn save(&mut self) -> Result<Vec<u8>> {
        self.save_with(SaveOptions::default()).map(|r| r.bytes)
    }

    /// Body-writing save with YubiKey refresh policy (constraint C5).
    pub fn save_with(&mut self, opts: SaveOptions<'_>) -> Result<SaveReport> {
        let yubikey_stale = self.prepare_yubikey_save(opts)?;
        let bytes = self.save_body()?;
        Ok(SaveReport {
            bytes,
            yubikey_stale,
        })
    }

    fn prepare_yubikey_save(&mut self, opts: SaveOptions<'_>) -> Result<bool> {
        if !self.has_yubikey_2fa() {
            return Ok(false);
        }
        let strict = opts.yubikey_strict.unwrap_or(self.payload.yubikey_strict);
        let password = match opts.password {
            Some(p) => p,
            None if strict => return Err(Error::YubiKeyStrictSave),
            None => return Ok(true),
        };
        if let Some(respond) = opts.yubikey_respond {
            let mut new_challenge = [0u8; 32];
            random_bytes(&mut new_challenge)?;
            match respond(&new_challenge) {
                Ok(hw) => {
                    self.refresh_yubikey_2fa_stanza(password, &hw, &new_challenge)?;
                    return Ok(false);
                }
                Err(_) if strict => return Err(Error::YubiKeyStrictSave),
                Err(_) => return Ok(true),
            }
        }
        if strict {
            return Err(Error::YubiKeyStrictSave);
        }
        Ok(true)
    }

    fn refresh_yubikey_2fa_stanza(
        &mut self,
        password: &[u8],
        hw_response: &[u8],
        challenge: &[u8; 32],
    ) -> Result<()> {
        let recovery = self
            .header
            .stanzas
            .iter()
            .find(|s| s.stanza_type == kind::PASSWORD)
            .ok_or(Error::HeaderAuth)?
            .clone();
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
        self.header.stanzas = vec![yubikey, recovery];
        Ok(())
    }

    fn save_body(&mut self) -> Result<Vec<u8>> {
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
        crate::crypto::reject_kdf_below_floor(m_cost, t_cost, p_cost)?;
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

    /// Replace the vault data key and re-wrap every stanza (gap C2 `rotate-data-key`).
    ///
    /// Re-encrypts the payload on the next [`Vault::save`] / [`Vault::save_with`]. Old exfiltrated
    /// blobs remain decryptable with the **old** data key until sync/backends drop them — document
    /// honestly; this seals **new** writes under a fresh key.
    pub fn rotate_data_key(&mut self, opts: &mut RotateDataKeyOptions<'_>) -> Result<()> {
        let new_dk = envelope::generate_data_key()?;
        let new_bytes = *new_dk.expose_secret();
        self.rewrap_stanzas(&new_bytes, opts)?;
        self.data_key = new_dk;
        Ok(())
    }

    fn rewrap_stanzas(
        &mut self,
        new_dk: &[u8; 32],
        opts: &mut RotateDataKeyOptions<'_>,
    ) -> Result<()> {
        let salt = self.header.kdf.salt;
        let vid = self.header.vault_id;
        let (m, t, p) = (
            self.header.kdf.m_cost,
            self.header.kdf.t_cost,
            self.header.kdf.p_cost,
        );
        let has_recovery = self.has_recovery_stanza();
        if has_recovery && opts.recovery_code.is_none() {
            return Err(Error::Hardware(
                "recovery code required to re-seal the anti-lockout stanza during data-key rotation"
                    .into(),
            ));
        }
        let mut out = Vec::with_capacity(self.header.stanzas.len());
        let mut password_stanza_index = 0usize;
        for s in &self.header.stanzas {
            let wrapped = match s.stanza_type {
                kind::PASSWORD => {
                    let secret = if self.is_2fa() || password_stanza_index > 0 {
                        opts.recovery_code.ok_or_else(|| {
                            Error::Hardware("missing recovery code for recovery stanza".into())
                        })?
                    } else {
                        opts.password
                    };
                    password_stanza_index += 1;
                    envelope::wrap_password_stanza(new_dk, secret, &salt, &vid, m, t, p)?
                }
                kind::PW_YUBIKEY => {
                    let respond = opts
                        .yubikey_respond
                        .as_mut()
                        .ok_or(Error::YubiKeyStrictSave)?;
                    let mut challenge = [0u8; 32];
                    random_bytes(&mut challenge)?;
                    let hw = respond(&challenge)?;
                    envelope::wrap_yubikey_2fa_stanza(
                        new_dk,
                        opts.password,
                        &hw,
                        &challenge,
                        &salt,
                        &vid,
                        m,
                        t,
                        p,
                    )?
                }
                kind::PW_KEYFILE => {
                    let kf = opts.keyfile.ok_or_else(|| {
                        Error::Hardware("keyfile required for pw-keyfile vault rotation".into())
                    })?;
                    envelope::wrap_keyfile_2fa_stanza(
                        new_dk,
                        opts.password,
                        kf,
                        &salt,
                        &vid,
                        m,
                        t,
                        p,
                    )?
                }
                other => {
                    return Err(Error::Hardware(format!(
                        "rotate-data-key does not support `{}` stanzas yet",
                        crate::format::stanza::kind_name(other)
                    )));
                }
            };
            out.push(wrapped);
        }
        self.header.stanzas = out;
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
        self.header.stanzas.retain(|s| s.stanza_type != stanza_type);
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
    fn create_rejects_below_floor_without_escape_hatch() {
        assert!(matches!(
            Vault::create(b"pw", 8192, 1, 1, false),
            Err(Error::KdfBelowFloor)
        ));
        assert!(Vault::create(
            b"pw",
            crate::crypto::ARGON2_FLOOR_M_COST_KIB,
            crate::crypto::ARGON2_FLOOR_T_COST,
            crate::crypto::ARGON2_FLOOR_P_COST,
            false,
        )
        .is_ok());
    }

    #[test]
    fn create_save_open_round_trip() {
        let mut v = Vault::create(b"hunter2", M, T, P, true).unwrap();
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
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
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
        let mut v = Vault::create(b"right", M, T, P, true).unwrap();
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
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
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
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
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
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
        v.add_entry(entry("x", b"s"));
        let a = v.save().unwrap();
        let b = v.save().unwrap();
        assert_ne!(a, b);
        // both still open and the version advanced
        assert_eq!(Vault::open(&b, b"pw").unwrap().version(), 2);
    }

    #[test]
    fn search_and_get() {
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
        v.add_entry(entry("GitHub-Work", b"a"));
        v.add_entry(entry("gitlab", b"b"));
        assert_eq!(v.search("git").len(), 2);
        assert_eq!(v.search("hub").len(), 1);
        assert!(v.get("github-work").is_some()); // case-insensitive
        assert!(v.get("nope").is_none());
    }

    #[test]
    fn change_kdf_rewraps_and_reopens() {
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
        v.add_entry(entry("x", b"s"));
        let _ = v.save().unwrap();
        v.change_kdf(
            b"pw",
            crate::crypto::ARGON2_FLOOR_M_COST_KIB,
            crate::crypto::ARGON2_FLOOR_T_COST,
            crate::crypto::ARGON2_FLOOR_P_COST,
        )
        .unwrap();
        let bytes = v.save().unwrap();
        let opened = Vault::open(&bytes, b"pw").unwrap();
        assert_ne!(
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
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
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
        let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
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

    fn mock_yk_response(challenge: &[u8; 32]) -> Zeroizing<Vec<u8>> {
        let mut out = b"mock-yubikey-hmac-response".to_vec();
        out.extend_from_slice(challenge);
        Zeroizing::new(out)
    }

    #[test]
    fn yubikey_2fa_enroll_open_and_recovery() {
        let challenge = [0x55u8; 32];
        let recovery: &[u8] = b"RECOVERY-CODE-high-entropy-7f3a91";

        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
        v.add_entry(entry("svc", b"s3cr3t"));
        let _ = v.save().unwrap(); // password-only so far
        v.enroll_yubikey_2fa(
            b"masterpw",
            &mock_yk_response(&challenge),
            &challenge,
            recovery,
        )
        .unwrap();
        assert!(v.is_2fa());
        assert!(v.yubikey_strict());
        let mut stored_challenge = challenge;
        let mut respond = |c: &[u8; 32]| -> crate::Result<Zeroizing<Vec<u8>>> {
            stored_challenge = *c;
            Ok(mock_yk_response(c))
        };
        let report = v
            .save_with(SaveOptions {
                password: Some(b"masterpw"),
                yubikey_strict: None,
                yubikey_respond: Some(&mut respond),
            })
            .unwrap();
        assert!(!report.yubikey_stale);
        let bytes = report.bytes;
        assert!(Vault::requires_yubikey(&bytes));

        // password + the (mock) key response → opens; the responder gets the stored challenge.
        let opened = Vault::open_2fa(&bytes, b"masterpw", |c| {
            assert_eq!(c, &stored_challenge);
            Ok(mock_yk_response(c))
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
    fn yubikey_strict_save_aborts_without_responder() {
        let challenge = [0x55u8; 32];
        let recovery: &[u8] = b"RECOVERY-CODE-high-entropy-7f3a91";

        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
        v.enroll_yubikey_2fa(
            b"masterpw",
            &mock_yk_response(&challenge),
            &challenge,
            recovery,
        )
        .unwrap();
        assert!(matches!(
            v.save_with(SaveOptions {
                password: Some(b"masterpw"),
                yubikey_strict: Some(true),
                yubikey_respond: None,
            }),
            Err(Error::YubiKeyStrictSave)
        ));
    }

    #[test]
    fn yubikey_graceful_save_allows_stale_stanza() {
        let challenge = [0x55u8; 32];
        let recovery: &[u8] = b"RECOVERY-CODE-high-entropy-7f3a91";

        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
        v.enroll_yubikey_2fa(
            b"masterpw",
            &mock_yk_response(&challenge),
            &challenge,
            recovery,
        )
        .unwrap();
        v.set_yubikey_strict(false);
        let report = v
            .save_with(SaveOptions {
                password: Some(b"masterpw"),
                yubikey_strict: None,
                yubikey_respond: None,
            })
            .unwrap();
        assert!(report.yubikey_stale);
        Vault::open_2fa(&report.bytes, b"masterpw", |c| {
            assert_eq!(c, &challenge);
            Ok(mock_yk_response(c))
        })
        .unwrap();
    }

    #[test]
    fn yubikey_refresh_rotates_challenge() {
        let challenge = [0x55u8; 32];
        let recovery: &[u8] = b"RECOVERY-CODE-high-entropy-7f3a91";

        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
        v.enroll_yubikey_2fa(
            b"masterpw",
            &mock_yk_response(&challenge),
            &challenge,
            recovery,
        )
        .unwrap();
        let mut seen = challenge;
        let mut respond = |c: &[u8; 32]| -> crate::Result<Zeroizing<Vec<u8>>> {
            seen = *c;
            Ok(mock_yk_response(c))
        };
        let report = v
            .save_with(SaveOptions {
                password: Some(b"masterpw"),
                yubikey_strict: None,
                yubikey_respond: Some(&mut respond),
            })
            .unwrap();
        assert_ne!(seen, challenge);
        Vault::open_2fa(&report.bytes, b"masterpw", |c| {
            assert_eq!(c, &seen);
            Ok(mock_yk_response(c))
        })
        .unwrap();
        // Response to the pre-refresh challenge no longer unlocks (anti-replay).
        assert!(matches!(
            Vault::open_2fa(&report.bytes, b"masterpw", |c| {
                assert_eq!(c, &seen);
                Ok(mock_yk_response(&challenge))
            }),
            Err(Error::HeaderAuth)
        ));
    }

    #[test]
    fn keyfile_2fa_enroll_open_and_recovery() {
        let keyfile = b"random-keyfile-bytes-kept-on-a-separate-usb-stick";
        let recovery: &[u8] = b"KEYFILE-RECOVERY-code-2b8e10";

        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
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

    #[test]
    fn rotate_data_key_reseals_password_only_vault() {
        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
        v.add_entry(entry("acct", b"before-rotate"));
        let before = v.save().unwrap();

        v.rotate_data_key(&mut RotateDataKeyOptions {
            password: b"masterpw",
            recovery_code: None,
            keyfile: None,
            yubikey_respond: None,
        })
        .unwrap();
        let after = v.save().unwrap();
        assert_ne!(before, after);

        let old = Vault::open(&before, b"masterpw").unwrap();
        assert_eq!(
            old.get("acct").unwrap().password.expose().as_slice(),
            b"before-rotate"
        );
        let new = Vault::open(&after, b"masterpw").unwrap();
        assert_eq!(
            new.get("acct").unwrap().password.expose().as_slice(),
            b"before-rotate"
        );
    }

    #[test]
    fn init_recovery_stanza_unlocks_without_master_password() {
        let recovery: &[u8] = b"OFFLINE-RECOVERY-CODE-7f3a91bc";
        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
        v.add_recovery_stanza(recovery).unwrap();
        assert!(v.has_recovery_stanza());
        let bytes = v.save().unwrap();
        assert!(Vault::open(&bytes, b"masterpw").is_ok());
        assert!(Vault::open(&bytes, recovery).is_ok());
        assert!(Vault::open(&bytes, b"wrong-secret").is_err());
    }

    #[test]
    fn rotate_data_key_requires_recovery_for_2fa_vault() {
        let challenge = [0x55u8; 32];
        let recovery: &[u8] = b"RECOVERY-CODE-high-entropy-7f3a91";
        let mut v = Vault::create(b"masterpw", M, T, P, true).unwrap();
        v.enroll_yubikey_2fa(
            b"masterpw",
            &mock_yk_response(&challenge),
            &challenge,
            recovery,
        )
        .unwrap();
        let mut respond =
            |c: &[u8; 32]| -> crate::Result<Zeroizing<Vec<u8>>> { Ok(mock_yk_response(c)) };
        assert!(matches!(
            v.rotate_data_key(&mut RotateDataKeyOptions {
                password: b"masterpw",
                recovery_code: None,
                keyfile: None,
                yubikey_respond: Some(&mut respond),
            }),
            Err(Error::Hardware(_))
        ));
    }
}
