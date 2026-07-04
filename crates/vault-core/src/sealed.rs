//! Sealed file containers (UC-23, constraints C61–C66).
//!
//! One `.vltf` blob: existing header + stanza envelope (C7/C5), STREAM body (C1),
//! HmacBlockStream framing (C10), inner file-archive TLV (C62). Padmé default-on (C66).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::crypto::{
    reject_kdf_below_floor, stream::StreamEncryptor, validate_kdf_params,
    ARGON2_DEFAULT_M_COST_KIB, ARGON2_DEFAULT_P_COST, ARGON2_DEFAULT_T_COST,
};
use crate::envelope;
use crate::format::file_archive::{self, ArchiveIncrementalParser, FileMeta, MAX_PART_LEN};
use crate::format::header::KDF_ALGORITHM_ARGON2ID;
use crate::format::stanza::kind;
use crate::format::{block_stream, Header, KdfParams};
use crate::memory::{DataKey, PageLock};
use crate::pad::PadMode;
use crate::{Error, Result, FORMAT_VERSION, MAGIC_VLTF};

/// Uniform open/extract failure text (C64 — no format oracle).
pub const SEALED_OPEN_ERROR: &str = "sealed container could not be opened";

/// `--stdout` size cap until SC9 spike calibrates (C64 > C27).
pub const STDOUT_SIZE_LIMIT: u64 = 64 * 1024 * 1024;

const STAGING_DIR: &str = ".vltf-partial";
const READ_BUF: usize = 64 * 1024;

/// Unlock material for a sealed container (UC-09 stanza parity — C61).
pub struct SealedUnlock<'a> {
    /// Master password or recovery code (`--recovery`).
    pub password: &'a [u8],
    /// Keyfile bytes when the header carries a composite keyfile stanza.
    pub keyfile: Option<&'a [u8]>,
}

impl<'a> SealedUnlock<'a> {
    /// Password-only unlock (default for freshly sealed `.vltf` files).
    pub fn password_only(password: &'a [u8]) -> Self {
        Self {
            password,
            keyfile: None,
        }
    }
}

impl<'a> std::fmt::Debug for SealedUnlock<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedUnlock")
            .field("password", &"[redacted]")
            .field("keyfile", &self.keyfile.map(|_| "[redacted]"))
            .finish()
    }
}

/// YubiKey HMAC challenge responder (UC-09 stanza parity).
pub type YubiKeyRespond<'a> = &'a mut dyn FnMut(&[u8; 32]) -> Result<Zeroizing<Vec<u8>>>;

/// Optional cancel hook + byte progress for seal/open (UC-23 GUI / C63).
#[derive(Default)]
pub struct SealedIoOpts<'a> {
    /// When set and true, abort with [`Error::SealedOpenFailed`] (C64).
    pub cancel: Option<&'a AtomicBool>,
    /// `(bytes_done, bytes_total)` — totals include plaintext payload bytes only.
    pub progress: Option<&'a mut dyn FnMut(u64, u64)>,
}

impl<'a> std::fmt::Debug for SealedIoOpts<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedIoOpts")
            .field("cancel", &self.cancel.is_some())
            .field("progress", &self.progress.is_some())
            .finish()
    }
}

/// Inner-tree metadata returned by [`SealedContainer::peek_entries`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntryMeta {
    /// Relative path inside the container (forward slashes).
    pub path: String,
    /// Declared body size in bytes.
    pub size: u64,
    /// Unix permission bits (lower 12 bits).
    pub mode: u32,
    /// Modification time (Unix seconds).
    pub mtime: u64,
}

impl From<FileMeta> for ArchiveEntryMeta {
    fn from(m: FileMeta) -> Self {
        Self {
            path: m.path,
            size: m.size,
            mode: m.mode,
            mtime: m.mtime,
        }
    }
}

/// Options for creating or sealing a container.
#[derive(Debug, Clone)]
pub struct SealOptions {
    /// Argon2id memory cost (KiB).
    pub m_cost: u32,
    /// Argon2id time cost.
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u32,
    /// Allow below-floor KDF (tests/scripts only).
    pub allow_weak_kdf: bool,
    /// Payload padding policy — default Padmé for `.vltf` (C66).
    pub pad_mode: PadMode,
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            m_cost: ARGON2_DEFAULT_M_COST_KIB,
            t_cost: ARGON2_DEFAULT_T_COST,
            p_cost: ARGON2_DEFAULT_P_COST,
            allow_weak_kdf: false,
            pad_mode: PadMode::Padme,
        }
    }
}

/// Unlocked sealed container — holds the data key for seal/re-seal workflows.
#[derive(Debug)]
pub struct SealedContainer {
    header: Header,
    data_key: DataKey,
    pad_mode: PadMode,
}

fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Crypto)
}

fn open_fail<E: Into<Error>>(_: E) -> Error {
    Error::SealedOpenFailed
}

impl SealedContainer {
    /// Create with recommended Argon2id parameters and Padmé default-on (C66).
    pub fn create_default(password: &[u8]) -> Result<Self> {
        Self::create(password, SealOptions::default())
    }

    /// Create an empty sealed container ready to [`Self::seal_paths`].
    pub fn create(password: &[u8], opts: SealOptions) -> Result<Self> {
        validate_kdf_params(opts.m_cost, opts.t_cost, opts.p_cost)?;
        if !opts.allow_weak_kdf {
            reject_kdf_below_floor(opts.m_cost, opts.t_cost, opts.p_cost)?;
        }

        let mut vault_id = [0u8; 16];
        let mut salt = [0u8; 32];
        let mut master_seed = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        random_bytes(&mut vault_id)?;
        random_bytes(&mut salt)?;
        random_bytes(&mut master_seed)?;
        random_bytes(&mut nonce_prefix)?;

        let data_key = envelope::generate_data_key()?;
        let stanza = envelope::wrap_password_stanza(
            data_key.expose_secret(),
            password,
            &salt,
            &vault_id,
            opts.m_cost,
            opts.t_cost,
            opts.p_cost,
        )?;

        let header = Header {
            magic: MAGIC_VLTF,
            format_version: FORMAT_VERSION,
            vault_id,
            kdf: KdfParams {
                algorithm: KDF_ALGORITHM_ARGON2ID,
                m_cost: opts.m_cost,
                t_cost: opts.t_cost,
                p_cost: opts.p_cost,
                salt,
            },
            master_seed,
            nonce_prefix,
            stanzas: vec![stanza],
            header_hash: [0; 32],
            header_hmac: [0; 32],
        };

        Ok(Self {
            header,
            data_key,
            pad_mode: opts.pad_mode,
        })
    }

    /// Padmé policy for the next seal.
    pub fn pad_mode(&self) -> PadMode {
        self.pad_mode
    }

    /// Set Padmé policy for the next seal.
    pub fn set_pad_mode(&mut self, mode: PadMode) {
        self.pad_mode = mode;
    }

    /// Seal filesystem paths into serialized `.vltf` bytes (sorted paths, streaming read — C63).
    pub fn seal_paths(&self, paths: &[&Path]) -> Result<Vec<u8>> {
        self.seal_paths_with(paths, &mut SealedIoOpts::default())
    }

    /// Like [`Self::seal_paths`] with cancel + byte progress (GUI / C4).
    pub fn seal_paths_with(&self, paths: &[&Path], io: &mut SealedIoOpts<'_>) -> Result<Vec<u8>> {
        let entries = collect_entries(paths)?;
        let total: u64 = entries.iter().map(|e| e.meta.size).sum();
        if let Some(cb) = io.progress.as_deref_mut() {
            cb(0, total.max(1));
        }
        seal_entries(
            &self.header,
            &self.data_key,
            self.pad_mode,
            &entries,
            io,
            total,
        )
    }

    /// Seal one stream from `reader` as `inner_path` inside a new container (pipe mode — A13).
    pub fn seal_reader(
        password: &[u8],
        opts: SealOptions,
        inner_path: &str,
        reader: &mut impl Read,
        io: &mut SealedIoOpts<'_>,
    ) -> Result<Vec<u8>> {
        file_archive::validate_inner_path(inner_path)?;
        let container = Self::create(password, opts)?;
        let mut body = Vec::new();
        reader.read_to_end(&mut body).map_err(Error::Io)?;
        let meta = file_meta_from_len(inner_path, body.len() as u64)?;
        let entry = LocalEntry {
            abs: PathBuf::new(), // unused — inline body
            meta,
            inline: Some(body),
        };
        let total = entry.meta.size;
        if let Some(cb) = io.progress.as_deref_mut() {
            cb(0, total.max(1));
        }
        seal_entries(
            &container.header,
            &container.data_key,
            container.pad_mode,
            &[entry],
            io,
            total,
        )
    }

    /// Whether opening this blob requires a YubiKey tap (composite stanza present).
    pub fn requires_yubikey(bytes: &[u8]) -> bool {
        Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::PW_YUBIKEY))
            .unwrap_or(false)
    }

    /// Whether opening this blob requires a keyfile second factor.
    pub fn requires_keyfile(bytes: &[u8]) -> bool {
        Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::PW_KEYFILE))
            .unwrap_or(false)
    }

    /// Unlock a sealed container (password / keyfile / YubiKey stanzas — C61).
    pub fn open(bytes: &[u8], unlock: &SealedUnlock<'_>) -> Result<Self> {
        Self::open_with(bytes, unlock, None)
    }

    /// Like [`Self::open`] with optional YubiKey responder.
    pub fn open_with(
        bytes: &[u8],
        unlock: &SealedUnlock<'_>,
        yubikey: Option<YubiKeyRespond<'_>>,
    ) -> Result<Self> {
        let header = Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))?;
        let data_key = unwrap_data_key(&header, unlock, yubikey)?;
        Ok(Self {
            header,
            data_key,
            pad_mode: PadMode::Padme,
        })
    }

    /// Enrolled unlock stanzas (types only — no secret material).
    pub fn stanzas(&self) -> &[crate::format::Stanza] {
        &self.header.stanzas
    }

    /// Whether composite password+second-factor stanzas are enrolled.
    pub fn is_2fa(&self) -> bool {
        self.header
            .stanzas
            .iter()
            .any(|s| matches!(s.stanza_type, kind::PW_YUBIKEY | kind::PW_KEYFILE))
    }

    /// Whether a YubiKey composite stanza is enrolled.
    pub fn has_yubikey_2fa(&self) -> bool {
        self.header
            .stanzas
            .iter()
            .any(|s| s.stanza_type == kind::PW_YUBIKEY)
    }

    /// Enroll a keyfile second factor (UC-09 parity — re-wraps header only; inner archive unchanged).
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

    /// Enroll YubiKey second factor (UC-09 parity — re-wraps header only).
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

    /// Re-serialize with an updated header/stanza set; inner STREAM body bytes are preserved.
    pub fn save_preserving_body(&self, original_bytes: &[u8]) -> Result<Vec<u8>> {
        let old = Header::parse_with_kind(original_bytes, Some(crate::ContainerKind::SealedFile))?;
        let body_start = old.on_disk_len();
        if body_start > original_bytes.len() {
            return Err(Error::BodyMalformed);
        }
        let body = &original_bytes[body_start..];
        let mut header = self.header.clone();
        header.seal(self.data_key.expose_secret());
        let mut out = header.serialize();
        out.extend_from_slice(body);
        Ok(out)
    }

    /// Container identity (same field as credential vaults — FIDO2/TPM enroll).
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.header.vault_id
    }

    /// Whether a recovery-code password stanza is present (2FA enroll or init).
    pub fn has_recovery_stanza(&self) -> bool {
        let password_stanzas = self
            .header
            .stanzas
            .iter()
            .filter(|s| s.stanza_type == kind::PASSWORD)
            .count();
        password_stanzas > 1 || (self.is_2fa() && password_stanzas == 1)
    }

    /// Re-wrap the password stanza under new Argon2id parameters (header-only — body unchanged).
    pub fn change_kdf(
        &mut self,
        password: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<()> {
        validate_kdf_params(m_cost, t_cost, p_cost)?;
        reject_kdf_below_floor(m_cost, t_cost, p_cost)?;
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

    /// Replace the data key, re-wrap stanzas, and re-encrypt the inner archive (rotate-data-key).
    pub fn rotate_data_key(
        &mut self,
        original_bytes: &[u8],
        opts: &mut crate::RotateDataKeyOptions<'_>,
    ) -> Result<Vec<u8>> {
        let entries =
            archive_entries_from_blob(original_bytes, &self.header, self.data_key.expose_secret())?;
        let new_dk = envelope::generate_data_key()?;
        self.rewrap_stanzas(new_dk.expose_secret(), opts)?;
        self.data_key = new_dk;
        let total: u64 = entries.iter().map(|e| e.meta.size).sum();
        seal_entries(
            &self.header,
            &self.data_key,
            self.pad_mode,
            &entries,
            &mut SealedIoOpts::default(),
            total,
        )
    }

    /// Merge new filesystem paths into an opened container and re-seal (full re-encrypt).
    pub fn append_paths(
        &self,
        original_bytes: &[u8],
        paths: &[&Path],
        io: &mut SealedIoOpts<'_>,
    ) -> Result<Vec<u8>> {
        let entries = merge_entries_from_blob(
            original_bytes,
            &self.header,
            self.data_key.expose_secret(),
            paths,
        )?;
        let total: u64 = entries.iter().map(|e| e.meta.size).sum();
        if let Some(cb) = io.progress.as_deref_mut() {
            cb(0, total.max(1));
        }
        seal_entries(
            &self.header,
            &self.data_key,
            self.pad_mode,
            &entries,
            io,
            total,
        )
    }

    /// Add a FIDO2 OR stanza (additive — password path stays). Caller saves via [`Self::save_preserving_body`].
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

    /// Add or replace the TPM OR stanza. Caller saves via [`Self::save_preserving_body`].
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

    /// Whether the serialized blob has a FIDO2 OR stanza.
    pub fn has_fido2_stanza(bytes: &[u8]) -> bool {
        Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::FIDO2))
            .unwrap_or(false)
    }

    /// Whether the serialized blob has a TPM OR stanza.
    pub fn has_tpm_stanza(bytes: &[u8]) -> bool {
        Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))
            .map(|h| h.stanzas.iter().any(|s| s.stanza_type == kind::TPM))
            .unwrap_or(false)
    }

    fn rewrap_stanzas(
        &mut self,
        new_dk: &[u8; 32],
        opts: &mut crate::RotateDataKeyOptions<'_>,
    ) -> Result<()> {
        let salt = self.header.kdf.salt;
        let vid = self.header.vault_id;
        let (m, t, p) = (
            self.header.kdf.m_cost,
            self.header.kdf.t_cost,
            self.header.kdf.p_cost,
        );
        if self.has_recovery_stanza() && opts.recovery_code.is_none() {
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
                        Error::Hardware("keyfile required for pw-keyfile rotation".into())
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
                kind::FIDO2 | kind::TPM => {
                    return Err(Error::Hardware(format!(
                        "rotate-data-key on sealed containers does not re-wrap `{}` stanzas yet — \
                         remove the stanza first or rotate after dropping hardware factors",
                        crate::format::stanza::kind_name(s.stanza_type)
                    )));
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

    /// List inner paths and sizes without writing files (post-unlock metadata only — C62).
    pub fn peek_entries(bytes: &[u8], unlock: &SealedUnlock<'_>) -> Result<Vec<ArchiveEntryMeta>> {
        Self::peek_entries_with_yubikey(bytes, unlock, None)
    }

    /// Extract all entries under `dest`, fail-closed via `.vltf-partial/` staging (C64/C65).
    pub fn open_to_dir(bytes: &[u8], unlock: &SealedUnlock<'_>, dest: &Path) -> Result<()> {
        let mut io = SealedIoOpts::default();
        Self::open_to_dir_with(bytes, unlock, dest, &mut io, None)
    }

    /// Like [`Self::open_to_dir`] with cancel, byte progress, and optional YubiKey responder.
    pub fn open_to_dir_with(
        bytes: &[u8],
        unlock: &SealedUnlock<'_>,
        dest: &Path,
        io: &mut SealedIoOpts<'_>,
        yubikey: Option<YubiKeyRespond<'_>>,
    ) -> Result<()> {
        let header = Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))?;
        let data_key = unwrap_data_key(&header, unlock, yubikey)?;
        extract_to_dir(&header, data_key.expose_secret(), bytes, dest, io).map_err(|e| match e {
            Error::Io(_) => e,
            _ => Error::SealedOpenFailed,
        })
    }

    /// List inner paths — YubiKey variant (same as [`Self::peek_entries`] + responder).
    pub fn peek_entries_with_yubikey(
        bytes: &[u8],
        unlock: &SealedUnlock<'_>,
        yubikey: Option<YubiKeyRespond<'_>>,
    ) -> Result<Vec<ArchiveEntryMeta>> {
        let header = Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))?;
        let data_key = unwrap_data_key(&header, unlock, yubikey)?;
        let plaintext =
            decrypt_body(&header, data_key.expose_secret(), bytes).map_err(open_fail)?;
        let files = file_archive::parse_all(&plaintext).map_err(open_fail)?;
        Ok(files.into_iter().map(|(m, _)| m.into()).collect())
    }

    /// Extract a single small file to memory for `--stdout` (SC9 — size capped).
    pub fn read_single_stdout(
        bytes: &[u8],
        unlock: &SealedUnlock<'_>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        Self::read_single_stdout_with(bytes, unlock, None)
    }

    /// Like [`Self::read_single_stdout`] with optional YubiKey responder.
    pub fn read_single_stdout_with(
        bytes: &[u8],
        unlock: &SealedUnlock<'_>,
        yubikey: Option<YubiKeyRespond<'_>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let header = Header::parse_with_kind(bytes, Some(crate::ContainerKind::SealedFile))?;
        let data_key = unwrap_data_key(&header, unlock, yubikey)?;
        let plaintext =
            decrypt_body(&header, data_key.expose_secret(), bytes).map_err(open_fail)?;
        let files = file_archive::parse_all(&plaintext).map_err(open_fail)?;
        if files.len() != 1 {
            return Err(Error::SealedOpenFailed);
        }
        let (meta, body) = &files[0];
        if body.len() as u64 != meta.size || meta.size > STDOUT_SIZE_LIMIT {
            return Err(Error::SealedOpenFailed);
        }
        Ok(Zeroizing::new(body.clone()))
    }
}

fn unwrap_data_key(
    header: &Header,
    unlock: &SealedUnlock<'_>,
    yubikey: Option<YubiKeyRespond<'_>>,
) -> Result<DataKey> {
    let (m, t, p) = (header.kdf.m_cost, header.kdf.t_cost, header.kdf.p_cost);
    if let Some(respond) = yubikey {
        if let Some(s) = header
            .stanzas
            .iter()
            .find(|s| s.stanza_type == kind::PW_YUBIKEY)
        {
            let challenge = envelope::yubikey_challenge(s)?;
            let resp = respond(&challenge)?;
            let data_key = envelope::unwrap_yubikey_2fa_stanza(
                s,
                unlock.password,
                &resp,
                &header.kdf.salt,
                &header.vault_id,
                m,
                t,
                p,
            )
            .map_err(map_unlock_err)?;
            header
                .verify_hmac(data_key.expose_secret())
                .map_err(open_fail)?;
            return Ok(data_key);
        }
    }
    if let Some(kf) = unlock.keyfile {
        if let Some(s) = header
            .stanzas
            .iter()
            .find(|s| s.stanza_type == kind::PW_KEYFILE)
        {
            let data_key = envelope::unwrap_keyfile_2fa_stanza(
                s,
                unlock.password,
                kf,
                &header.kdf.salt,
                &header.vault_id,
                m,
                t,
                p,
            )
            .map_err(map_unlock_err)?;
            header
                .verify_hmac(data_key.expose_secret())
                .map_err(open_fail)?;
            return Ok(data_key);
        }
    }
    let stanzas: Vec<_> = header
        .stanzas
        .iter()
        .filter(|s| s.stanza_type == kind::PASSWORD)
        .collect();
    if stanzas.is_empty() {
        return Err(Error::HeaderAuth);
    }
    let mut last = Error::HeaderAuth;
    for stanza in stanzas {
        match envelope::unwrap_password_stanza(
            stanza,
            unlock.password,
            &header.kdf.salt,
            &header.vault_id,
            m,
            t,
            p,
        ) {
            Ok(data_key) => {
                header
                    .verify_hmac(data_key.expose_secret())
                    .map_err(open_fail)?;
                return Ok(data_key);
            }
            Err(e) => last = e,
        }
    }
    Err(map_unlock_err(last))
}

fn map_unlock_err(e: Error) -> Error {
    match e {
        Error::HeaderAuth => Error::HeaderAuth,
        _ => Error::SealedOpenFailed,
    }
}

fn check_cancel(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Err(Error::SealedOpenFailed);
    }
    Ok(())
}

fn decrypt_body(header: &Header, data_key: &[u8; 32], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let body = &bytes[header.on_disk_len()..];
    let stream_ct = block_stream::read(data_key, &header.master_seed, body)?;
    crate::crypto::stream::decrypt(data_key, &header.nonce_prefix, &stream_ct)
}

struct LocalEntry {
    abs: PathBuf,
    meta: FileMeta,
    /// In-memory body for pipe/stdin seal (A13) — skips filesystem read.
    inline: Option<Vec<u8>>,
}

fn collect_entries(paths: &[&Path]) -> Result<Vec<LocalEntry>> {
    let mut map: BTreeMap<String, LocalEntry> = BTreeMap::new();
    for path in paths {
        if path.is_file() {
            let name =
                path.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "bad path",
                    )))?;
            let rel = name.to_string();
            file_archive::validate_inner_path(&rel)?;
            let meta = file_meta(path, &rel)?;
            map.insert(
                rel.clone(),
                LocalEntry {
                    abs: path.to_path_buf(),
                    meta,
                    inline: None,
                },
            );
        } else if path.is_dir() {
            walk_dir(path, path, &mut map)?;
        } else {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "path not found",
            )));
        }
    }
    Ok(map.into_values().collect())
}

fn walk_dir(root: &Path, dir: &Path, map: &mut BTreeMap<String, LocalEntry>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            walk_dir(root, &path, map)?;
        } else if path.is_file() {
            let rel = rel_path(root, &path)?;
            let meta = file_meta(&path, &rel)?;
            map.insert(
                rel,
                LocalEntry {
                    abs: path,
                    meta,
                    inline: None,
                },
            );
        }
    }
    Ok(())
}

fn rel_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path.strip_prefix(root).map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path prefix",
        ))
    })?;
    let mut out = String::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(&c.to_string_lossy());
            }
            _ => return Err(Error::SealedOpenFailed),
        }
    }
    file_archive::validate_inner_path(&out)?;
    Ok(out)
}

fn file_meta(path: &Path, rel: &str) -> Result<FileMeta> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    if size > file_archive::MAX_FILE_SIZE {
        return Err(Error::BodyMalformed);
    }
    Ok(FileMeta {
        path: rel.to_string(),
        mode: unix_mode(&meta),
        mtime: unix_mtime(&meta),
        size,
    })
}

#[cfg(unix)]
fn unix_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn unix_mode(_meta: &fs::Metadata) -> u32 {
    0o644
}

fn unix_mtime(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn file_meta_from_len(rel: &str, size: u64) -> Result<FileMeta> {
    if size > file_archive::MAX_FILE_SIZE {
        return Err(Error::BodyMalformed);
    }
    Ok(FileMeta {
        path: rel.to_string(),
        mode: 0o644,
        mtime: 0,
        size,
    })
}

fn archive_entries_from_blob(
    bytes: &[u8],
    header: &Header,
    data_key: &[u8; 32],
) -> Result<Vec<LocalEntry>> {
    let plaintext = decrypt_body(header, data_key, bytes).map_err(open_fail)?;
    let files = file_archive::parse_all(&plaintext).map_err(open_fail)?;
    Ok(files
        .into_iter()
        .map(|(meta, body)| LocalEntry {
            abs: PathBuf::new(),
            meta,
            inline: Some(body),
        })
        .collect())
}

fn merge_entries_from_blob(
    bytes: &[u8],
    header: &Header,
    data_key: &[u8; 32],
    new_paths: &[&Path],
) -> Result<Vec<LocalEntry>> {
    let plaintext = decrypt_body(header, data_key, bytes).map_err(open_fail)?;
    let files = file_archive::parse_all(&plaintext).map_err(open_fail)?;
    let mut map: BTreeMap<String, LocalEntry> = BTreeMap::new();
    for (meta, body) in files {
        map.insert(
            meta.path.clone(),
            LocalEntry {
                abs: PathBuf::new(),
                meta,
                inline: Some(body),
            },
        );
    }
    for entry in collect_entries(new_paths)? {
        map.insert(entry.meta.path.clone(), entry);
    }
    Ok(map.into_values().collect())
}

fn seal_entries(
    template: &Header,
    data_key: &DataKey,
    pad_mode: PadMode,
    entries: &[LocalEntry],
    io: &mut SealedIoOpts<'_>,
    total: u64,
) -> Result<Vec<u8>> {
    let mut header = template.clone();
    random_bytes(&mut header.master_seed)?;
    random_bytes(&mut header.nonce_prefix)?;

    let mut enc = StreamEncryptor::new(data_key.expose_secret(), &header.nonce_prefix)?;
    let mut done = 0u64;
    for entry in entries {
        check_cancel(io.cancel)?;
        push_file_hdr(&mut enc, &entry.meta)?;
        stream_file_parts(&mut enc, entry, io, &mut done, total)?;
    }
    check_cancel(io.cancel)?;
    push_end(&mut enc)?;

    let pad_len = pad_mode
        .padded_len(enc.plaintext_len())
        .saturating_sub(enc.plaintext_len());
    if pad_len > 0 {
        let zeros = vec![0u8; pad_len];
        enc.push(&zeros)?;
    }

    let stream_ct = enc.finish()?;
    let body = block_stream::frame(data_key.expose_secret(), &header.master_seed, &stream_ct);
    header.seal(data_key.expose_secret());
    let mut out = header.serialize();
    out.extend_from_slice(&body);
    Ok(out)
}

fn push_tlv(
    enc: &mut StreamEncryptor,
    build: impl FnOnce(&mut Vec<u8>) -> Result<()>,
) -> Result<()> {
    let mut buf = Vec::new();
    build(&mut buf)?;
    enc.push(&buf)
}

fn push_file_hdr(enc: &mut StreamEncryptor, meta: &FileMeta) -> Result<()> {
    push_tlv(enc, |buf| file_archive::write_file_hdr(buf, meta))
}

fn push_file_part(enc: &mut StreamEncryptor, chunk: &[u8]) -> Result<()> {
    push_tlv(enc, |buf| file_archive::write_file_part(buf, chunk))
}

fn push_end(enc: &mut StreamEncryptor) -> Result<()> {
    push_tlv(enc, |buf| {
        file_archive::write_end(buf);
        Ok(())
    })
}

fn stream_file_parts(
    enc: &mut StreamEncryptor,
    entry: &LocalEntry,
    io: &mut SealedIoOpts<'_>,
    done: &mut u64,
    total: u64,
) -> Result<()> {
    if let Some(inline) = &entry.inline {
        let mut offset = 0usize;
        while offset < inline.len() {
            check_cancel(io.cancel)?;
            let take = (inline.len() - offset).min(MAX_PART_LEN);
            let chunk = Zeroizing::new(inline[offset..offset + take].to_vec());
            let _lock = PageLock::new(&chunk);
            push_file_part(enc, &chunk)?;
            offset += take;
            *done += take as u64;
            if let Some(cb) = io.progress.as_deref_mut() {
                cb(*done, total.max(1));
            }
        }
        return Ok(());
    }
    let mut file = File::open(&entry.abs)?;
    let mut remaining = entry.meta.size;
    let mut buf = vec![0u8; READ_BUF.min(MAX_PART_LEN)];
    while remaining > 0 {
        check_cancel(io.cancel)?;
        let take = remaining.min(buf.len() as u64) as usize;
        file.read_exact(&mut buf[..take])?;
        let chunk = Zeroizing::new(buf[..take].to_vec());
        let _lock = PageLock::new(&chunk);
        push_file_part(enc, &chunk)?;
        remaining -= take as u64;
        *done += take as u64;
        if let Some(cb) = io.progress.as_deref_mut() {
            cb(*done, total.max(1));
        }
    }
    Ok(())
}

fn extract_to_dir(
    header: &Header,
    data_key: &[u8; 32],
    bytes: &[u8],
    dest: &Path,
    io: &mut SealedIoOpts<'_>,
) -> Result<()> {
    fs::create_dir_all(dest)?;
    let dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());
    let staging = dest.join(STAGING_DIR);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;

    let result = extract_streaming(header, data_key, bytes, &dest, &staging, io);
    let _ = fs::remove_dir_all(&staging);
    result
}

fn extract_streaming(
    header: &Header,
    data_key: &[u8; 32],
    bytes: &[u8],
    dest: &Path,
    staging: &Path,
    io: &mut SealedIoOpts<'_>,
) -> Result<()> {
    let body = &bytes[header.on_disk_len()..];
    let stream_ct = block_stream::read(data_key, &header.master_seed, body)?;
    let total_est = stream_ct.len() as u64;
    let mut parser = ArchiveIncrementalParser::new();
    let mut decrypted = 0u64;

    crate::crypto::stream::decrypt_streaming(
        data_key,
        &header.nonce_prefix,
        &stream_ct,
        |chunk| {
            check_cancel(io.cancel)?;
            decrypted += chunk.len() as u64;
            if let Some(cb) = io.progress.as_deref_mut() {
                cb(decrypted, total_est.max(1));
            }
            let completed = parser.feed(chunk)?;
            for (meta, body) in completed {
                write_staged_file(staging, &meta, &body)?;
            }
            Ok(())
        },
    )?;

    parser.finish().map_err(open_fail)?;
    promote_staging(staging, dest)?;
    Ok(())
}

fn write_staged_file(staging: &Path, meta: &FileMeta, body: &[u8]) -> Result<()> {
    let staged_path = file_archive::resolve_under_root(staging, &meta.path)?;
    if let Some(parent) = staged_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = staged_path.with_extension("vltf-part");
    fs::write(&tmp, body)?;
    apply_mode(&tmp, meta.mode)?;
    fs::rename(&tmp, &staged_path)?;
    Ok(())
}

fn promote_staging(staging: &Path, dest: &Path) -> Result<()> {
    for entry in walk_files(staging)? {
        let rel = entry
            .strip_prefix(staging)
            .map_err(|_| Error::SealedOpenFailed)?;
        let rel_str = rel.to_string_lossy();
        let rel_str = rel_str.replace('\\', "/");
        let final_path = file_archive::resolve_under_root(dest, &rel_str)?;
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&entry, &final_path)?;
    }
    Ok(())
}

fn walk_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_files(&path)?);
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(out)
}

fn apply_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_default_buckets_identical_length() {
        let password = b"sealed-test-password";
        let c = SealedContainer::create_default(password).unwrap();
        let dir = std::env::temp_dir().join(format!("vault-sealed-pad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), vec![b'x'; 100]).unwrap();
        fs::write(dir.join("b.txt"), vec![b'y'; 105]).unwrap();
        let a = c.seal_paths(&[dir.join("a.txt").as_path()]).unwrap();
        let b = c.seal_paths(&[dir.join("b.txt").as_path()]).unwrap();
        assert_eq!(a.len(), b.len());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ciphertext_hides_inner_paths() {
        let password = b"grep-test";
        let c = SealedContainer::create_default(password).unwrap();
        let dir = std::env::temp_dir().join(format!("vault-sealed-grep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let secret_name = "super_secret_filename.txt";
        fs::write(dir.join(secret_name), b"data").unwrap();
        let blob = c.seal_paths(&[dir.join(secret_name).as_path()]).unwrap();
        let needle = secret_name.as_bytes();
        assert!(
            !blob.windows(needle.len()).any(|w| w == needle),
            "inner path must not appear in ciphertext"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trip_large_file_streaming() {
        let password = b"large-stream";
        let opts = SealOptions {
            allow_weak_kdf: true,
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
            pad_mode: PadMode::Padme,
        };
        let c = SealedContainer::create(password, opts).unwrap();
        let dir = std::env::temp_dir().join(format!("vault-sealed-large-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("large.bin");
        fs::write(&src, vec![0xABu8; 128 * 1024]).unwrap();
        let out_dir = dir.join("out");
        let blob = c.seal_paths(&[src.as_path()]).unwrap();
        SealedContainer::open_to_dir(&blob, &SealedUnlock::password_only(password), &out_dir)
            .unwrap();
        assert_eq!(
            fs::metadata(out_dir.join("large.bin")).unwrap().len(),
            128 * 1024
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trip_single_file() {
        let password = b"round-trip";
        let c = SealedContainer::create_default(password).unwrap();
        let dir = std::env::temp_dir().join(format!("vault-sealed-rt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("nested").join("hello.txt");
        fs::create_dir_all(src.parent().unwrap()).unwrap();
        fs::write(&src, b"hello sealed").unwrap();
        let out_dir = dir.join("out");
        let blob = c.seal_paths(&[src.as_path()]).unwrap();
        assert_eq!(blob[0..4], MAGIC_VLTF);
        let entries =
            SealedContainer::peek_entries(&blob, &SealedUnlock::password_only(password)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "hello.txt");
        SealedContainer::open_to_dir(&blob, &SealedUnlock::password_only(password), &out_dir)
            .unwrap();
        assert_eq!(
            fs::read(out_dir.join("hello.txt")).unwrap(),
            b"hello sealed"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn double_seal_yields_distinct_ciphertext() {
        let password = b"fresh-key";
        let c = SealedContainer::create_default(password).unwrap();
        let dir = std::env::temp_dir().join(format!("vault-sealed-2x-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("f"), b"x").unwrap();
        let a = c.seal_paths(&[dir.join("f").as_path()]).unwrap();
        let b = c.seal_paths(&[dir.join("f").as_path()]).unwrap();
        assert_ne!(a, b);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_preserving_body_round_trips_without_reencrypt() {
        let password = b"preserve-body";
        let c = SealedContainer::create_default(password).unwrap();
        let dir =
            std::env::temp_dir().join(format!("vault-sealed-preserve-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("data.txt"), b"inner").unwrap();
        let blob = c.seal_paths(&[dir.join("data.txt").as_path()]).unwrap();
        let opened = SealedContainer::open(&blob, &SealedUnlock::password_only(password)).unwrap();
        let resaved = opened.save_preserving_body(&blob).unwrap();
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        SealedContainer::open_to_dir(&resaved, &SealedUnlock::password_only(password), &out)
            .unwrap();
        assert_eq!(fs::read(out.join("data.txt")).unwrap(), b"inner");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_vault_magic() {
        let password = b"x";
        let mut v = crate::Vault::create_default(password).unwrap();
        let bytes = v.save().unwrap();
        assert!(matches!(
            SealedContainer::open(&bytes, &SealedUnlock::password_only(password)),
            Err(Error::WrongContainerKind)
        ));
    }
}
