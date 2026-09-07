//! Local encrypted workspace volumes (UC-25, constraints C67–C74).
//!
//! A `.vltd` file is an authenticated block device in a file: the plaintext Blindkey [`Header`]
//! (with [`MAGIC_VLTD`]), a dual AEAD-wrapped inner header, then fixed-size AEAD data blocks that
//! hold a packed in-memory VFS. The master data key comes from the same stanza envelope as sealed
//! containers (C61 parity); it is HKDF-split into independent `volume_key` / `mac_key` /
//! `nonce_key`. Integrity is layered: per-block AEAD (C68), a key commitment on unlock (C69), a
//! Merkle root over block tags (ADR-0008), and a local freshness anchor (C70). All auth/parse
//! failures collapse to the uniform [`Error::VolumeOpenFailed`] (C74).

mod anchor;
mod block;
mod fs;
mod inner;
mod materialize;
mod merkle;
mod working_copy;

pub use materialize::{cleartext_mnt_beside, CloseMountError, MaterializedMount};
pub use working_copy::{
    assert_hydrated_for_checkout, default_work_root, has_unresolved_conflicts, hash_outer_logical,
    is_under_sync_root, list_work_sessions, orphan_work_sessions, orphaned_cleartext_sessions,
    CheckinOpts, CheckoutOpts, OuterFingerprint, WorkPhase, WorkSessionInfo, WorkingCopySession,
    WORKING_COPY_ERROR,
};

use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::{
    self, reject_kdf_below_floor, validate_kdf_params, ARGON2_DEFAULT_M_COST_KIB,
    ARGON2_DEFAULT_P_COST, ARGON2_DEFAULT_T_COST,
};
use crate::envelope;
use crate::format::header::KDF_ALGORITHM_ARGON2ID;
use crate::format::stanza::kind;
use crate::format::{Header, KdfParams};
use crate::memory::DataKey;
use crate::pad::PadMode;
use crate::{Error, Result, FORMAT_VERSION, MAGIC_VLTD};

use block::{KIND_DIR, KIND_FILE, NONCE_LEN, TAG_LEN};
use fs::{Inode, Node, Vfs};
use inner::{InnerHeader, INNER_WRAPPED_LEN};

/// Uniform open failure text (C74 — no format oracle). Matches [`Error::VolumeOpenFailed`].
pub const VOLUME_OPEN_ERROR: &str = "volume could not be opened";

/// Metadata kind of a VFS node. Carries a byte length for files but never the contents (C71/C27) —
/// used by `status`/`peek` and the mount adapter's `getattr`/`lookup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory.
    Dir,
    /// A regular file of the given byte length.
    File(u64),
}

/// HKDF info labels splitting the volume master into subkeys (exact bytes matter).
const DATA_INFO: &[u8] = b"volume-data-v1";
const MAC_INFO: &[u8] = b"volume-mac-v1";
const NONCE_INFO: &[u8] = b"volume-nonce-v1";

/// Default data-block plaintext capacity, in KiB.
const DEFAULT_BLOCK_KIB: u16 = 32;

/// Unlock material for a volume (UC-09 stanza parity — C61).
pub struct VolumeUnlock<'a> {
    /// Master password.
    pub password: &'a [u8],
    /// Keyfile bytes when a composite keyfile stanza is enrolled.
    pub keyfile: Option<&'a [u8]>,
}

impl<'a> VolumeUnlock<'a> {
    /// Password-only unlock (default for a freshly created volume).
    pub fn password_only(password: &'a [u8]) -> Self {
        Self {
            password,
            keyfile: None,
        }
    }
}

impl std::fmt::Debug for VolumeUnlock<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeUnlock")
            .field("password", &"[redacted]")
            .field("keyfile", &self.keyfile.map(|_| "[redacted]"))
            .finish()
    }
}

/// Options for creating a volume.
#[derive(Debug, Clone)]
pub struct VolumeCreateOpts {
    /// Logical volume size in bytes (advisory; the file grows with content).
    pub size_bytes: u64,
    /// Maximum logical size in bytes.
    pub max_bytes: u64,
    /// Data-block plaintext capacity in KiB (default 32).
    pub block_size_kib: u16,
    /// Payload padding policy — default Padmé (C71).
    pub pad_mode: PadMode,
    /// Allow below-floor KDF (tests/scripts only).
    pub allow_weak_kdf: bool,
    /// Argon2id memory cost (KiB).
    pub m_cost: u32,
    /// Argon2id time cost.
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u32,
}

impl Default for VolumeCreateOpts {
    fn default() -> Self {
        Self {
            size_bytes: 64 * 1024 * 1024,
            max_bytes: 256 * 1024 * 1024,
            block_size_kib: DEFAULT_BLOCK_KIB,
            pad_mode: PadMode::Padme,
            allow_weak_kdf: false,
            m_cost: ARGON2_DEFAULT_M_COST_KIB,
            t_cost: ARGON2_DEFAULT_T_COST,
            p_cost: ARGON2_DEFAULT_P_COST,
        }
    }
}

/// The volume master split into three independent subkeys. Zeroized on drop.
struct VolumeKeys {
    volume_key: [u8; 32],
    mac_key: [u8; 32],
    nonce_key: [u8; 32],
}

impl VolumeKeys {
    fn derive(master: &[u8; 32], volume_id: &[u8; 16]) -> Self {
        Self {
            volume_key: crypto::hkdf32(master, volume_id, DATA_INFO),
            mac_key: crypto::hkdf32(master, volume_id, MAC_INFO),
            nonce_key: crypto::hkdf32(master, volume_id, NONCE_INFO),
        }
    }
}

impl Drop for VolumeKeys {
    fn drop(&mut self) {
        self.volume_key.zeroize();
        self.mac_key.zeroize();
        self.nonce_key.zeroize();
    }
}

impl std::fmt::Debug for VolumeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeKeys").finish_non_exhaustive()
    }
}

/// An unlocked volume handle. Holds the decrypted VFS in memory; [`Volume::sync`] persists it and
/// keys zeroize on drop.
pub struct Volume {
    path: PathBuf,
    header: Header,
    data_key: DataKey,
    keys: VolumeKeys,
    block_size_kib: u16,
    size_bytes: u64,
    max_bytes: u64,
    pad_mode: PadMode,
    version: u64,
    merkle_root: [u8; 32],
    kcom: [u8; 32],
    vfs: Vfs,
}

impl std::fmt::Debug for Volume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume")
            .field("path", &self.path)
            .field("version", &self.version)
            .field("entries", &self.vfs.len())
            .finish_non_exhaustive()
    }
}

fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Crypto)
}

fn vfail<E>(_: E) -> Error {
    Error::VolumeOpenFailed
}

impl Volume {
    /// Create a new encrypted volume at `path`.
    pub fn create(path: &Path, unlock: &VolumeUnlock<'_>, opts: &VolumeCreateOpts) -> Result<Self> {
        validate_kdf_params(opts.m_cost, opts.t_cost, opts.p_cost)?;
        if !opts.allow_weak_kdf {
            reject_kdf_below_floor(opts.m_cost, opts.t_cost, opts.p_cost)?;
        }
        if opts.block_size_kib == 0 {
            return Err(Error::Crypto);
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
        let stanza = wrap_stanza(
            &data_key,
            unlock,
            &salt,
            &vault_id,
            opts.m_cost,
            opts.t_cost,
            opts.p_cost,
        )?;

        let header = Header {
            magic: MAGIC_VLTD,
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

        let keys = VolumeKeys::derive(data_key.expose_secret(), &vault_id);
        let kcom = envelope::password_key_commitment(
            unlock.password,
            &salt,
            &vault_id,
            opts.m_cost,
            opts.t_cost,
            opts.p_cost,
        )?;

        let mut vol = Self {
            path: path.to_path_buf(),
            header,
            data_key,
            keys,
            block_size_kib: opts.block_size_kib,
            size_bytes: opts.size_bytes,
            max_bytes: opts.max_bytes,
            pad_mode: opts.pad_mode,
            version: 0,
            merkle_root: [0; 32],
            kcom,
            vfs: Vfs::new(),
        };
        vol.persist()?;
        Ok(vol)
    }

    /// Open an existing volume, enforcing the local freshness anchor (C70).
    pub fn open(path: &Path, unlock: &VolumeUnlock<'_>) -> Result<Self> {
        Self::open_inner(path, unlock, true)
    }

    /// Open without the freshness-anchor check — for the trust-anchor flow on a new device (C70).
    pub fn open_ignoring_anchor(path: &Path, unlock: &VolumeUnlock<'_>) -> Result<Self> {
        Self::open_inner(path, unlock, false)
    }

    fn open_inner(path: &Path, unlock: &VolumeUnlock<'_>, check_anchor: bool) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let header = Header::parse_with_kind(&bytes, Some(crate::ContainerKind::Volume))?;
        let (m, t, p) = (header.kdf.m_cost, header.kdf.t_cost, header.kdf.p_cost);
        let data_key = unwrap_data_key(&header, unlock).map_err(vfail)?;
        header
            .verify_hmac(data_key.expose_secret())
            .map_err(vfail)?;
        let vault_id = header.vault_id;
        let keys = VolumeKeys::derive(data_key.expose_secret(), &vault_id);

        // Inner header (dual copy).
        let inner_start = header.on_disk_len();
        let inner_end = inner_start
            .checked_add(2 * INNER_WRAPPED_LEN)
            .ok_or(Error::VolumeOpenFailed)?;
        if bytes.len() < inner_end {
            return Err(Error::VolumeOpenFailed);
        }
        let ih = inner::parse_dual(&keys.volume_key, &vault_id, &bytes[inner_start..inner_end])?;

        // C69 — key commitment: recompute from the password factor and compare constant-time.
        let expected_kcom = envelope::password_key_commitment(
            unlock.password,
            &header.kdf.salt,
            &vault_id,
            m,
            t,
            p,
        )
        .map_err(vfail)?;
        if !bool::from(expected_kcom.ct_eq(&ih.kcom)) {
            return Err(Error::VolumeOpenFailed);
        }

        // Data blocks.
        let capacity = ih.block_size_kib as usize * 1024;
        let block_on_disk = NONCE_LEN + capacity + TAG_LEN;
        let mut plaintexts: Vec<Vec<u8>> = Vec::with_capacity(ih.block_count as usize);
        let mut tags: Vec<[u8; 16]> = Vec::with_capacity(ih.block_count as usize);
        let mut off = inner_end;
        for block_id in 0..ih.block_count as u64 {
            let end = off
                .checked_add(block_on_disk)
                .ok_or(Error::VolumeOpenFailed)?;
            if bytes.len() < end {
                return Err(Error::VolumeOpenFailed);
            }
            let on_disk = &bytes[off..end];
            let kind = if block_id < ih.meta_block_count as u64 {
                KIND_DIR
            } else {
                KIND_FILE
            };
            let pt = block::open_block(
                &keys.volume_key,
                &keys.nonce_key,
                &vault_id,
                block_id,
                ih.version,
                kind,
                on_disk,
            )?;
            tags.push(block::block_tag(on_disk)?);
            plaintexts.push(pt);
            off = end;
        }

        // Merkle root binds every block at this version (ADR-0008).
        let root = merkle::root(&keys.mac_key, ih.version, &tags);
        if !bool::from(root.ct_eq(&ih.merkle_root)) {
            return Err(Error::VolumeOpenFailed);
        }

        // C70 — local freshness anchor.
        if check_anchor {
            anchor::verify_fresh(&vault_id, &ih.merkle_root, ih.version)?;
        }

        let vfs = unpack_vfs(&plaintexts, &ih, capacity)?;

        Ok(Self {
            path: path.to_path_buf(),
            header,
            data_key,
            keys,
            block_size_kib: ih.block_size_kib,
            size_bytes: ih.size_bytes,
            max_bytes: ih.max_bytes,
            pad_mode: ih.pad_mode,
            version: ih.version,
            merkle_root: ih.merkle_root,
            kcom: ih.kcom,
            vfs,
        })
    }

    /// Write the current freshness state as the local trust anchor (C70).
    pub fn trust_anchor(&self) -> Result<()> {
        anchor::write(&self.header.vault_id, &self.merkle_root, self.version)
    }

    /// Persist and zeroize — the graceful close (keys also zeroize on drop).
    pub fn close(mut self) -> Result<()> {
        self.persist()
    }

    /// Flush the in-memory VFS to disk, advancing the volume version and Merkle root.
    pub fn sync(&mut self) -> Result<()> {
        self.persist()
    }

    /// List the immediate child names of `dir` (`""` or `/` for the root).
    pub fn list(&self, dir: &str) -> Result<Vec<String>> {
        let dir = fs::normalize(dir)?;
        let mut out = Vec::new();
        for path in self.vfs.keys() {
            if fs::parent_of(path) == dir && !path.is_empty() {
                out.push(fs::base_of(path).to_string());
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Read a file's contents.
    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        let path = fs::normalize(path)?;
        match self.vfs.get(&path) {
            Some(Node::File(data)) => Ok(data.clone()),
            _ => Err(Error::VolumeOpenFailed),
        }
    }

    /// Write (create or replace) a file, auto-creating parent directories.
    pub fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let path = fs::normalize(path)?;
        if path.is_empty() {
            return Err(Error::VolumeOpenFailed);
        }
        self.ensure_parents(&path)?;
        self.vfs.insert(path, Node::File(data.to_vec()));
        Ok(())
    }

    /// Create a directory (and any missing parents). Idempotent for existing directories.
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let path = fs::normalize(path)?;
        if path.is_empty() {
            return Ok(());
        }
        if let Some(Node::File(_)) = self.vfs.get(&path) {
            return Err(Error::VolumeOpenFailed);
        }
        self.ensure_parents(&path)?;
        self.vfs.entry(path).or_insert(Node::Dir);
        Ok(())
    }

    /// Remove a file; its freed blocks are securely overwritten on the next [`Volume::sync`].
    pub fn unlink(&mut self, path: &str) -> Result<()> {
        let path = fs::normalize(path)?;
        match self.vfs.get(&path) {
            Some(Node::File(_)) => {
                self.vfs.remove(&path);
                Ok(())
            }
            _ => Err(Error::VolumeOpenFailed),
        }
    }

    /// Remove an empty directory. Fails closed if the path is not an empty directory (a directory
    /// with children, a file, or a missing path all collapse to [`Error::VolumeOpenFailed`]).
    pub fn rmdir(&mut self, path: &str) -> Result<()> {
        let path = fs::normalize(path)?;
        if path.is_empty() {
            return Err(Error::VolumeOpenFailed);
        }
        match self.vfs.get(&path) {
            Some(Node::Dir) => {
                let prefix = format!("{path}/");
                if self.vfs.keys().any(|k| k.starts_with(&prefix)) {
                    return Err(Error::VolumeOpenFailed);
                }
                self.vfs.remove(&path);
                Ok(())
            }
            _ => Err(Error::VolumeOpenFailed),
        }
    }

    /// Rename a file or directory (moves the whole subtree for a directory).
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let from = fs::normalize(from)?;
        let to = fs::normalize(to)?;
        if from.is_empty() || to.is_empty() {
            return Err(Error::VolumeOpenFailed);
        }
        let prefix = format!("{from}/");
        let movable: Vec<String> = self
            .vfs
            .keys()
            .filter(|k| **k == from || k.starts_with(&prefix))
            .cloned()
            .collect();
        if movable.is_empty() {
            return Err(Error::VolumeOpenFailed);
        }
        self.ensure_parents(&to)?;
        for key in movable {
            let node = self.vfs.remove(&key).expect("key just listed");
            let new_key = if key == from {
                to.clone()
            } else {
                format!("{to}{}", &key[from.len()..])
            };
            self.vfs.insert(new_key, node);
        }
        Ok(())
    }

    /// Truncate or zero-extend a file to `len` bytes.
    pub fn truncate(&mut self, path: &str, len: u64) -> Result<()> {
        let path = fs::normalize(path)?;
        match self.vfs.get_mut(&path) {
            Some(Node::File(data)) => {
                data.resize(len as usize, 0);
                Ok(())
            }
            _ => Err(Error::VolumeOpenFailed),
        }
    }

    /// Size of a file in bytes.
    pub fn getattr_size(&self, path: &str) -> Result<u64> {
        let path = fs::normalize(path)?;
        match self.vfs.get(&path) {
            Some(Node::File(data)) => Ok(data.len() as u64),
            _ => Err(Error::VolumeOpenFailed),
        }
    }

    /// Change the advisory logical volume size (must stay within `max_bytes`).
    pub fn resize(&mut self, new_size: u64) -> Result<()> {
        if new_size > self.max_bytes {
            return Err(Error::Crypto);
        }
        self.size_bytes = new_size;
        Ok(())
    }

    /// Re-wrap the unlock stanza + key commitment under new Argon2id parameters. The master keys
    /// (and therefore all block ciphertext) are unchanged — this is a header-only rotation (C: parity
    /// with sealed `change_kdf`), persisted in place.
    pub fn upgrade_kdf(
        &mut self,
        unlock: &VolumeUnlock<'_>,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<()> {
        validate_kdf_params(m_cost, t_cost, p_cost)?;
        reject_kdf_below_floor(m_cost, t_cost, p_cost)?;
        let salt = self.header.kdf.salt;
        let vid = self.header.vault_id;
        let stanza = wrap_stanza(&self.data_key, unlock, &salt, &vid, m_cost, t_cost, p_cost)?;
        self.header.stanzas = vec![stanza];
        self.header.kdf.m_cost = m_cost;
        self.header.kdf.t_cost = t_cost;
        self.header.kdf.p_cost = p_cost;
        self.kcom = envelope::password_key_commitment(
            unlock.password,
            &salt,
            &vid,
            m_cost,
            t_cost,
            p_cost,
        )?;
        self.persist()
    }

    /// On-disk path of this volume.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The 16-byte volume identity (header `vault_id`).
    pub fn volume_id(&self) -> [u8; 16] {
        self.header.vault_id
    }

    /// Advisory logical size in bytes (the file grows with content up to `max_bytes`).
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Maximum logical size in bytes.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Data-block plaintext capacity in KiB.
    pub fn block_size_kib(&self) -> u16 {
        self.block_size_kib
    }

    /// Payload padding policy (default Padmé — C71).
    pub fn pad_mode(&self) -> PadMode {
        self.pad_mode
    }

    /// Monotonic on-disk version counter (freshness-anchor input — C70).
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Metadata kind of a path — directory, or file with its byte length. Returns `None` for a
    /// missing path. Never exposes file contents (C71/C27). The root (`""` / `/`) is a directory.
    pub fn node_kind(&self, path: &str) -> Option<NodeKind> {
        let path = fs::normalize(path).ok()?;
        if path.is_empty() {
            return Some(NodeKind::Dir);
        }
        match self.vfs.get(&path) {
            Some(Node::Dir) => Some(NodeKind::Dir),
            Some(Node::File(data)) => Some(NodeKind::File(data.len() as u64)),
            None => None,
        }
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn ensure_parents(&mut self, path: &str) -> Result<()> {
        let mut acc = String::new();
        let segs: Vec<&str> = path.split('/').collect();
        for seg in &segs[..segs.len().saturating_sub(1)] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            if let Some(Node::File(_)) = self.vfs.get(&acc) {
                return Err(Error::VolumeOpenFailed);
            }
            self.vfs.entry(acc.clone()).or_insert(Node::Dir);
        }
        Ok(())
    }

    fn persist(&mut self) -> Result<()> {
        self.version = self.version.checked_add(1).ok_or(Error::Crypto)?;
        let capacity = self.block_size_kib as usize * 1024;

        // 1. Build inode table (block runs assigned after the dir-meta region).
        let (inodes_no_layout, file_bodies) = self.collect_inodes();
        let meta_len = fs::encode_inodes(&inodes_no_layout).len() as u64; // path-only dependent
        let meta_block_count = div_ceil(meta_len as usize, capacity).max(1) as u32;

        let mut inodes = inodes_no_layout;
        let mut next_block = meta_block_count as u64;
        let mut file_idx = 0usize;
        for ino in &mut inodes {
            if !ino.is_dir {
                let bc = ino.block_count;
                ino.first_block = next_block;
                next_block += bc;
                file_idx += 1;
            }
        }
        debug_assert_eq!(file_idx, file_bodies.len());
        let block_count = next_block;

        let meta_bytes = fs::encode_inodes(&inodes);
        debug_assert_eq!(meta_bytes.len() as u64, meta_len);

        // 2. Seal blocks (dir-meta region, then file-data region) and collect tags.
        let vid = self.header.vault_id;
        let mut body = Vec::new();
        let mut tags: Vec<[u8; 16]> = Vec::with_capacity(block_count as usize);
        let mut block_id = 0u64;
        for chunk in fixed_chunks(&meta_bytes, capacity, meta_block_count as usize) {
            let sealed = block::seal_block(
                &self.keys.volume_key,
                &self.keys.nonce_key,
                &vid,
                block_id,
                self.version,
                KIND_DIR,
                &chunk,
            )?;
            tags.push(block::block_tag(&sealed)?);
            body.extend_from_slice(&sealed);
            block_id += 1;
        }
        for data in &file_bodies {
            let nblocks = div_ceil(data.len(), capacity);
            for chunk in fixed_chunks(data, capacity, nblocks) {
                let sealed = block::seal_block(
                    &self.keys.volume_key,
                    &self.keys.nonce_key,
                    &vid,
                    block_id,
                    self.version,
                    KIND_FILE,
                    &chunk,
                )?;
                tags.push(block::block_tag(&sealed)?);
                body.extend_from_slice(&sealed);
                block_id += 1;
            }
        }
        debug_assert_eq!(block_id, block_count);

        // 3. Merkle root + inner header.
        self.merkle_root = merkle::root(&self.keys.mac_key, self.version, &tags);
        let ih = InnerHeader {
            block_size_kib: self.block_size_kib,
            pad_mode: self.pad_mode,
            size_bytes: self.size_bytes,
            max_bytes: self.max_bytes,
            version: self.version,
            block_count: block_count as u32,
            meta_block_count,
            meta_len,
            kcom: self.kcom,
            merkle_root: self.merkle_root,
        };
        let inner_bytes = inner::serialize_dual(&self.keys.volume_key, &vid, &ih)?;

        // 4. Assemble: outer header (fresh seeds each save) + inner + blocks, then Padmé pad.
        random_bytes(&mut self.header.master_seed)?;
        random_bytes(&mut self.header.nonce_prefix)?;
        self.header.seal(self.data_key.expose_secret());
        let mut out = self.header.serialize();
        out.extend_from_slice(&inner_bytes);
        out.extend_from_slice(&body);

        let pad_len = self
            .pad_mode
            .padded_len(out.len())
            .saturating_sub(out.len());
        if pad_len > 0 {
            out.resize(out.len() + pad_len, 0);
        }

        write_file_secure(&self.path, &out)
    }

    /// Sorted inode table (no block layout yet) + file bodies in the same order (files only).
    fn collect_inodes(&self) -> (Vec<Inode>, Vec<Vec<u8>>) {
        let capacity = self.block_size_kib as usize * 1024;
        let mut inodes = Vec::with_capacity(self.vfs.len());
        let mut bodies = Vec::new();
        for (path, node) in &self.vfs {
            match node {
                Node::Dir => inodes.push(Inode {
                    path: path.clone(),
                    is_dir: true,
                    length: 0,
                    first_block: 0,
                    block_count: 0,
                }),
                Node::File(data) => {
                    inodes.push(Inode {
                        path: path.clone(),
                        is_dir: false,
                        length: data.len() as u64,
                        first_block: 0,
                        block_count: div_ceil(data.len(), capacity) as u64,
                    });
                    bodies.push(data.clone());
                }
            }
        }
        (inodes, bodies)
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        self.merkle_root.zeroize();
        self.kcom.zeroize();
        // `keys` (VolumeKeys) and `data_key` (Secret) zeroize via their own Drop impls.
    }
}

/// Wrap the master data key in a password (or composite keyfile) stanza — C61 parity with sealed.
fn wrap_stanza(
    data_key: &DataKey,
    unlock: &VolumeUnlock<'_>,
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m: u32,
    t: u32,
    p: u32,
) -> Result<crate::format::Stanza> {
    match unlock.keyfile {
        Some(kf) => envelope::wrap_keyfile_2fa_stanza(
            data_key.expose_secret(),
            unlock.password,
            kf,
            salt,
            vault_id,
            m,
            t,
            p,
        ),
        None => envelope::wrap_password_stanza(
            data_key.expose_secret(),
            unlock.password,
            salt,
            vault_id,
            m,
            t,
            p,
        ),
    }
}

/// Unwrap the master data key (keyfile stanza when a keyfile is supplied, else password) — C61.
fn unwrap_data_key(header: &Header, unlock: &VolumeUnlock<'_>) -> Result<DataKey> {
    let (m, t, p) = (header.kdf.m_cost, header.kdf.t_cost, header.kdf.p_cost);
    if let Some(kf) = unlock.keyfile {
        if let Some(s) = header
            .stanzas
            .iter()
            .find(|s| s.stanza_type == kind::PW_KEYFILE)
        {
            return envelope::unwrap_keyfile_2fa_stanza(
                s,
                unlock.password,
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
    envelope::unwrap_password_stanza(
        s,
        unlock.password,
        &header.kdf.salt,
        &header.vault_id,
        m,
        t,
        p,
    )
}

/// Reconstruct the VFS from decrypted blocks + the inode table.
fn unpack_vfs(plaintexts: &[Vec<u8>], ih: &InnerHeader, capacity: usize) -> Result<Vfs> {
    let mut meta = Vec::with_capacity(ih.meta_block_count as usize * capacity);
    for pt in plaintexts.iter().take(ih.meta_block_count as usize) {
        meta.extend_from_slice(pt);
    }
    if (ih.meta_len as usize) > meta.len() {
        return Err(Error::VolumeOpenFailed);
    }
    meta.truncate(ih.meta_len as usize);
    let inodes = fs::decode_inodes(&meta)?;

    let mut vfs = Vfs::new();
    for ino in inodes {
        if ino.is_dir {
            vfs.insert(ino.path, Node::Dir);
            continue;
        }
        let first = ino.first_block as usize;
        let end = first
            .checked_add(ino.block_count as usize)
            .ok_or(Error::VolumeOpenFailed)?;
        if end > plaintexts.len() {
            return Err(Error::VolumeOpenFailed);
        }
        let mut data = Vec::with_capacity(ino.length as usize);
        for pt in &plaintexts[first..end] {
            data.extend_from_slice(pt);
        }
        if (ino.length as usize) > data.len() {
            return Err(Error::VolumeOpenFailed);
        }
        data.truncate(ino.length as usize);
        vfs.insert(ino.path, Node::File(data));
    }
    Ok(vfs)
}

/// Split `data` into exactly `count` fixed-size chunks, zero-padding the final chunk.
fn fixed_chunks(data: &[u8], capacity: usize, count: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * capacity;
        let mut chunk = vec![0u8; capacity];
        if start < data.len() {
            let take = (data.len() - start).min(capacity);
            chunk[..take].copy_from_slice(&data[start..start + take]);
        }
        out.push(chunk);
    }
    out
}

fn div_ceil(n: usize, d: usize) -> usize {
    n.div_ceil(d)
}

/// Write the volume file in place, overwriting any shrunk tail with random bytes first so freed
/// ciphertext is destroyed before the file is truncated (secure free — C: unlink).
fn write_file_secure(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut oo = std::fs::OpenOptions::new();
    oo.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.mode(0o600);
    }
    let mut f = oo.open(path)?;
    let old_len = f.metadata()?.len();
    let new_len = bytes.len() as u64;
    if old_len > new_len {
        f.seek(SeekFrom::Start(new_len))?;
        let mut remaining = old_len - new_len;
        let mut rnd = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let take = remaining.min(rnd.len() as u64) as usize;
            random_bytes(&mut rnd[..take])?;
            f.write_all(&rnd[..take])?;
            remaining -= take as u64;
        }
        f.sync_data()?;
        f.set_len(new_len)?;
    }
    f.seek(SeekFrom::Start(0))?;
    f.write_all(bytes)?;
    f.set_len(new_len)?;
    f.sync_all()?;
    Ok(())
}
