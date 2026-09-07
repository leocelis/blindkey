//! Local freshness anchor (UC-25 / C70).
//!
//! Mirrors the [`crate::rollback`] anchor style: a small file kept in the platform data dir, outside
//! any sync backend, recording the last-trusted `(merkle_root, version)`. On open, a disk volume
//! whose version regresses below the anchor — or forks at the same version — fails closed with
//! [`Error::VolumeAnchorMismatch`] unless the caller explicitly ignores it. A missing anchor is
//! trust-on-first-use (the documented residual risk, same as rollback).

use std::path::PathBuf;

use crate::{rollback, Error, Result};

const ANCHOR_LEN: usize = 32 + 8; // merkle_root || version_le

/// Last-trusted freshness state for a volume.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Anchor {
    pub root: [u8; 32],
    pub version: u64,
}

/// `<data_dir>/blindkey/volume-anchors/<hex volume_id>/anchor.bin` — reuses the rollback platform
/// data dir so macOS/Linux/Windows paths stay identical (C17).
pub(crate) fn anchor_path(volume_id: &[u8; 16]) -> Result<PathBuf> {
    let state = rollback::anchor_path(volume_id)?; // <data_dir>/blindkey/<hex>.state
    let blindkey_dir = state
        .parent()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no data dir",
            ))
        })?
        .to_path_buf();
    Ok(blindkey_dir
        .join("volume-anchors")
        .join(hex16(volume_id))
        .join("anchor.bin"))
}

/// Read the local anchor, or `None` when absent/short (trust-on-first-use).
pub(crate) fn read(volume_id: &[u8; 16]) -> Result<Option<Anchor>> {
    let path = anchor_path(volume_id)?;
    match std::fs::read(&path) {
        Ok(b) if b.len() >= ANCHOR_LEN => {
            let mut root = [0u8; 32];
            root.copy_from_slice(&b[..32]);
            let version = u64::from_le_bytes(b[32..40].try_into().unwrap());
            Ok(Some(Anchor { root, version }))
        }
        _ => Ok(None),
    }
}

/// Write (trust) the current `(root, version)` as the local anchor — atomic replace.
pub(crate) fn write(volume_id: &[u8; 16], root: &[u8; 32], version: u64) -> Result<()> {
    let path = anchor_path(volume_id)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut buf = Vec::with_capacity(ANCHOR_LEN);
    buf.extend_from_slice(root);
    buf.extend_from_slice(&version.to_le_bytes());

    use std::io::Write;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut oo = std::fs::OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o600);
        }
        let mut f = oo.open(&tmp)?;
        f.write_all(&buf)?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Fail closed if the disk state is stale versus the anchor (regressed version, or a fork at the
/// same version). Forward progress (higher version) is accepted.
pub(crate) fn verify_fresh(
    volume_id: &[u8; 16],
    disk_root: &[u8; 32],
    disk_version: u64,
) -> Result<()> {
    match read(volume_id)? {
        None => Ok(()), // trust-on-first-use
        Some(a) => {
            let stale =
                disk_version < a.version || (disk_version == a.version && disk_root != &a.root);
            if stale {
                Err(Error::VolumeAnchorMismatch)
            } else {
                Ok(())
            }
        }
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
