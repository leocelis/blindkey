//! Rollback detection — constraint **C16**.
//!
//! STREAM segment-binding stops intra-file tampering but not whole-file rollback (a sync backend
//! serving an older, still-valid ciphertext). We keep a monotonic `vault_version` inside the
//! encrypted payload and compare it against a **local** last-seen anchor stored outside the sync
//! backend's control (platform XDG/AppData path, never inside the synced vault directory — C17).
//!
//! The anchor is an alarm wire, not a lock: a missing/short/garbage file reads as `0`, so a fresh
//! machine trusts the first version it sees (trust-on-first-use — the documented residual risk in
//! [`docs/THREAT_MODEL.md`]). Advancing is monotonic (`max`) and serialized by an advisory file
//! lock so two concurrent `blindkey` processes can never lower it.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Outcome of comparing the decrypted version counter against the local anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackCheck {
    /// `payload_version >= last_seen` — fine; the anchor will be advanced.
    Ok,
    /// `payload_version < last_seen` — the backend may have served an older copy. Abort unless the
    /// user explicitly allows it (and never prompt on a non-TTY — abort with exit code 2).
    Regressed {
        /// The locally-anchored last-seen version (the minimum we expected).
        expected: u64,
        /// The version found in the decrypted payload.
        got: u64,
    },
}

/// Compare a decrypted vault version against the locally-anchored last-seen value (constraint C16).
pub fn check(payload_version: u64, last_seen: u64) -> RollbackCheck {
    if payload_version >= last_seen {
        RollbackCheck::Ok
    } else {
        RollbackCheck::Regressed {
            expected: last_seen,
            got: payload_version,
        }
    }
}

/// Read the local last-seen version for an anchor file. A missing, empty, short, or unreadable file
/// reads as `0` (never an error — the anchor is an alarm wire, constraint C16).
pub fn read_anchor(path: &Path) -> u64 {
    match std::fs::read(path) {
        Ok(b) if b.len() >= 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
        _ => 0,
    }
}

/// Advance the anchor to `max(current, seen)` — monotonic, atomic, and serialized by an advisory
/// lock so concurrent processes cannot lower it (constraint C16 / UC-07 §3.4).
pub fn advance_anchor(path: &Path, seen: u64) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    with_anchor_lock(path, || {
        let current = read_anchor(path);
        let new = current.max(seen);
        if new == current && path.exists() {
            return Ok(());
        }
        write_u64_atomic(path, new)
    })
}

/// Path to the non-synced local state anchor for a given vault id (constraints C16, C17).
///
/// `<data_dir>/blindkey/<vault_id_hex>.state` — `data_dir` is `$XDG_DATA_HOME` (or `~/.local/share`)
/// on Linux, `~/Library/Application Support` on macOS, `%LOCALAPPDATA%` on Windows.
pub fn anchor_path(vault_id: &[u8; 16]) -> Result<PathBuf> {
    Ok(data_dir()?
        .join("blindkey")
        .join(format!("{}.state", hex16(vault_id))))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn write_u64_atomic(path: &Path, value: u64) -> Result<()> {
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
        f.write_all(&value.to_le_bytes())?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn with_anchor_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    use std::os::unix::io::AsRawFd;
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    // Best-effort advisory lock; if the lock file can't be opened we proceed unlocked (the `max`
    // keeps the anchor monotonic in the common case — the lock only closes the concurrent-save race).
    let locked_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path);
    match locked_file {
        Ok(file) => {
            let fd = file.as_raw_fd();
            let held = blindkey_sys::flock_exclusive(fd);
            let r = f();
            if held {
                blindkey_sys::flock_unlock(fd);
            }
            r
        }
        Err(_) => f(),
    }
}

#[cfg(not(unix))]
fn with_anchor_lock<T>(_path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    f()
}

fn data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(no_data_dir)?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support"))
    }
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var_os("LOCALAPPDATA").ok_or_else(no_data_dir)?;
        Ok(PathBuf::from(local))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return Ok(PathBuf::from(xdg));
            }
        }
        let home = std::env::var_os("HOME").ok_or_else(no_data_dir)?;
        Ok(PathBuf::from(home).join(".local").join("share"))
    }
}

fn no_data_dir() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "cannot determine a local data directory for the rollback anchor",
    ))
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_ok_when_equal_or_greater() {
        assert_eq!(check(5, 5), RollbackCheck::Ok);
        assert_eq!(check(6, 5), RollbackCheck::Ok);
        assert_eq!(check(3, 0), RollbackCheck::Ok); // trust-on-first-use (anchor 0)
    }

    #[test]
    fn check_regressed_when_lower() {
        assert_eq!(
            check(3, 5),
            RollbackCheck::Regressed {
                expected: 5,
                got: 3
            }
        );
    }

    #[test]
    fn read_anchor_missing_or_short_is_zero() {
        let dir = std::env::temp_dir().join(format!("vault-anchor-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("missing.state");
        assert_eq!(read_anchor(&p), 0);
        std::fs::write(&p, [1u8, 2, 3]).unwrap(); // too short
        assert_eq!(read_anchor(&p), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn advance_is_monotonic_and_atomic() {
        let dir = std::env::temp_dir().join(format!("vault-anchor-mono-{}", std::process::id()));
        let p = dir.join("v.state");
        advance_anchor(&p, 5).unwrap();
        assert_eq!(read_anchor(&p), 5);
        advance_anchor(&p, 3).unwrap(); // lower → ignored
        assert_eq!(read_anchor(&p), 5);
        advance_anchor(&p, 9).unwrap(); // higher → advances
        assert_eq!(read_anchor(&p), 9);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn anchor_path_layout() {
        let id = [0xABu8; 16];
        let p = anchor_path(&id).unwrap();
        assert!(p.ends_with("blindkey/abababababababababababababababab.state"));
    }
}
