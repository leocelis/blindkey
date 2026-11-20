//! Default on-disk locations shared by every frontend (CLI, TUI, desktop app).
//!
//! One implementation so the frontends cannot drift apart: a vault created with
//! `blindkey init` is the same vault the desktop app and the TUI open by default.
//! The directory is `~/.blindkey` (intent C47 names `~/.blindkey/config`).
//!
//! Desktop and TUI builds up to 1.1.1 defaulted to `~/.vault`. When `~/.blindkey`
//! does not exist yet and `~/.vault/vault.vlt` does, that legacy directory is used,
//! so an existing vault keeps opening without a move. Nothing here moves or copies
//! files.

use std::path::{Path, PathBuf};

/// Default data directory name under the home directory.
pub const DEFAULT_DIR_NAME: &str = ".blindkey";
/// Directory name used by desktop/TUI builds up to 1.1.1.
pub const LEGACY_DIR_NAME: &str = ".vault";
/// Vault file name inside the data directory.
pub const VAULT_FILE_NAME: &str = "vault.vlt";

/// The user's home directory (`HOME`, else `USERPROFILE`).
#[must_use]
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Data directory under `home`: `home/.blindkey`, or the legacy `home/.vault` when only
/// the legacy directory holds a vault.
#[must_use]
pub fn data_dir_in(home: &Path) -> PathBuf {
    let current = home.join(DEFAULT_DIR_NAME);
    let legacy = home.join(LEGACY_DIR_NAME);
    if !current.exists() && legacy.join(VAULT_FILE_NAME).is_file() {
        legacy
    } else {
        current
    }
}

/// Data directory for the current user, or `None` when no home directory is known.
#[must_use]
pub fn data_dir() -> Option<PathBuf> {
    home_dir().map(|h| data_dir_in(&h))
}

/// Default vault file for the current user: `<data dir>/vault.vlt`.
#[must_use]
pub fn default_vault_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join(VAULT_FILE_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(tag: &str) -> PathBuf {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("rng");
        let p = std::env::temp_dir().join(format!(
            "bk-paths-{tag}-{}",
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    #[test]
    fn fresh_home_uses_dot_blindkey() {
        let h = temp_home("fresh");
        assert_eq!(data_dir_in(&h), h.join(".blindkey"));
        std::fs::remove_dir_all(&h).ok();
    }

    #[test]
    fn legacy_vault_alone_keeps_opening() {
        let h = temp_home("legacy");
        std::fs::create_dir_all(h.join(".vault")).expect("mkdir");
        std::fs::write(h.join(".vault/vault.vlt"), b"x").expect("write");
        assert_eq!(data_dir_in(&h), h.join(".vault"));
        std::fs::remove_dir_all(&h).ok();
    }

    #[test]
    fn dot_blindkey_wins_when_both_exist() {
        let h = temp_home("both");
        std::fs::create_dir_all(h.join(".vault")).expect("mkdir");
        std::fs::write(h.join(".vault/vault.vlt"), b"x").expect("write");
        std::fs::create_dir_all(h.join(".blindkey")).expect("mkdir");
        assert_eq!(data_dir_in(&h), h.join(".blindkey"));
        std::fs::remove_dir_all(&h).ok();
    }

    #[test]
    fn legacy_dir_without_a_vault_is_ignored() {
        let h = temp_home("emptylegacy");
        std::fs::create_dir_all(h.join(".vault")).expect("mkdir");
        assert_eq!(data_dir_in(&h), h.join(".blindkey"));
        std::fs::remove_dir_all(&h).ok();
    }
}
