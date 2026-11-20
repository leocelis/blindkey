//! Every frontend opens the same default vault (intent C47: `~/.blindkey`).
//!
//! Regression: up to 1.1.1 the CLI defaulted to `~/.blindkey/vault.vlt` while the
//! desktop app and the TUI defaulted to `~/.vault/vault.vlt`, so a vault made with the
//! README Quickstart did not appear in the desktop app. The location now lives in one
//! function (`blindkey_core::paths`, executed by its unit tests); this guard fails if a
//! frontend builds its own default path again.

use std::path::PathBuf;

fn read_repo_file(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

const FRONTENDS: [(&str, &str); 3] = [
    (
        "crates/blindkey-cli/src/commands/mod.rs",
        "paths::default_vault_path()",
    ),
    (
        "crates/blindkey-tui/src/main.rs",
        "paths::default_vault_path()",
    ),
    ("crates/blindkey-gui/src/gui_config.rs", "paths::data_dir()"),
];

#[test]
fn every_frontend_takes_its_default_from_blindkey_core_paths() {
    for (file, call) in FRONTENDS {
        let src = read_repo_file(file);
        assert!(src.contains(call), "{file} must use blindkey_core::{call}");
        for own in [r#"join(".vault")"#, r#"join(".blindkey")"#] {
            assert!(
                !src.contains(own),
                "{file} builds its own default dir with {own}; use blindkey_core::paths"
            );
        }
    }
}
