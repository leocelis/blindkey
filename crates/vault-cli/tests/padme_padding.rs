//! Padmé padding exploration regression (security-gap review P3, S-12).
//!
//! Patterns: `internal/patterns/vault/padme_padding_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn padme_guide_documents_default_off_and_toggle() {
    let guide = read_repo_file("docs/guides/size-padding-padme.md");
    for needle in ["Default: off", "vault pad on", "Padmé", "mtime"] {
        assert!(
            guide.contains(needle),
            "size-padding guide missing: {needle}"
        );
    }
}

#[test]
fn pad_rs_defaults_none_and_exports_padme() {
    let pad = read_repo_file("crates/vault-core/src/pad.rs");
    assert!(pad.contains("#[default]") && pad.contains("None"));
    assert!(pad.contains("pub fn padme"));
    assert!(pad.contains("Optional, default off"));
}

#[test]
fn vault_create_defaults_padding_none() {
    let vault = read_repo_file("crates/vault-core/src/vault.rs");
    assert!(
        vault.contains("pad_mode: crate::pad::PadMode::None"),
        "Vault::create must default pad_mode to None"
    );
}

#[test]
fn roadmap_marks_s12_done() {
    let roadmap = read_repo_file("ROADMAP.md");
    assert!(
        roadmap.contains("S-12") && roadmap.contains("Padmé") && roadmap.contains("DONE"),
        "ROADMAP S-12 must mark Padmé exploration done"
    );
}

#[test]
fn research_and_patterns_exist() {
    let research = read_repo_file("research/padme_padding_research.md");
    assert!(research.contains("default-off"));
    assert!(research.contains("v2"));
    let patterns = std::fs::read_to_string(
        repo_root().join("../internal/patterns/vault/padme_padding_patterns.yaml"),
    )
    .unwrap_or_else(|e| panic!("read padme_padding_patterns.yaml: {e}"));
    assert!(patterns.contains("PAD-01"));
}

#[test]
fn cli_documents_pad_command() {
    let cli = read_repo_file("docs/CLI.md");
    assert!(cli.contains("vault pad") && cli.contains("Padmé"));
}
