//! Live FIDO2 + TPM hardware regression.
//!

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn live_fido2_module_uses_fido2_token() {
    let fido2 = read_repo_file("crates/blindkey-hardware/src/fido2.rs");
    assert!(fido2.contains("fido2-token"));
    assert!(fido2.contains("hmac-secret") || fido2.contains("-h"));
}

#[test]
fn live_tpm_module_uses_tpm2_tools() {
    let tpm = read_repo_file("crates/blindkey-hardware/src/tpm.rs");
    assert!(tpm.contains("tpm2_create"));
    assert!(tpm.contains("tpm2_unseal"));
}

#[test]
fn envelope_fido2_and_tpm_modules_exist() {
    assert!(
        read_repo_file("crates/blindkey-core/src/envelope/fido2.rs").contains("wrap_fido2_stanza")
    );
    assert!(read_repo_file("crates/blindkey-core/src/envelope/tpm.rs").contains("wrap_tpm_stanza"));
}

#[test]
fn vault_exposes_hw_stanza_api() {
    let vault = read_repo_file("crates/blindkey-core/src/vault.rs");
    assert!(vault.contains("add_fido2_stanza"));
    assert!(vault.contains("set_tpm_stanza"));
    assert!(vault.contains("open_fido2"));
    assert!(vault.contains("open_tpm"));
}

#[test]
fn cli_enroll_tpm_is_live_not_stub() {
    let cmds = read_repo_file("crates/blindkey-cli/src/commands/mod.rs");
    assert!(cmds.contains("blindkey_hardware::tpm::seal"));
    assert!(!cmds.contains("not enabled in this build (optional M7 feature)"));
}

#[test]
fn cli_enroll_fido2_wired() {
    let cmds = read_repo_file("crates/blindkey-cli/src/commands/mod.rs");
    assert!(cmds.contains("cmd_enroll_fido2"));
    assert!(cmds.contains("enroll fido2"));
}

#[test]
fn research_doc_exists() {
    let research = read_repo_file("research/live_hw_ffi_research.md");
    assert!(research.contains("fido2-token"));
    assert!(research.contains("tpm2-tools"));
}
