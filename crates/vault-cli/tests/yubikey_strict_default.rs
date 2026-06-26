//! YubiKey strict default regression tests (security-gap review P1).
//!
//! Patterns: `internal/patterns/vault/yubikey_strict_default_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn yubikey_strict_research_and_patterns_exist() {
    let research = read_repo_file("research/yubikey_strict_default_research.md");
    assert!(research.contains("yubikey_strict"));
}

#[test]
fn cli_documents_yubikey_strict_flags() {
    let cli = read_repo_file("docs/CLI.md");
    for needle in [
        "--strict-yubikey",
        "--allow-stale-yubikey",
        "strict saves by default",
    ] {
        assert!(cli.contains(needle), "CLI.md missing: {needle}");
    }
    assert!(
        cli.contains("graceful-yubikey") || cli.contains("--graceful-yubikey"),
        "CLI.md must document graceful enrollment opt-out"
    );
}

#[test]
fn core_exports_yubikey_stale_warning() {
    assert!(vault_core::YUBIKEY_STALE_WARNING.contains("not refreshed"));
}

#[test]
fn payload_yubikey_strict_tlv_round_trips() {
    use vault_core::format::entry::Protected;
    use vault_core::format::payload::{Payload, INNER_STREAM_KEY_LEN};
    use vault_core::pad::PadMode;

    let p = Payload {
        inner_stream_key: Protected::new(vec![0xAB; INNER_STREAM_KEY_LEN]),
        pad_mode: PadMode::None,
        vault_version: 2,
        yubikey_strict: true,
        entries: vec![],
        usage: vault_core::frecency::FrecencyStore::new(),
    };
    let parsed = Payload::parse(&p.serialize()).unwrap();
    assert!(parsed.yubikey_strict);
}
