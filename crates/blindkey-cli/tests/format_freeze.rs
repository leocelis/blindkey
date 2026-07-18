//! Format v1 freeze regression tests (ADR-0005).
//!

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn pre_release_notice_covers_audit_not_format_instability() {
    let src = read_repo_file("crates/blindkey-cli/src/commands/mod.rs");
    let start = src
        .find("pub const PRE_RELEASE_NOTICE")
        .expect("PRE_RELEASE_NOTICE");
    let notice = &src[start..start + 400];
    assert!(
        notice.contains("third-party security audit"),
        "notice must warn about third-party audit posture"
    );
    assert!(
        !notice.to_lowercase().contains("format may"),
        "notice must not claim format instability after freeze: {notice}"
    );
}

#[test]
fn readme_declares_format_v1_stable_not_may_change() {
    let readme = read_repo_file("README.md");
    assert!(
        !readme.contains("format may still change"),
        "README must not warn format may still change after ADR-0005"
    );
    assert!(
        readme.contains("format v1 is stable") || readme.contains("ADR-0005"),
        "README must declare format v1 stable"
    );
}

#[test]
fn security_md_declares_format_v1_stable() {
    let sec = read_repo_file("SECURITY.md");
    assert!(
        !sec.contains("format may still change"),
        "SECURITY.md must not warn format may still change"
    );
    assert!(
        sec.contains("format v1 is stable") || sec.contains("ADR-0005"),
        "SECURITY.md must declare format v1 stable"
    );
}

#[test]
fn adr_0005_exists_and_accepts_freeze() {
    let adr = read_repo_file("docs/adr/0005-format-v1-freeze.md");
    assert!(adr.contains("Status:** Accepted"));
    assert!(adr.contains("format_version = 1"));
}
