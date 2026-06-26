//! v1.0.0 release regression tests (security-gap review P0 item 2).
//!
//! Patterns: `internal/patterns/vault/v1_release_patterns.yaml`

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn workspace_version_is_1_0_0() {
    let toml = read_repo_file("Cargo.toml");
    assert!(
        toml.contains("version = \"1.0.0\""),
        "workspace.package version must be 1.0.0"
    );
}

#[test]
fn readme_dropped_pre_1_0_banner_language() {
    let readme = read_repo_file("README.md");
    assert!(
        !readme.contains("Pre-1.0") && !readme.contains("pre-1.0"),
        "README must not use pre-1.0 banner after v1.0.0"
    );
    assert!(
        readme.contains("v1.0.0") && readme.contains("third-party"),
        "README must state v1.0.0 and honest audit posture"
    );
}

#[test]
fn changelog_has_1_0_0_section() {
    let log = read_repo_file("CHANGELOG.md");
    assert!(log.contains("## [1.0.0]"));
}

#[test]
fn check_release_version_script_accepts_v1_0_0() {
    let script = repo_root().join("scripts/check-release-version.sh");
    let out = Command::new("bash")
        .arg(script)
        .arg("v1.0.0")
        .current_dir(repo_root())
        .output()
        .expect("run check-release-version.sh");
    assert!(
        out.status.success(),
        "check-release-version.sh v1.0.0 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
