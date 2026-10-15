//! Release regression tests for the current workspace version.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn workspace_version() -> String {
    let toml = read_repo_file("Cargo.toml");
    let mut in_pkg = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with("[workspace.package]") {
            in_pkg = true;
            continue;
        }
        if in_pkg && t.starts_with('[') {
            break;
        }
        if in_pkg {
            if let Some(rest) = t.strip_prefix("version = \"") {
                return rest.strip_suffix('"').unwrap_or(rest).to_string();
            }
        }
    }
    panic!("workspace.package version in Cargo.toml");
}

#[test]
fn workspace_version_matches_changelog_and_readme() {
    let ver = workspace_version();
    assert!(
        ver.starts_with("1."),
        "post-1.0 workspace version expected, got {ver}"
    );
    let toml = read_repo_file("Cargo.toml");
    assert!(
        toml.contains(&format!("version = \"{ver}\"")),
        "Cargo.toml must declare version {ver}"
    );
    let log = read_repo_file("CHANGELOG.md");
    assert!(
        log.contains(&format!("## [{ver}]")),
        "CHANGELOG.md must have ## [{ver}]"
    );
    assert!(
        log.contains("## [1.0.0]"),
        "CHANGELOG.md must keep the historical ## [1.0.0] section"
    );
    let readme = read_repo_file("README.md");
    assert!(
        !readme.contains("Pre-1.0") && !readme.contains("pre-1.0"),
        "README must not use pre-1.0 banner after v1.0.0"
    );
    assert!(
        readme.contains(&format!("v{ver}")) && readme.contains("third-party"),
        "README must state v{ver} and honest audit posture"
    );
}

#[test]
fn check_release_version_script_accepts_workspace_tag() {
    let ver = workspace_version();
    let tag = format!("v{ver}");
    let script = repo_root().join("scripts/check-release-version.sh");
    let out = Command::new("bash")
        .arg(&script)
        .arg(&tag)
        .current_dir(repo_root())
        .output()
        .expect("run check-release-version.sh");
    assert!(
        out.status.success(),
        "check-release-version.sh {tag} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
