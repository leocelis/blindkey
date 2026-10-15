//! Guard: Linux must never enable fuser's `libfuse` feature (that selects libfuse3 on
//! Linux hosts and is the RUSTSEC-2021-0154 path). macOS `macos-fuse` may enable
//! `libfuse` (fuser builds libfuse2 against macFUSE). See docs/SUPPLY_CHAIN.md.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Slice from a `[section]` marker through the next line that starts a new `[…]` table.
fn section_after(hay: &str, marker: &str) -> String {
    let idx = hay
        .find(marker)
        .unwrap_or_else(|| panic!("missing section marker: {marker}"));
    let rest = &hay[idx + marker.len()..];
    let mut end = rest.len();
    for (i, line) in rest.lines().enumerate() {
        if i == 0 {
            continue;
        }
        if line.starts_with('[') {
            end = rest.find(line).unwrap_or(rest.len());
            break;
        }
    }
    rest[..end].to_string()
}

#[test]
fn workspace_fuser_default_features_off() {
    let cargo = read("Cargo.toml");
    // Prefer the dependency key line, not the "fusermount" prose comment.
    let line = cargo
        .lines()
        .find(|l| l.trim_start().starts_with("fuser"))
        .expect("workspace Cargo.toml must declare fuser = …");
    assert!(
        line.contains("default-features = false"),
        "workspace fuser must keep default-features = false (pure-Rust on Linux):\n{line}"
    );
    assert!(
        !line.contains("libfuse"),
        "workspace fuser must not enable libfuse:\n{line}"
    );
}

#[test]
fn linux_target_fuser_is_workspace_only() {
    let fuse = read("crates/blindkey-fuse/Cargo.toml");
    let linux = section_after(&fuse, "[target.'cfg(target_os = \"linux\")'.dependencies]");
    assert!(
        linux.contains("fuser.workspace = true"),
        "linux fuser must be workspace = true (no libfuse feature pin):\n{linux}"
    );
    assert!(
        !linux.contains("libfuse"),
        "linux fuser dep must not name libfuse:\n{linux}"
    );
}

#[test]
fn macos_optional_fuser_may_enable_libfuse() {
    let fuse = read("crates/blindkey-fuse/Cargo.toml");
    let macos = section_after(&fuse, "[target.'cfg(target_os = \"macos\")'.dependencies]");
    assert!(
        macos.contains("libfuse"),
        "macos optional fuser is expected to enable libfuse (libfuse2 / macFUSE):\n{macos}"
    );
}
