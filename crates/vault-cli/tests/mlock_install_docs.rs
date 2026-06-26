//! mlock / Docker INSTALL doc regression (security-gap review P2, C12).
//!
//! Patterns: `internal/patterns/vault/mlock_degradation_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn install_documents_mlock_docker_and_host_native() {
    let install = read_repo_file("docs/INSTALL.md");
    for needle in ["mlock", "Docker", "EPERM", "IPC_LOCK", "host", "ulimit"] {
        assert!(
            install.contains(needle),
            "INSTALL.md must document mlock/container topic: {needle}"
        );
    }
    assert!(
        install.contains("UC-14") || install.contains("runtime-hardening"),
        "INSTALL must cross-link UC-14"
    );
}

#[test]
fn memory_module_emits_c12_warning_string() {
    let mem = read_repo_file("crates/vault-core/src/memory/mod.rs");
    assert!(
        mem.contains("mlock failed") && mem.contains("CAP_IPC_LOCK"),
        "PageLock must emit UC-14 C12 warning on failure"
    );
    assert!(
        mem.contains("MLOCK_WARNED") || mem.contains("swap(true"),
        "mlock warning must be once per process"
    );
}

#[test]
fn vault_sys_exposes_lock_region_errno() {
    let sys = read_repo_file("crates/vault-sys/src/lib.rs");
    assert!(
        sys.contains("lock_region_errno"),
        "vault-sys must expose errno for C12 warnings"
    );
}

#[test]
fn research_and_patterns_exist() {
    let research = read_repo_file("research/mlock_docker_research.md");
    assert!(research.contains("EPERM") && research.contains("host-native"));
    let patterns = std::fs::read_to_string(
        repo_root().join("../internal/patterns/vault/mlock_degradation_patterns.yaml"),
    )
    .unwrap_or_else(|e| panic!("read mlock_degradation_patterns.yaml: {e}"));
    assert!(patterns.contains("MLOCK-04"));
}
