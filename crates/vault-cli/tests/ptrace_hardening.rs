//! ptrace / live-memory hardening — doc + startup regression (security-gap review P2).
//!
//! Patterns: `internal/patterns/vault/ptrace_hardening_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn vault_sys_documents_ptrace_and_coredump_filter() {
    let lib = read_repo_file("crates/vault-sys/src/lib.rs");
    for needle in [
        "PR_SET_DUMPABLE",
        "coredump_filter",
        "ptrace",
    ] {
        assert!(lib.contains(needle), "vault-sys missing: {needle}");
    }
}

#[test]
fn mains_call_harden_process_before_secrets() {
    for rel in [
        "crates/vault-cli/src/main.rs",
        "crates/vault-tui/src/main.rs",
        "crates/vault-gui/src/main.rs",
    ] {
        let main_src = read_repo_file(rel);
        assert!(
            main_src.contains("harden_process()"),
            "{rel} must call harden_process at startup"
        );
    }
}

#[test]
fn install_documents_ptrace_scope_hardening() {
    let install = read_repo_file("docs/INSTALL.md");
    for needle in [
        "ptrace_scope",
        "PR_SET_DUMPABLE",
        "non-dumpable",
    ] {
        assert!(install.contains(needle), "INSTALL.md missing: {needle}");
    }
}

#[test]
fn ptrace_hardening_research_exists() {
    let research = read_repo_file("research/ptrace_hardening_research.md");
    for needle in ["PR_SET_DUMPABLE", "coredump_filter", "ptrace_scope", "gap B3"] {
        assert!(research.contains(needle), "research missing: {needle}");
    }
}

#[test]
fn threat_model_notes_linux_anti_ptrace() {
    let tm = read_repo_file("docs/THREAT_MODEL.md");
    assert!(
        tm.contains("anti-ptrace (Linux)"),
        "THREAT_MODEL must note Linux anti-ptrace coverage"
    );
}
