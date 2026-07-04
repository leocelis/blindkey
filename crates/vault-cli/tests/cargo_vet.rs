//! cargo-vet supply-chain gate — pinned exemptions + audit-ready .
//!

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn supply_chain_config_exists_with_vet_version() {
    let config = read_repo_file("supply-chain/config.toml");
    assert!(
        config.contains("[cargo-vet]"),
        "supply-chain/config.toml must declare [cargo-vet]"
    );
    assert!(
        config.contains("version = \"0.10\""),
        "cargo-vet config version must be pinned"
    );
    assert!(
        config.contains("[[exemptions."),
        "bootstrap exemptions must be pinned in config.toml"
    );
}

#[test]
fn supply_chain_audits_and_imports_lock_exist() {
    let audits = read_repo_file("supply-chain/audits.toml");
    assert!(
        audits.contains("[audits]"),
        "supply-chain/audits.toml must declare [audits]"
    );
    let imports = read_repo_file("supply-chain/imports.lock");
    assert!(
        imports.contains("cargo-vet imports lock"),
        "supply-chain/imports.lock must exist"
    );
}

#[test]
fn audit_readiness_runs_cargo_vet() {
    let script = read_repo_file("scripts/audit-readiness.sh");
    assert!(
        script.contains("cargo vet"),
        "audit-readiness.sh must invoke cargo vet"
    );
}

#[test]
fn justfile_audit_includes_vet() {
    let just = read_repo_file("justfile");
    assert!(
        just.contains("cargo vet"),
        "justfile audit/vet targets must include cargo vet"
    );
}

#[test]
fn audit_readiness_docs_mention_vet() {
    let doc = read_repo_file("docs/AUDIT_READINESS.md");
    assert!(
        doc.contains("cargo vet"),
        "AUDIT_READINESS.md must document cargo vet in the gate"
    );
}

#[test]
fn cargo_vet_research_exists() {
    let research = read_repo_file("research/cargo_vet_research.md");
    for needle in ["cargo-vet", "supply-chain/", "audit-readiness", "gap D2"] {
        assert!(research.contains(needle), "research missing: {needle}");
    }
}
