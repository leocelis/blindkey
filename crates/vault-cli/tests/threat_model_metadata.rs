//! THREAT_MODEL sync metadata leak doc regression (security-gap review P2, C17).
//!
//! Patterns: `internal/patterns/vault/metadata_leak_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn threat_model_documents_accepted_sync_metadata() {
    let tm = read_repo_file("docs/THREAT_MODEL.md");
    for needle in [
        "Accepted residual",
        "mtime",
        "file size",
        "save frequency",
        "C17",
    ] {
        assert!(
            tm.contains(needle),
            "THREAT_MODEL must document sync metadata residual: {needle}"
        );
    }
    assert!(
        tm.contains("UC-07") || tm.contains("untrusted-storage-sync"),
        "THREAT_MODEL must cross-link UC-07"
    );
    assert!(
        tm.contains("sync-to-untrusted-storage"),
        "THREAT_MODEL must cross-link sync user guide"
    );
}

#[test]
fn threat_model_distinguishes_protected_vs_residual() {
    let tm = read_repo_file("docs/THREAT_MODEL.md");
    assert!(
        tm.contains("does *not* leak") || tm.contains("does not leak"),
        "THREAT_MODEL must state what remains protected"
    );
    assert!(
        tm.contains("Padmé") || tm.contains("pad on") || tm.contains("padding"),
        "THREAT_MODEL must mention optional size-padding mitigation"
    );
}

#[test]
fn security_md_lists_sync_metadata_out_of_scope() {
    let sec = read_repo_file("SECURITY.md");
    assert!(
        sec.contains("sync/storage metadata") || sec.contains("blob size"),
        "SECURITY.md must list sync metadata as documented residual"
    );
    assert!(sec.contains("THREAT_MODEL"));
}

#[test]
fn research_and_patterns_exist() {
    let research = read_repo_file("research/metadata_leak_research.md");
    assert!(research.contains("C17") && research.contains("mtime"));
    let patterns = std::fs::read_to_string(
        repo_root().join("../internal/patterns/vault/metadata_leak_patterns.yaml"),
    )
    .unwrap_or_else(|e| panic!("read metadata_leak_patterns.yaml: {e}"));
    assert!(patterns.contains("META-01"));
}

#[test]
fn sync_guide_cross_links_threat_model() {
    let guide = read_repo_file("docs/guides/sync-to-untrusted-storage.md");
    assert!(
        guide.contains("THREAT_MODEL") && guide.contains("metadata"),
        "sync guide must cross-link THREAT_MODEL metadata section"
    );
}
