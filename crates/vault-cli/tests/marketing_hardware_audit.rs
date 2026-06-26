//! Marketing hardware honesty regression (security-gap review P2).
//!
//! Patterns: `internal/patterns/vault/marketing_hardware_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn hardware_status_guide_is_canonical() {
    let guide = read_repo_file("docs/guides/hardware-factor-status.md");
    for needle in ["YubiKey", "keyfile", "mock", "fido2-token", "tpm2-tools"] {
        assert!(
            guide.contains(needle),
            "hardware-factor-status.md missing: {needle}"
        );
    }
    assert!(
        guide.contains("not") && guide.contains("third-party audit"),
        "guide must deny independent audit marketing"
    );
}

#[test]
fn readme_links_hardware_status_and_qualifies_unlock() {
    let readme = read_repo_file("README.md");
    assert!(readme.contains("hardware-factor-status"));
    assert!(
        readme.contains("deferred") || readme.contains("FIDO2"),
        "README unlock row must qualify deferred hardware"
    );
    let lower = readme.to_lowercase();
    assert!(
        !lower.contains("independently audited") || lower.contains("not"),
        "README must not claim independent audit without negation"
    );
    assert!(
        !lower.contains("audit-backed"),
        "README must not claim audit-backed"
    );
}

#[test]
fn prd_uc9_has_v1_status_block() {
    let prd = read_repo_file("docs/PRD.md");
    let uc9 = prd
        .split("### UC-9")
        .nth(1)
        .and_then(|s| s.split("### UC-10").next())
        .expect("UC-9 section");
    assert!(
        uc9.contains("Status (v1.0.0)") || uc9.contains("Status (v1"),
        "PRD UC-9 must have v1 Status block"
    );
    assert!(
        uc9.contains("mock") || uc9.contains("stub"),
        "PRD UC-9 must mention mock/stub for deferred factors"
    );
    assert!(uc9.contains("hardware-factor-status"));
}

#[test]
fn architecture_notes_mock_hardware() {
    let arch = read_repo_file("docs/ARCHITECTURE.md");
    assert!(
        arch.contains("mock") || arch.contains("stub"),
        "ARCHITECTURE must note mock/stub hardware"
    );
    assert!(arch.contains("YubiKey") || arch.contains("keyfile"));
}

#[test]
fn enterprise_posture_denies_deferred_hardware() {
    let ep = read_repo_file("docs/ENTERPRISE_POSTURE.md");
    assert!(
        ep.contains("FIDO2") || ep.contains("TPM"),
        "ENTERPRISE_POSTURE must list deferred hardware in non-claims"
    );
    assert!(ep.contains("hardware-factor-status"));
}

#[test]
fn research_doc_exists() {
    let research = read_repo_file("research/marketing_hardware_audit_research.md");
    assert!(research.contains("S-8a") && research.contains("mock"));
}
