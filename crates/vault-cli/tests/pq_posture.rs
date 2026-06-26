//! Post-quantum posture doc regression (gap E1, security-gap review P2).
//!
//! Patterns: `internal/patterns/vault/pq_posture_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn pq_guide_is_canonical_and_honest() {
    let guide = read_repo_file("docs/guides/post-quantum-posture.md");
    assert!(
        guide.contains("Grover"),
        "guide must explain Grover impact on symmetric keys"
    );
    assert!(
        guide.contains("store-now-decrypt-later") || guide.contains("SNDL"),
        "guide must name SNDL for optional asymmetric stanzas"
    );
    assert!(
        guide.contains("format_version"),
        "guide must reference format_version agility"
    );
    assert!(
        guide.contains("ML-KEM") || guide.contains("hybrid"),
        "guide must reserve hybrid-PQ for future format"
    );
    let lower = guide.to_lowercase();
    assert!(
        !lower.contains("is quantum-safe")
            && !lower.contains("pq-certified")
            && !lower.contains("claims nist pq certification"),
        "guide must not overclaim PQ certification"
    );
}

#[test]
fn crypto_md_links_pq_guide_and_agility() {
    let crypto = read_repo_file("docs/CRYPTO.md");
    assert!(
        crypto.contains("guides/post-quantum-posture.md"),
        "CRYPTO.md must link canonical PQ guide"
    );
    assert!(
        crypto.contains("format_version") && crypto.contains("ADR-0005"),
        "CRYPTO.md must document agility + v2 reservation"
    );
}

#[test]
fn file_format_documents_crypto_agility() {
    let fmt = read_repo_file("docs/FILE_FORMAT.md");
    assert!(
        fmt.contains("Crypto agility") || fmt.contains("post-quantum evolution"),
        "FILE_FORMAT must have agility section"
    );
    assert!(
        fmt.contains("kdf_algorithm") && fmt.contains("format_version"),
        "FILE_FORMAT agility must name header fields"
    );
    assert!(
        fmt.contains("post-quantum-posture.md"),
        "FILE_FORMAT must cross-link PQ guide"
    );
}

#[test]
fn threat_model_cross_links_pq_residual() {
    let tm = read_repo_file("docs/THREAT_MODEL.md");
    assert!(
        tm.contains("post-quantum-posture.md"),
        "THREAT_MODEL must link PQ guide"
    );
    assert!(
        tm.contains("store-now-decrypt-later") || tm.contains("CRQC"),
        "THREAT_MODEL must describe PQ residual for hardware stanzas"
    );
}

#[test]
fn research_and_patterns_exist() {
    let research = read_repo_file("research/pq_posture_research.md");
    assert!(research.contains("gap E1"));
    let patterns = std::fs::read_to_string(
        repo_root().join("../internal/patterns/vault/pq_posture_patterns.yaml"),
    )
    .unwrap_or_else(|e| panic!("read pq_posture_patterns.yaml: {e}"));
    assert!(patterns.contains("post-quantum-posture.md"));
}

#[test]
fn security_gaps_marks_e1_addressed() {
    let gaps = read_repo_file("research/security_coverage_gaps.md");
    assert!(
        gaps.contains("E1") && gaps.contains("ADDRESSED"),
        "security_coverage_gaps must mark E1 addressed"
    );
}
