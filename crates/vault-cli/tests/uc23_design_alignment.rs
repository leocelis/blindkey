//! UC-23 sealed-file-storage design package alignment (Gate-0, S-22).
//!
//! Regression locks the design artifacts together before Phase A implementation:
//! intent v1.8.0 (C61–C66, SC9) ↔ spec ↔ PRD ↔ ROADMAP ↔ research ↔ CONSTRAINT_INDEX.
//! Patterns source: `.sdlc/features/sealed-file-storage/patterns.yaml` (private);
//! public spec §3.4 + patterns P1–P13 are the implementer-facing contract.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

const FORWARD: &[&str] = &["C61", "C62", "C63", "C64", "C65", "C66"];

/// Key design decisions from patterns.yaml P1–P13 distilled into public-doc needles.
const PATTERN_NEEDLES: &[(&str, &[&str])] = &[
    (
        "P1 sealed-archive only",
        &["vault seal", "Non-goals", "FUSE"],
    ),
    (
        "P2 streaming bounded memory",
        &["Streaming", "bounded memory", "C63", "400 MiB/s"],
    ),
    (
        "P3 zero plaintext metadata",
        &["C62", "inside the AEAD", "7-Zip"],
    ),
    ("P4 Padmé default-on", &["C66", "default-on", "--no-pad"]),
    (
        "P5 no deterministic mode",
        &["deterministic-encryption", "dedup"],
    ),
    (
        "P6 fail-closed extraction",
        &["C64", "fail-closed", ".vltf-partial"],
    ),
    ("P7 path traversal safe", &["C65", "traversal", "zip-slip"]),
    ("P8 fuzz target", &["file_archive_parse", "C30"]),
    (
        "P9 one-verb happy paths",
        &["vault seal", "vault open", "vault peek"],
    ),
    ("P10 stanza parity", &["keyfile", "YubiKey", "UC-09"]),
    ("P11 model-blind files", &["C27", "--stdout"]),
    ("P12 throughput budget", &["400 MiB/s", "Argon2id"]),
    (
        "P13 GUI worker thread",
        &["worker thread", "request_repaint", "C52", "C64"],
    ),
];

#[test]
fn design_package_files_exist() {
    for rel in [
        "vault_intent.yaml",
        "docs/specs/UC-23-sealed-file-storage.md",
        "research/encrypted_cloud_storage_research.md",
        "docs/CONSTRAINT_INDEX.md",
        "docs/PRD.md",
        "ROADMAP.md",
        "docs/specs/README.md",
    ] {
        assert!(
            repo_root().join(rel).exists(),
            "missing design artifact: {rel}"
        );
    }
}

#[test]
fn intent_v180_forward_constraints_and_sc9() {
    let intent = read_repo_file("vault_intent.yaml");
    assert!(
        intent.contains("version: \"1.8.0\""),
        "intent meta.version must be 1.8.0"
    );
    assert!(
        intent.contains("constraint_count: 66"),
        "intent constraint_count must be 66"
    );
    assert!(intent.contains("G16:"), "intent must define group G16");
    for id in FORWARD {
        assert!(
            intent.contains(&format!("- id: {id}")),
            "intent missing forward constraint {id}"
        );
        assert!(
            intent.contains("group: G16"),
            "constraint {id} should be in G16 (checked via group marker presence)"
        );
    }
    assert!(
        intent.contains("- id: SC9"),
        "intent must document SC9 (--stdout vs C64 fail-closed)"
    );
    assert!(
        intent.contains("joint_satisfaction_test:"),
        "intent must name joint_satisfaction_test for C61–C66 (IVD 3+ constraints)"
    );
    assert!(
        intent.contains("SEGMENT 12"),
        "intent implementation_notes must include SEGMENT 12 (G16 / UC-23)"
    );
}

#[test]
fn uc23_spec_matches_intent_and_patterns() {
    let spec = read_repo_file("docs/specs/UC-23-sealed-file-storage.md");
    assert!(spec.contains("Accepted v1.0"));
    assert!(spec.contains("intent v1.8.0"));
    assert!(spec.contains("VLTF1"));
    assert!(spec.contains("ADR-0005"));
    assert!(spec.contains("Joint satisfaction"));
    assert!(spec.contains("Desktop app (`vault-gui`) design"));
    assert!(spec.contains("worker thread"));
    for id in FORWARD {
        assert!(spec.contains(id), "UC-23 spec must map constraint {id}");
    }
    for (label, needles) in PATTERN_NEEDLES {
        for needle in *needles {
            assert!(
                spec.contains(needle),
                "UC-23 spec missing pattern alignment {label}: {needle}"
            );
        }
    }
}

#[test]
fn constraint_index_lists_uc23_rows_as_pass() {
    let index = read_repo_file("docs/CONSTRAINT_INDEX.md");
    assert!(index.contains("v1.8.0"));
    assert!(index.contains("66 constraints"));
    assert!(
        index.contains("66 PASS"),
        "CONSTRAINT_INDEX must report 66/66 PASS after UC-23"
    );
    for id in FORWARD {
        assert!(index.contains(id), "CONSTRAINT_INDEX missing {id}");
        let needle = format!("| {id} |");
        let row_start = index
            .find(&needle)
            .unwrap_or_else(|| panic!("CONSTRAINT_INDEX missing row for {id}"));
        let row_end = index[row_start..]
            .find('\n')
            .map(|i| row_start + i)
            .unwrap_or(index.len());
        let row = &index[row_start..row_end];
        assert!(
            row.contains("| PASS |"),
            "CONSTRAINT_INDEX {id} must be PASS after Phase A–C: {row}"
        );
    }
}

#[test]
fn prd_roadmap_and_specs_index_reference_uc23() {
    let prd = read_repo_file("docs/PRD.md");
    assert!(prd.contains("UC-23"));
    assert!(prd.contains("v1.8.0"));
    assert!(prd.contains("C61"));
    assert!(prd.contains("sealed-archive"));

    let roadmap = read_repo_file("ROADMAP.md");
    assert!(roadmap.contains("S-22"));
    assert!(roadmap.contains("UC-23-sealed-file-storage.md"));
    assert!(
        roadmap.contains("Shipped") || roadmap.contains("shipped"),
        "ROADMAP S-22 should mark UC-23 shipped"
    );

    let specs_readme = read_repo_file("docs/specs/README.md");
    assert!(specs_readme.contains("UC-23"));
    assert!(specs_readme.contains("C61"));
}

#[test]
fn research_survey_supports_uc23_decisions() {
    let research = read_repo_file("research/encrypted_cloud_storage_research.md");
    for needle in [
        "Cryptomator",
        "age",
        "Padmé",
        "multi-snapshot",
        "UC-07",
        "opaque blob",
        "C17",
    ] {
        assert!(
            research.contains(needle),
            "encrypted_cloud_storage_research.md missing: {needle}"
        );
    }
    let spec = read_repo_file("docs/specs/UC-23-sealed-file-storage.md");
    assert!(
        spec.contains("encrypted_cloud_storage_research.md"),
        "UC-23 spec must link the research survey"
    );
}

#[test]
fn proposed_constraint_texts_align_intent_and_spec() {
    let intent = read_repo_file("vault_intent.yaml");
    let spec = read_repo_file("docs/specs/UC-23-sealed-file-storage.md");
    let pairs: &[(&str, &str, &str)] = &[
        ("C61", "no second crypto stack", "one crypto path"),
        ("C62", "Zero plaintext metadata", "C62"),
        ("C63", "Bounded-memory streaming", "C63"),
        ("C64", "Fail-closed extraction", "C64"),
        ("C65", "Path-traversal-safe", "C65"),
        ("C66", "Size padding default-on", "C66"),
    ];
    for (id, intent_phrase, spec_phrase) in pairs {
        assert!(intent.contains(id), "intent missing constraint id {id}");
        assert!(
            intent.contains(intent_phrase),
            "intent {id} missing phrase: {intent_phrase}"
        );
        assert!(
            spec.contains(id) && spec.contains(spec_phrase),
            "spec {id} missing phrase: {spec_phrase}"
        );
    }
}
