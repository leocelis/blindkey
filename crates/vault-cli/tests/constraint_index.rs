//! Constraint index sanity checks (IVD Rule 3).
//!
//! See [`docs/CONSTRAINT_INDEX.md`](../../docs/CONSTRAINT_INDEX.md) for the C1–C60 map.

/// CP-7 sweep status per constraint (2026-06-25).
const CP7_SWEEP: &[(&str, &str)] = &[
    ("C1", "PASS"),
    ("C2", "PASS"),
    ("C3", "PASS"),
    ("C4", "PASS"),
    ("C5", "PASS"),
    ("C6", "PASS"),
    ("C7", "PASS"),
    ("C8", "PASS"),
    ("C9", "PASS"),
    ("C10", "PASS"),
    ("C11", "PASS"),
    ("C12", "PASS"),
    ("C13", "PASS"),
    ("C14", "PASS"),
    ("C15", "PASS"),
    ("C16", "PASS"),
    ("C17", "PASS"),
    ("C18", "PASS"),
    ("C19", "PASS"),
    ("C20", "PASS"),
    ("C21", "PASS"),
    ("C22", "PASS"),
    ("C23", "PASS"),
    ("C24", "PASS"),
    ("C25", "PASS"),
    ("C26", "PASS"),
    ("C27", "PASS"),
    ("C28", "PASS"),
    ("C29", "PASS"),
    ("C30", "PASS"),
    ("C31", "PASS"),
    ("C32", "PASS"),
    ("C33", "PASS"),
    ("C34", "PASS"),
    ("C35", "PASS"),
    ("C36", "PASS"),
    ("C37", "PASS"),
    ("C38", "PASS"),
    ("C39", "PASS"),
    ("C40", "PASS"),
    ("C41", "PASS"),
    ("C42", "PASS"),
    ("C43", "PASS"),
    ("C44", "PASS"),
    ("C45", "PASS"),
    ("C46", "PASS"),
    ("C47", "PASS"),
    ("C48", "PASS"),
    ("C49", "PASS"),
    ("C50", "PASS"),
    ("C51", "PASS"),
    ("C52", "PASS"),
    ("C53", "PASS"),
    ("C54", "PASS"),
    ("C55", "PASS"),
    ("C56", "PASS"),
    ("C57", "PASS"),
    ("C58", "PASS"),
    ("C59", "PASS"),
    ("C60", "PASS"),
];

#[test]
fn constraint_index_documentation_exists() {
    let index =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CONSTRAINT_INDEX.md");
    let text = std::fs::read_to_string(&index).expect("read docs/CONSTRAINT_INDEX.md");
    assert!(text.contains("v1.7.0"));
    assert!(text.contains("C60"));
    assert!(text.contains("CP-7 IVD Rule 2 sweep"));
}

#[test]
fn cp7_sweep_lists_all_sixty_constraints() {
    assert_eq!(CP7_SWEEP.len(), 60);

    let index =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CONSTRAINT_INDEX.md");
    let text = std::fs::read_to_string(&index).expect("read docs/CONSTRAINT_INDEX.md");

    let pass = CP7_SWEEP.iter().filter(|(_, s)| *s == "PASS").count();
    let needs_review = CP7_SWEEP
        .iter()
        .filter(|(_, s)| *s == "NEEDS_REVIEW")
        .count();
    assert_eq!(pass, 60);
    assert_eq!(needs_review, 0);

    for (id, status) in CP7_SWEEP {
        let needle = format!("| {id} |");
        let row_start = text
            .find(&needle)
            .unwrap_or_else(|| panic!("CONSTRAINT_INDEX.md missing sweep row for {id}"));
        let row_end = text[row_start..]
            .find('\n')
            .map(|i| row_start + i)
            .unwrap_or(text.len());
        let row = &text[row_start..row_end];
        assert!(
            row.contains(&format!("| {status} |")),
            "row for {id} should contain status {status}: {row}"
        );
    }
}

#[test]
fn distributed_test_suites_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for rel in [
        "crates/vault-cli/tests/cli.rs",
        "crates/vault-cli/tests/constraint_policy.rs",
        "crates/vault-cli/src/terminal.rs",
        "crates/vault-cli/src/clipboard.rs",
        "crates/vault-clip/src/lib.rs",
        "crates/vault-core/tests/robustness.rs",
        "crates/vault-core/tests/constraint_gaps.rs",
        "crates/vault-hardware/tests/constraint_hardware.rs",
        "crates/vault-gui/tests/uc20_constraints.rs",
        "crates/vault-gui/tests/uc21_constraints.rs",
        "crates/vault-gui/tests/uc22_constraints.rs",
        "vault_intent.yaml",
        "docs/CONSTRAINT_INDEX.md",
    ] {
        assert!(root.join(rel).exists(), "missing {rel}");
    }
}
