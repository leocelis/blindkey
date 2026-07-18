//! Constraint index sanity checks (IVD Rule 3).
//!
//! See [`docs/CONSTRAINT_INDEX.md`](../../docs/CONSTRAINT_INDEX.md) for the C1–C66 map.

/// CP-7 sweep status per constraint (2026-06-25) — implemented set only.
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
    ("C61", "PASS"),
    ("C62", "PASS"),
    ("C63", "PASS"),
    ("C64", "PASS"),
    ("C65", "PASS"),
    ("C66", "PASS"),
];

const UC23_IDS: &[&str] = &["C61", "C62", "C63", "C64", "C65", "C66"];

#[test]
fn constraint_index_documentation_exists() {
    let index =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CONSTRAINT_INDEX.md");
    let text = std::fs::read_to_string(&index).expect("read docs/CONSTRAINT_INDEX.md");
    assert!(text.contains("v1.8.0"));
    assert!(text.contains("66 constraints"));
    assert!(text.contains("C60"));
    assert!(text.contains("C66"));
    assert!(text.contains("CP-7 IVD Rule 2 sweep"));
}

#[test]
fn cp7_sweep_lists_all_sixty_six_constraints() {
    assert_eq!(CP7_SWEEP.len(), 66);

    let index =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CONSTRAINT_INDEX.md");
    let text = std::fs::read_to_string(&index).expect("read docs/CONSTRAINT_INDEX.md");

    let pass = CP7_SWEEP.iter().filter(|(_, s)| *s == "PASS").count();
    let needs_review = CP7_SWEEP
        .iter()
        .filter(|(_, s)| *s == "NEEDS_REVIEW")
        .count();
    assert_eq!(pass, 66);
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
fn uc23_constraints_listed_as_pass() {
    let index =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CONSTRAINT_INDEX.md");
    let text = std::fs::read_to_string(&index).expect("read docs/CONSTRAINT_INDEX.md");
    assert!(
        text.contains("66 PASS"),
        "CONSTRAINT_INDEX must report 66/66 PASS"
    );
    for id in UC23_IDS {
        let needle = format!("| {id} |");
        let row_start = text
            .find(&needle)
            .unwrap_or_else(|| panic!("CONSTRAINT_INDEX.md missing row for {id}"));
        let row_end = text[row_start..]
            .find('\n')
            .map(|i| row_start + i)
            .unwrap_or(text.len());
        let row = &text[row_start..row_end];
        assert!(
            row.contains("| PASS |"),
            "UC-23 {id} must be PASS after implementation: {row}"
        );
    }
}

#[test]
fn distributed_test_suites_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for rel in [
        "crates/blindkey-cli/tests/cli.rs",
        "crates/blindkey-cli/tests/constraint_policy.rs",
        "crates/blindkey-cli/src/terminal.rs",
        "crates/blindkey-cli/src/clipboard.rs",
        "crates/blindkey-clip/src/lib.rs",
        "crates/blindkey-core/tests/robustness.rs",
        "crates/blindkey-core/tests/constraint_gaps.rs",
        "crates/blindkey-core/tests/uc23_joint_satisfaction.rs",
        "crates/blindkey-core/tests/sealed_constraints.rs",
        "crates/blindkey-hardware/tests/constraint_hardware.rs",
        "crates/blindkey-gui/tests/uc20_constraints.rs",
        "crates/blindkey-gui/tests/uc21_constraints.rs",
        "crates/blindkey-gui/tests/uc22_constraints.rs",
        "crates/blindkey-cli/tests/uc23_design_alignment.rs",
        "blindkey_intent.yaml",
        "docs/CONSTRAINT_INDEX.md",
    ] {
        assert!(root.join(rel).exists(), "missing {rel}");
    }
}
