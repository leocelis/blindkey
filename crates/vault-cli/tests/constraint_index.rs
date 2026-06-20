//! Constraint index sanity checks (IVD Rule 3).
//!
//! See [`docs/CONSTRAINT_INDEX.md`](../../docs/CONSTRAINT_INDEX.md) for the C1–C60 map.

#[test]
fn constraint_index_documentation_exists() {
    let index = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/CONSTRAINT_INDEX.md");
    let text = std::fs::read_to_string(&index).expect("read docs/CONSTRAINT_INDEX.md");
    assert!(text.contains("v1.7.0"));
    assert!(text.contains("C60"));
}

#[test]
fn distributed_test_suites_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for rel in [
        "crates/vault-cli/tests/cli.rs",
        "crates/vault-cli/tests/constraint_policy.rs",
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
