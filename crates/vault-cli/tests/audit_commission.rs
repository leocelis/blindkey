//! Third-party audit commission pack regression tests .
//!

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn audit_commission_doc_has_rfp_sections() {
    let doc = read_repo_file("docs/AUDIT_COMMISSION.md");
    for needle in [
        "Scope statement",
        "In scope",
        "Out of scope",
        "Commissioning checklist",
        "Expected deliverables",
    ] {
        assert!(
            doc.contains(needle),
            "AUDIT_COMMISSION.md missing: {needle}"
        );
    }
}

#[test]
fn third_party_audit_links_commission_pack() {
    let doc = read_repo_file("docs/THIRD_PARTY_AUDIT.md");
    assert!(
        doc.contains("AUDIT_COMMISSION.md"),
        "THIRD_PARTY_AUDIT must link to commission pack"
    );
}

#[test]
fn audit_intake_checklist_script_exists() {
    let script = repo_root().join("scripts/audit-intake-checklist.sh");
    assert!(script.is_file(), "audit-intake-checklist.sh must exist");
}

#[test]
fn audit_intake_checklist_quick_passes() {
    let script = repo_root().join("scripts/audit-intake-checklist.sh");
    let out = Command::new("sh")
        .arg(script)
        .current_dir(repo_root())
        .output()
        .expect("run audit-intake-checklist.sh");
    assert!(
        out.status.success(),
        "intake checklist failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
