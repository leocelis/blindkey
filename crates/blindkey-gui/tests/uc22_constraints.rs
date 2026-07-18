//! UC-22 constraint tests (C55–C60).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_gui_config() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/gui_config.rs"))
        .expect("gui_config.rs")
}

fn read_search_tests() -> String {
    std::fs::read_to_string(repo_root().join("crates/blindkey-core/src/search.rs"))
        .expect("search.rs")
}

#[test]
fn c55_release_quality_gate_wired() {
    let script = repo_root().join("scripts/audit-readiness.sh");
    let text = std::fs::read_to_string(&script).expect("audit-readiness.sh");
    assert!(text.contains("--release latency"));
    assert!(text.contains("clippy"));
}

#[test]
fn c56_audit_readiness_doc_exists() {
    let doc = repo_root().join("docs/AUDIT_READINESS.md");
    let text = std::fs::read_to_string(&doc).expect("AUDIT_READINESS.md");
    assert!(text.contains("CP-7"));
}

#[test]
fn c57_enterprise_env_vars_wired() {
    let src = read_gui_config();
    assert!(src.contains("BLINDKEY_VAULT_PATH"));
    assert!(src.contains("BLINDKEY_CONFIG_DIR"));
    assert!(src.contains("BLINDKEY_LOCK_ON_BLUR"));
    assert!(src.contains("resolve_vault_path"));
    assert!(src.contains("apply_env_overrides"));

    let main_src =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
            .unwrap();
    assert!(main_src.contains("gui_config::resolve_vault_path"));
}

#[test]
fn c58_c38_skips_in_debug() {
    let src = read_search_tests();
    let fn_body = src
        .split("fn latency_under_budget_at_scale")
        .nth(1)
        .expect("latency_under_budget_at_scale");
    assert!(fn_body.contains("cfg!(debug_assertions)"));
}

#[test]
fn c59_five_thousand_release_bench_wired() {
    let src = read_search_tests();
    assert!(src.contains("fn latency_at_five_thousand"));
    assert!(src.contains("synthetic_corpus(5000)"));
    assert!(src.contains("< 200"));
}

#[test]
fn c60_enterprise_docs_exist() {
    let posture = repo_root().join("docs/ENTERPRISE_POSTURE.md");
    let deploy = repo_root().join("docs/guides/enterprise-deployment.md");
    let posture_text = std::fs::read_to_string(&posture).expect("ENTERPRISE_POSTURE.md");
    let deploy_text = std::fs::read_to_string(&deploy).expect("enterprise-deployment.md");
    assert!(posture_text.contains("SOC2") || posture_text.contains("non-goal"));
    assert!(deploy_text.contains("BLINDKEY_VAULT_PATH"));

    let install = std::fs::read_to_string(repo_root().join("docs/INSTALL.md")).unwrap();
    assert!(install.contains("enterprise-deployment"));
}
