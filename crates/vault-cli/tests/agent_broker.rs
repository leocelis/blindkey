//! Agent broker scaffold regression tests .
//!

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn agent_broker_research_and_adr_exist() {
    assert!(read_repo_file("research/agent_broker_research.md").contains("S-13"));
    assert!(read_repo_file("docs/adr/0006-agent-broker-scaffold.md").contains("vault-agent"));
}

#[test]
fn agent_broker_guide_exists() {
    let guide = read_repo_file("docs/AGENT_BROKER.md");
    assert!(guide.contains("vault agent allow"));
    assert!(guide.contains("status only"));
}

#[test]
fn cli_documents_vault_agent() {
    let cli = read_repo_file("docs/CLI.md");
    assert!(cli.contains("vault agent"));
}

#[test]
fn use_response_never_includes_password_key() {
    let json = vault_agent::UseResponse::ok().to_json_line().unwrap();
    assert!(!json.contains("password"));
}
