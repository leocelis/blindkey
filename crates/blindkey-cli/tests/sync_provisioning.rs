//! Sync guide — expect-min-version + fleet provisioning doc regression .
//!

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn sync_guide_documents_expect_min_version_and_fleet() {
    let guide = read_repo_file("docs/guides/sync-to-untrusted-storage.md");
    for needle in [
        "--expect-min-version",
        "Provisioning a new machine",
        "trust-on-first-use",
        "BLINDKEY_EXPECT_MIN_VERSION",
        "exit code **2**",
        "od -An -tu8",
        ".state",
    ] {
        assert!(guide.contains(needle), "sync guide missing: {needle}");
    }
}

#[test]
fn cli_documents_global_rollback_flags() {
    let cli = read_repo_file("docs/CLI.md");
    for needle in [
        "Global flags (rollback",
        "--expect-min-version",
        "--allow-rollback",
    ] {
        assert!(cli.contains(needle), "CLI.md missing: {needle}");
    }
}

#[test]
fn enterprise_deployment_links_sync_fleet_section() {
    let ent = read_repo_file("docs/guides/enterprise-deployment.md");
    assert!(
        ent.contains("sync-to-untrusted-storage.md"),
        "enterprise-deployment must link sync guide"
    );
    assert!(
        ent.contains("BLINDKEY_EXPECT_MIN_VERSION"),
        "enterprise-deployment must mention BLINDKEY_EXPECT_MIN_VERSION"
    );
}

#[test]
fn sync_provisioning_research_exists() {
    let research = read_repo_file("research/sync_provisioning_research.md");
    assert!(
        research.contains("expect-min-version"),
        "research doc must cover expect-min-version"
    );
}
