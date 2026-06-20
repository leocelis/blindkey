//! Policy tests for constraints C23 (zero network) and C24 (OSS license / supply chain).

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const NETWORK_CRATE_DENY: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "surf",
    "isahc",
    "attohttpc",
    "opentelemetry",
    "sentry",
    "posthog",
    "amplitude",
];

/// C23 — no telemetry / HTTP client deps in user-facing crates.
#[test]
fn c23_no_network_dependencies_in_shipped_crates() {
    for rel in [
        "crates/vault-cli/Cargo.toml",
        "crates/vault-core/Cargo.toml",
        "crates/vault-gui/Cargo.toml",
        "crates/vault-tui/Cargo.toml",
    ] {
        let text = std::fs::read_to_string(repo_root().join(rel)).unwrap();
        for banned in NETWORK_CRATE_DENY {
            assert!(
                !text.contains(&format!("{banned} =")),
                "{rel} must not depend on {banned} (C23)"
            );
            assert!(
                !text.contains(&format!("{banned}.workspace")),
                "{rel} must not depend on {banned} (C23)"
            );
        }
    }

    let main_rs = std::fs::read_to_string(repo_root().join("crates/vault-cli/src/main.rs")).unwrap();
    for needle in ["reqwest::", "hyper::", "TcpStream::connect", "ureq::"] {
        assert!(
            !main_rs.contains(needle),
            "vault CLI must not open network sockets ({needle})"
        );
    }
}

/// C24 — dual license, MSRV, cargo-deny policy.
#[test]
fn c24_open_source_license_and_supply_chain_policy() {
    let root = repo_root();
    assert!(root.join("LICENSE-MIT").exists());
    assert!(root.join("LICENSE-APACHE").exists());
    assert!(root.join("LICENSE").exists());

    let workspace = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(
        workspace.contains("license = \"MIT OR Apache-2.0\""),
        "workspace license must be MIT OR Apache-2.0"
    );
    assert!(
        workspace.contains("rust-version = \"1.96\""),
        "MSRV must be documented in workspace Cargo.toml"
    );

    let deny = std::fs::read_to_string(root.join("deny.toml")).unwrap();
    for lic in ["MIT", "Apache-2.0", "ISC", "BSD-2-Clause", "BSD-3-Clause"] {
        assert!(deny.contains(lic), "deny.toml must allow {lic}");
    }
    assert!(
        root.join(".github/workflows/audit.yml").exists(),
        "CI must run cargo-deny / cargo-audit (C24)"
    );
}

#[test]
fn c57_cli_honors_vault_vault_path_env() {
    let src = std::fs::read_to_string(
        repo_root().join("crates/vault-cli/src/commands/mod.rs"),
    )
    .unwrap();
    assert!(src.contains("VAULT_VAULT_PATH"));
}

#[test]
fn c31_unlock_secret_channels_wired() {
    let main_rs = std::fs::read_to_string(repo_root().join("crates/vault-cli/src/main.rs")).unwrap();
    let unlock = std::fs::read_to_string(
        repo_root().join("crates/vault-cli/src/unlock_secret.rs"),
    )
    .unwrap();
    assert!(main_rs.contains("password_fd"));
    assert!(main_rs.contains("password_stdin"));
    assert!(unlock.contains("VAULT_PASSWORD_FILE"));
    assert!(unlock.contains("0600"));
}
