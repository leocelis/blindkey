//! Crypto-shredding + rotate-data-key regression (security-gap review P2, gap C2).
//!
//! Patterns: `internal/patterns/vault/crypto_shred_rotation_patterns.yaml`

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn run_env(home: &Path, args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let mut argv: Vec<&str> = Vec::new();
    let has_pw_channel = args.iter().any(|a| {
        *a == "--password-stdin" || *a == "--password-fd" || a.starts_with("--password-fd=")
    });
    if !has_pw_channel && !stdin.is_empty() {
        argv.push("--password-stdin");
    }
    argv.extend_from_slice(args);
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("share"))
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vault");
    if !stdin.is_empty() {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn unique_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vault-{prefix}-{}", std::process::id()))
}

fn unique_vault() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("vault-rot-{}-{}.vlt", std::process::id(), nanos))
        .to_string_lossy()
        .into_owned()
}

const FAST_KDF: [&str; 7] = [
    "--kdf-m-cost",
    "8192",
    "--kdf-t-cost",
    "1",
    "--kdf-p-cost",
    "1",
    "--allow-weak-kdf",
];

fn sample_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../samples/keys.txt")
}

#[test]
fn rotate_data_key_cli_preserves_entries() {
    let home = unique_dir("rotate-home");
    let _ = std::fs::create_dir_all(&home);
    let vault = unique_vault();
    let vs = vault.as_str();
    let sp = sample_path().to_string_lossy().into_owned();
    let pw = "rotate-pass\n";

    let mut init = vec!["--vault", vs, "init", "--allow-weak-password"];
    init.extend_from_slice(&FAST_KDF);
    assert_eq!(run_env(&home, &init, pw).0, Some(0), "init");

    assert_eq!(
        run_env(
            &home,
            &[
                "--vault",
                vs,
                "import",
                "--format",
                "raw",
                sp.as_str(),
                "--yes",
            ],
            pw
        )
        .0,
        Some(0),
        "import"
    );

    let bytes_before = std::fs::read(&vault).unwrap();
    assert_eq!(
        run_env(&home, &["--vault", vs, "rotate-data-key"], pw).0,
        Some(0),
        "rotate-data-key"
    );
    let bytes_after = std::fs::read(&vault).unwrap();
    assert_ne!(
        bytes_before, bytes_after,
        "rotation must rewrite the vault file"
    );

    let (code, out, err) = run_env(&home, &["--vault", vs, "get", "github", "--stdout"], pw);
    assert_eq!(code, Some(0), "get after rotate: {err}");
    assert!(
        !out.is_empty() || !err.is_empty(),
        "github entry must survive rotation"
    );

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn deletion_guide_documents_crypto_shred_and_rotation() {
    let guide = read_repo_file("docs/guides/deletion-and-rotation.md");
    for needle in [
        "crypto-shredded",
        "rotate-data-key",
        "sync history",
        "do **not** promise",
    ] {
        assert!(guide.contains(needle), "guide missing: {needle}");
    }
}

#[test]
fn vault_core_exposes_rotate_data_key() {
    let lib = read_repo_file("crates/vault-core/src/vault.rs");
    assert!(
        lib.contains("pub fn rotate_data_key"),
        "Vault must expose rotate_data_key"
    );
}

#[test]
fn cli_lists_rotate_data_key_command() {
    let cli = read_repo_file("docs/CLI.md");
    assert!(
        cli.contains("rotate-data-key"),
        "CLI.md must document rotate-data-key"
    );
}

#[test]
fn crypto_shred_research_exists() {
    let research = read_repo_file("research/crypto_shred_rotation_research.md");
    assert!(
        research.contains("rotate-data-key"),
        "research must cover rotate-data-key"
    );
}

#[test]
fn stanzas_remove_mentions_rotate_hint() {
    let cmd = read_repo_file("crates/vault-cli/src/commands/mod.rs");
    assert!(
        cmd.contains("rotate-data-key"),
        "stanzas remove must hint rotate-data-key"
    );
}
