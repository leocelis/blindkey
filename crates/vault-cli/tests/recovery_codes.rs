//! Recovery codes at init — gap C3 regression (security-gap review P2).
//!
//! Patterns: `internal/patterns/vault/recovery_codes_patterns.yaml`

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
        .join(format!("vault-rec-{}-{}.vlt", std::process::id(), nanos))
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

#[test]
fn init_with_recovery_code_unlocks_via_recovery_flag() {
    let home = unique_dir("rec-home");
    let _ = std::fs::create_dir_all(&home);
    let vault = unique_vault();
    let vs = vault.as_str();
    let pw = "rec-init-pass\n";

    let mut init = vec![
        "--vault",
        vs,
        "init",
        "--allow-weak-password",
        "--with-recovery-code",
    ];
    init.extend_from_slice(&FAST_KDF);
    let (code, _, err) = run_env(&home, &init, pw);
    assert_eq!(code, Some(0), "init with recovery: {err}");

    let recovery = err
        .lines()
        .map(str::trim)
        .find(|l| l.len() >= 24 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .expect("recovery code in init stderr")
        .to_string();

    let recovery_stdin = format!("{recovery}\n");
    let (code, _, err) = run_env(&home, &["--vault", vs, "--recovery", "ls"], &recovery_stdin);
    assert_eq!(code, Some(0), "recovery unlock failed: {err}");

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn recovery_guide_and_research_exist() {
    let guide = read_repo_file("docs/guides/recovery-codes.md");
    for needle in ["--with-recovery-code", "--recovery", "NO password reset"] {
        assert!(guide.contains(needle), "guide missing: {needle}");
    }
    let research = read_repo_file("research/recovery_codes_research.md");
    assert!(research.contains("add_recovery_stanza"));
}

#[test]
fn vault_core_has_recovery_stanza_api() {
    let src = read_repo_file("crates/vault-core/src/vault.rs");
    for needle in ["add_recovery_stanza", "has_recovery_stanza"] {
        assert!(src.contains(needle), "vault.rs missing: {needle}");
    }
}

#[test]
fn init_flag_documented_in_cli_md() {
    assert!(
        read_repo_file("docs/CLI.md").contains("--with-recovery-code"),
        "CLI.md must document --with-recovery-code"
    );
}
