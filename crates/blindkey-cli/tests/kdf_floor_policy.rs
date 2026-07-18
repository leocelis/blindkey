//! KDF floor policy regression tests.
//!

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn run_env(home: &Path, args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let mut argv: Vec<&str> = Vec::new();
    let has_pw_channel = args.iter().any(|a| {
        *a == "--password-stdin" || *a == "--password-fd" || a.starts_with("--password-fd=")
    });
    if !has_pw_channel && !stdin.is_empty() {
        argv.push("--password-stdin");
    }
    argv.extend_from_slice(args);
    let mut child = Command::new(env!("CARGO_BIN_EXE_blindkey"))
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

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vault-{prefix}-{}", std::process::id()))
}

fn unique_vault() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("vault-kdf-{}-{}.vlt", std::process::id(), nanos))
        .to_string_lossy()
        .into_owned()
}

const WEAK_KDF: [&str; 6] = [
    "--kdf-m-cost",
    "8192",
    "--kdf-t-cost",
    "1",
    "--kdf-p-cost",
    "1",
];

#[test]
fn init_rejects_below_floor_without_escape_hatch() {
    let home = unique_dir("kdf-reject-home");
    let _ = std::fs::create_dir_all(&home);
    let vs = unique_vault();
    let pw = "floor-test-pass\n";
    let mut args = vec!["--vault", &vs, "init", "--allow-weak-password"];
    args.extend_from_slice(&WEAK_KDF);
    let (code, _, err) = run_env(&home, &args, pw);
    assert_ne!(code, Some(0), "weak init should fail: {err}");
    assert!(
        err.contains("below the minimum floor") || err.contains("KdfBelowFloor"),
        "expected floor error: {err}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn init_allows_below_floor_with_allow_weak_kdf() {
    let home = unique_dir("kdf-allow-home");
    let _ = std::fs::create_dir_all(&home);
    let vs = unique_vault();
    let pw = "floor-test-pass\n";
    let mut args = vec![
        "--vault",
        &vs,
        "init",
        "--allow-weak-password",
        "--allow-weak-kdf",
    ];
    args.extend_from_slice(&WEAK_KDF);
    let (code, _, err) = run_env(&home, &args, pw);
    assert_eq!(
        code,
        Some(0),
        "weak init with escape hatch should succeed: {err}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn open_weak_vault_warns_but_succeeds() {
    let home = unique_dir("kdf-open-home");
    let _ = std::fs::create_dir_all(&home);
    let vs = unique_vault();
    let pw = "floor-test-pass\n";
    let mut init = vec![
        "--vault",
        &vs,
        "init",
        "--allow-weak-password",
        "--allow-weak-kdf",
    ];
    init.extend_from_slice(&WEAK_KDF);
    assert_eq!(run_env(&home, &init, pw).0, Some(0), "init");
    let (code, _, err) = run_env(&home, &["--vault", &vs, "ls"], pw);
    assert_eq!(code, Some(0), "open weak vault should succeed: {err}");
    assert!(
        err.contains("below the recommended floor") || err.contains("upgrade-kdf"),
        "expected floor warning on open: {err}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn upgrade_kdf_rejects_below_floor_target() {
    let home = unique_dir("kdf-up-home");
    let _ = std::fs::create_dir_all(&home);
    let vs = unique_vault();
    let pw = "floor-test-pass\n";
    let mut init = vec![
        "--vault",
        &vs,
        "init",
        "--allow-weak-password",
        "--allow-weak-kdf",
    ];
    init.extend_from_slice(&WEAK_KDF);
    assert_eq!(run_env(&home, &init, pw).0, Some(0), "init");
    let mut up = vec!["--vault", &vs, "upgrade-kdf"];
    up.extend_from_slice(&WEAK_KDF);
    let (code, _, err) = run_env(&home, &up, pw);
    assert_ne!(code, Some(0), "upgrade to weak params should fail: {err}");
    assert!(
        err.contains("below the minimum floor") || err.contains("KdfBelowFloor"),
        "expected floor error: {err}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
