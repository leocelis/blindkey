//! End-to-end CLI integration test: drives the built `vault` binary against the sample `keys.txt`
//! over piped stdin (the non-interactive password path), and asserts the encrypted file leaks
//! nothing. Covers init → import → ls → get → wrong-password → rm → gen, plus the C18 on-disk check.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// A per-process temp dir used as `HOME`/`XDG_DATA_HOME` for the child, so the C16 rollback anchor
/// lands in an isolated location and never touches the developer's real data dir.
fn shared_home() -> PathBuf {
    let p = std::env::temp_dir().join(format!("vault-it-home-{}", std::process::id()));
    std::fs::create_dir_all(&p).ok();
    p
}

/// Run the `vault` binary under an isolated `home`, feeding `stdin`. Returns (exit code, out, err).
fn run_env(home: &Path, args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("share"))
        .env("LOCALAPPDATA", home.join("local")) // Windows anchor dir → keep it sandboxed too
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vault");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run with the shared isolated home; returns (success, stdout, stderr).
fn run(args: &[&str], stdin: &str) -> (bool, String, String) {
    let (code, out, err) = run_env(&shared_home(), args, stdin);
    (code == Some(0), out, err)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn sample_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../samples/keys.txt")
}

fn unique_vault() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vault-it-{}-{}.vlt", std::process::id(), nanos))
}

#[test]
fn cli_end_to_end() {
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    let pw = "integration-pass-1\n";

    // init with fast (below-recommended) KDF params so the test isn't dominated by Argon2id
    let (ok, _, err) = run(
        &[
            "--vault",
            vs,
            "init",
            "--kdf-m-cost",
            "8192",
            "--kdf-t-cost",
            "1",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert!(ok, "init failed: {err}");

    // import the messy sample
    let (ok, _, err) = run(&["--vault", vs, "import", "--format", "raw", sp], pw);
    assert!(ok, "import failed: {err}");
    assert!(err.contains("Imported"), "stderr: {err}");

    // ls finds the imported entries
    let (ok, out, _) = run(&["--vault", vs, "ls"], pw);
    assert!(ok);
    assert!(out.contains("github"), "ls: {out}");
    assert!(out.contains("openai"), "ls: {out}");

    // ls --search narrows
    let (_, out, _) = run(&["--vault", vs, "ls", "--search", "github"], pw);
    assert_eq!(out.trim(), "github");

    // get --stdout returns the real secret
    let (ok, out, _) = run(&["--vault", vs, "get", "github", "--stdout"], pw);
    assert!(ok);
    assert!(out.contains("ghp_FAKE0mZ9"), "get: {out}");

    // wrong password → ambiguous error, failure exit
    let (ok, _, err) = run(&["--vault", vs, "ls"], "wrong-pw\n");
    assert!(!ok);
    assert!(err.contains("tampered or wrong password"), "stderr: {err}");

    // rm deletes
    let (ok, _, err) = run(&["--vault", vs, "rm", "github"], pw);
    assert!(ok, "rm failed: {err}");
    let (_, out, _) = run(&["--vault", vs, "ls"], pw);
    assert!(!out.contains("github"), "github should be gone: {out}");

    // C18: the encrypted file leaks neither secrets nor titles
    let bytes = std::fs::read(&vault).unwrap();
    for needle in [
        &b"ghp_FAKE"[..],
        &b"sk-proj-FAKE"[..],
        &b"AKIAEXAMPLE"[..],
        &b"openai"[..],
    ] {
        assert!(!contains(&bytes, needle), "leak: {:?}", needle);
    }

    // gen needs no vault and produces a password of the requested length
    let (ok, out, err) = run(&["gen", "--length", "24", "--charset", "alnum"], "");
    assert!(ok);
    assert_eq!(out.trim().len(), 24);
    assert!(err.contains("bits of entropy"));

    let _ = std::fs::remove_file(&vault);
}

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("vault-it-{tag}-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&p).ok();
    p
}

/// 2FA: `vault otp <name>` wires up and reports a missing secret clearly. (Code generation itself
/// is proven by the RFC 6238 vectors in `vault-core::totp`.)
#[test]
fn cli_otp_requires_a_2fa_secret() {
    let home = unique_dir("otp-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "otp-pass\n";
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
    ];

    let mut init_args = vec!["--vault", vs, "init"];
    init_args.extend_from_slice(&fast);
    assert_eq!(run_env(&home, &init_args, pw).0, Some(0), "init");

    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    assert_eq!(
        run_env(&home, &["--vault", vs, "import", "--format", "raw", sp], pw).0,
        Some(0),
        "import"
    );

    let (code, _, err) = run_env(&home, &["--vault", vs, "otp", "github", "--stdout"], pw);
    assert!(code != Some(0), "otp without a 2FA secret should fail");
    assert!(err.contains("no 2FA secret"), "stderr: {err}");

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

/// Root-of-trust hardening: `vault init` warns on a weak master password; `--allow-weak-password`
/// silences it. (Non-interactive init proceeds either way — the prompt is TTY-only.)
#[test]
fn cli_init_warns_on_weak_master_password() {
    let home = unique_dir("weak-home");
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
    ];

    let v1 = unique_vault();
    let mut a1 = vec!["--vault", v1.to_str().unwrap(), "init"];
    a1.extend_from_slice(&fast);
    let (code, _, err) = run_env(&home, &a1, "abc\n");
    assert_eq!(
        code,
        Some(0),
        "weak init should proceed non-interactively: {err}"
    );
    assert!(err.to_lowercase().contains("weak"), "should warn: {err}");

    let v2 = unique_vault();
    let mut a2 = vec!["--vault", v2.to_str().unwrap(), "init"];
    a2.extend_from_slice(&fast);
    a2.push("--allow-weak-password");
    let (code, _, err) = run_env(&home, &a2, "abc\n");
    assert_eq!(code, Some(0), "init: {err}");
    assert!(
        !err.to_lowercase().contains("weak"),
        "--allow-weak-password should silence the warning: {err}"
    );

    let _ = std::fs::remove_file(&v1);
    let _ = std::fs::remove_file(&v2);
    let _ = std::fs::remove_dir_all(&home);
}

/// C26 diceware: `vault gen --words N` emits an N-word passphrase from the built-in list.
#[test]
fn cli_gen_passphrase() {
    let (ok, out, err) = run(&["gen", "--words", "6"], "");
    assert!(ok, "gen --words failed: {err}");
    let parts: Vec<&str> = out.trim().split('-').collect();
    assert_eq!(parts.len(), 6, "expected 6 words: {out}");
    assert!(parts.iter().all(|w| !w.is_empty()));
    assert!(err.contains("bits of entropy"), "stderr: {err}");
}

/// C22: `vault tune` benchmarks Argon2id and prints a recommended m/t/p with the measured time.
#[test]
fn cli_tune_recommends_params() {
    let (ok, out, err) = run(&["tune"], "");
    assert!(ok, "tune failed: {err}");
    let combined = format!("{out}{err}");
    assert!(
        combined.contains("ms"),
        "tune output must report milliseconds: {combined}"
    );
    assert!(
        combined.contains("m=") && combined.contains("t=") && combined.contains("p="),
        "tune output must list m/t/p: {combined}"
    );
}

/// UC-07 §3.2: `vault pad on` enables Padmé size-padding and the vault still opens.
#[test]
fn cli_padding_toggle() {
    let home = unique_dir("pad-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "pad-pass\n";
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
    ];

    let mut init_args = vec!["--vault", vs, "init"];
    init_args.extend_from_slice(&fast);
    assert_eq!(run_env(&home, &init_args, pw).0, Some(0), "init");

    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    assert_eq!(
        run_env(&home, &["--vault", vs, "import", "--format", "raw", sp], pw).0,
        Some(0),
        "import"
    );
    let before = std::fs::metadata(&vault).unwrap().len();

    let (code, _, err) = run_env(&home, &["--vault", vs, "pad", "on"], pw);
    assert_eq!(code, Some(0), "pad on: {err}");
    assert!(err.to_lowercase().contains("padding"), "stderr: {err}");
    let after = std::fs::metadata(&vault).unwrap().len();
    assert!(
        after >= before,
        "padded file should not shrink ({after} < {before})"
    );

    // The vault still opens (and lists) with padding enabled.
    let (code, out, _) = run_env(&home, &["--vault", vs, "ls"], pw);
    assert_eq!(code, Some(0));
    assert!(out.contains("github"), "ls after padding: {out}");

    assert_eq!(
        run_env(&home, &["--vault", vs, "pad", "off"], pw).0,
        Some(0),
        "pad off"
    );

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

/// C16 / UC-07: a sync backend serving an older copy is detected against the local anchor.
#[test]
fn cli_rollback_detection() {
    let home = unique_dir("rb-home"); // isolated HOME/XDG so the anchor is sandboxed
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "rollback-pass\n";
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
    ];

    // init → version 1, anchor = 1
    let mut init_args = vec!["--vault", vs, "init"];
    init_args.extend_from_slice(&fast);
    let (code, _, err) = run_env(&home, &init_args, pw);
    assert_eq!(code, Some(0), "init: {err}");

    // snapshot the v1 file, then bump the vault to v2 (anchor advances to 2)
    let saved_v1 = unique_vault();
    std::fs::copy(&vault, &saved_v1).unwrap();
    let mut up_args = vec!["--vault", vs, "upgrade-kdf"];
    up_args.extend_from_slice(&fast);
    let (code, _, err) = run_env(&home, &up_args, pw);
    assert_eq!(code, Some(0), "upgrade-kdf: {err}");

    // a malicious/buggy backend serves the OLD copy back
    std::fs::copy(&saved_v1, &vault).unwrap();

    // non-interactive open → rollback → exit code 2 (reserved), warning on stderr, no prompt
    let (code, _, err) = run_env(&home, &["--vault", vs, "ls"], pw);
    assert_eq!(code, Some(2), "expected exit 2 on rollback; stderr: {err}");
    assert!(err.contains("version regressed"), "stderr: {err}");

    // --allow-rollback proceeds (exit 0), still printing the warning
    let (code, _, err) = run_env(&home, &["--vault", vs, "ls", "--allow-rollback"], pw);
    assert_eq!(code, Some(0), "allow-rollback should proceed: {err}");
    assert!(err.contains("version regressed"), "stderr: {err}");

    // TOFU: wipe the anchor → the first open of the old copy is trusted (no warning, exit 0)
    std::fs::remove_dir_all(&home).ok();
    std::fs::create_dir_all(&home).ok();
    let (code, _, err) = run_env(&home, &["--vault", vs, "ls"], pw);
    assert_eq!(code, Some(0), "TOFU open should succeed: {err}");
    assert!(
        !err.contains("version regressed"),
        "no warning on TOFU: {err}"
    );

    // --expect-min-version pins a floor even on a fresh machine → trips the guard
    std::fs::remove_dir_all(&home).ok();
    std::fs::create_dir_all(&home).ok();
    let (code, _, err) = run_env(
        &home,
        &["--vault", vs, "--expect-min-version", "99", "ls"],
        pw,
    );
    assert_eq!(
        code,
        Some(2),
        "expect-min-version floor should trip rollback: {err}"
    );
    assert!(err.contains("version regressed"), "stderr: {err}");

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_file(&saved_v1);
    let _ = std::fs::remove_dir_all(&home);
}
