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
/// When `stdin` is non-empty and no explicit password channel is set, prepends `--password-stdin`.
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
        .env("LOCALAPPDATA", home.join("local")) // Windows anchor dir → keep it sandboxed too
        .args(&argv)
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
    let (ok, _, err) = run(
        &["--vault", vs, "import", "--format", "raw", sp, "--yes"],
        pw,
    );
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

#[test]
fn export_json_dumps_all_entries() {
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    let pw = "export-pass\n";

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
            "--allow-weak-password",
        ],
        pw,
    );
    assert!(ok, "init: {err}");

    let (ok, _, err) = run(
        &["--vault", vs, "import", "--format", "raw", sp, "--yes"],
        pw,
    );
    assert!(ok, "import: {err}");

    let (ok, out, err) = run(&["--vault", vs, "export", "--format", "json", "--yes"], pw);
    assert!(ok, "export failed: {err}");
    assert!(
        err.contains("WARNING: export writes ALL decrypted entries"),
        "stderr: {err}"
    );
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert_eq!(v["vault_export_version"], 1);
    let entries = v["entries"].as_array().unwrap();
    assert!(entries.len() >= 2);
    let github = entries
        .iter()
        .find(|e| e["title"] == "github")
        .expect("github entry");
    assert!(github["password"].as_str().unwrap().contains("ghp_FAKE"));
}

#[test]
fn export_piped_without_yes_exits_8() {
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let home = shared_home();
    let pw = "export-no-yes\n";
    let (code, _, _) = run_env(
        &home,
        &[
            "--password-stdin",
            "--vault",
            vs,
            "init",
            "--kdf-m-cost",
            "8192",
            "--kdf-t-cost",
            "1",
            "--kdf-p-cost",
            "1",
            "--allow-weak-password",
        ],
        pw,
    );
    assert_eq!(code, Some(0));
    let (code, _, err) = run_env(
        &home,
        &[
            "--password-stdin",
            "--vault",
            vs,
            "export",
            "--format",
            "json",
        ],
        pw,
    );
    assert_eq!(code, Some(8), "stderr: {err}");
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
        "--allow-weak-kdf",
    ];

    let mut init_args = vec!["--vault", vs, "init"];
    init_args.extend_from_slice(&fast);
    assert_eq!(run_env(&home, &init_args, pw).0, Some(0), "init");

    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    assert_eq!(
        run_env(
            &home,
            &["--vault", vs, "import", "--format", "raw", sp, "--yes"],
            pw
        )
        .0,
        Some(0),
        "import"
    );

    let (code, _, err) = run_env(&home, &["--vault", vs, "otp", "github", "--stdout"], pw);
    assert!(code != Some(0), "otp without a 2FA secret should fail");
    assert!(err.contains("no 2FA secret"), "stderr: {err}");

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

/// UC-19 fuzzy omni-search: `vault find QUERY --stdout` ranks by fuzzy match over metadata (typo-
/// tolerant), lists titles only (never a secret), and never echoes the query on a miss (C37). The
/// clipboard copy path is exercised at the unit level (no clipboard in CI).
#[test]
fn cli_find_fuzzy_lists_titles_and_never_leaks() {
    let home = unique_dir("find-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    let pw = "find-pass\n";
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
        "--allow-weak-kdf",
    ];

    let mut init = vec!["--vault", vs, "init"];
    init.extend_from_slice(&fast);
    assert_eq!(run_env(&home, &init, pw).0, Some(0), "init");
    assert_eq!(
        run_env(
            &home,
            &["--vault", vs, "import", "--format", "raw", sp, "--yes"],
            pw
        )
        .0,
        Some(0),
        "import"
    );

    // Fuzzy + typo-tolerant: "githb" still finds "github". Titles only, no secret in the output.
    let (code, out, _) = run_env(&home, &["--vault", vs, "find", "githb", "--stdout"], pw);
    assert_eq!(code, Some(0), "find --stdout should succeed");
    assert!(
        out.to_lowercase().contains("github"),
        "fuzzy query should match github: {out}"
    );
    assert!(
        !out.contains("ghp_FAKE0mZ9"),
        "find output must never contain a secret value: {out}"
    );

    // No match → non-zero exit, and the query is NOT echoed back anywhere (C37 — never log queries).
    let (code, _o, err) = run_env(
        &home,
        &["--vault", vs, "find", "zzgibberishzz", "--stdout"],
        pw,
    );
    assert!(code != Some(0), "a no-match search should fail");
    assert!(
        !err.contains("zzgibberishzz"),
        "the query must never be echoed/logged (C37): {err}"
    );
    assert!(
        err.contains("C35") || err.to_lowercase().contains("not passwords"),
        "no-match should explain searchable scope: {err}"
    );

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

/// UC-17 / UC-05: piped import must pass `--yes` explicitly (exit 8 otherwise).
#[test]
fn cli_import_non_tty_requires_yes() {
    let home = unique_dir("import-yes-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    let pw = "import-yes-pass\n";
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
        "--allow-weak-kdf",
    ];

    let mut init = vec!["--vault", vs, "init"];
    init.extend_from_slice(&fast);
    assert_eq!(run_env(&home, &init, pw).0, Some(0), "init");

    let (code, _, err) = run_env(&home, &["--vault", vs, "import", "--format", "raw", sp], pw);
    assert_eq!(
        code,
        Some(8),
        "piped import without --yes should be a usage error: {err}"
    );
    assert!(err.contains("--yes"), "stderr should name the flag: {err}");

    assert_eq!(
        run_env(
            &home,
            &["--vault", vs, "import", "--format", "raw", sp, "--yes"],
            pw,
        )
        .0,
        Some(0),
        "piped import with --yes should succeed"
    );

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_file(format!("{vs}.bak"));
    let _ = std::fs::remove_dir_all(&home);
}

/// C35: `vault find` never matches secret values or notes — metadata only.
#[test]
fn cli_find_does_not_search_secrets_or_notes() {
    let home = unique_dir("find-c35-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "find-c35-pass\n";
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
        "--allow-weak-kdf",
    ];
    let import_file = std::env::temp_dir().join(format!("vault-c35-{}.txt", std::process::id()));
    std::fs::write(
        &import_file,
        "---\n\nsecret-entry\nONLY_IN_PASSWORD_XYZ\nnote: ONLY_IN_NOTES_ABC\n",
    )
    .unwrap();
    let ip = import_file.to_str().unwrap();

    let mut init = vec!["--vault", vs, "init"];
    init.extend_from_slice(&fast);
    assert_eq!(run_env(&home, &init, pw).0, Some(0), "init");
    assert_eq!(
        run_env(
            &home,
            &["--vault", vs, "import", "--format", "raw", ip, "--yes"],
            pw,
        )
        .0,
        Some(0),
        "import"
    );

    for token in ["ONLY_IN_PASSWORD_XYZ", "ONLY_IN_NOTES_ABC"] {
        let (code, out, err) = run_env(&home, &["--vault", vs, "find", token, "--stdout"], pw);
        assert_ne!(
            code,
            Some(0),
            "find must not match secret-adjacent content ({token}): out={out} err={err}"
        );
        assert!(
            !out.contains(token),
            "stdout must not leak the token: {out}"
        );
    }

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_file(format!("{vs}.bak"));
    let _ = std::fs::remove_file(&import_file);
    let _ = std::fs::remove_dir_all(&home);
}

/// Pre-1.0 safety: `vault init` writes an initial `.bak` and prints the audit notice.
#[test]
fn cli_init_writes_initial_backup_and_notice() {
    let home = unique_dir("init-bak-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "init-bak-pass\n";
    let fast = [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
        "--allow-weak-kdf",
    ];
    let mut init = vec!["--vault", vs, "init"];
    init.extend_from_slice(&fast);
    let (code, _, err) = run_env(&home, &init, pw);
    assert_eq!(code, Some(0), "init: {err}");
    assert!(
        Path::new(&format!("{vs}.bak")).exists(),
        "init should seed vault.vlt.bak"
    );
    assert!(
        err.contains("third-party")
            || err.contains("independently audited")
            || err.contains("backup"),
        "init should warn about audit posture / backup: {err}"
    );

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_file(format!("{vs}.bak"));
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
        "--allow-weak-kdf",
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
        "--allow-weak-kdf",
    ];

    let mut init_args = vec!["--vault", vs, "init"];
    init_args.extend_from_slice(&fast);
    assert_eq!(run_env(&home, &init_args, pw).0, Some(0), "init");

    let sample = sample_path();
    let sp = sample.to_str().unwrap();
    assert_eq!(
        run_env(
            &home,
            &["--vault", vs, "import", "--format", "raw", sp, "--yes"],
            pw
        )
        .0,
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
        "--allow-weak-kdf",
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

/// Keyfile second factor (true 2FA, no hardware): enroll generates a keyfile, then the vault needs
/// BOTH the password and the keyfile to open. `--recovery` is the anti-lockout path (UC-09).
#[test]
fn cli_keyfile_2fa_enroll_open_and_recovery() {
    let home = std::env::temp_dir().join(format!("vault-kf-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).ok();
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let keyfile = std::env::temp_dir().join(format!("vault-kf-{}.key", std::process::id()));
    let kf = keyfile.to_str().unwrap();
    let pw = "keyfile-master-pass-1\n";

    let (code, _, err) = run_env(
        &home,
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
    assert_eq!(code, Some(0), "init failed: {err}");

    // Enroll the keyfile — the path doesn't exist yet, so a fresh random one is generated (0600).
    let (code, _, err) = run_env(&home, &["--vault", vs, "enroll", "keyfile", kf], pw);
    assert_eq!(code, Some(0), "enroll keyfile failed: {err}");
    assert!(std::path::Path::new(kf).exists(), "keyfile should exist");
    assert_eq!(std::fs::read(kf).unwrap().len(), 32, "keyfile is 32 bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(kf).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keyfile must be 0600");
    }

    // Pull the recovery code out of the enroll output (printed on its own indented line).
    let recovery = err
        .lines()
        .map(str::trim)
        .find(|l| l.len() >= 24 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .expect("recovery code in enroll output")
        .to_string();

    // Password alone (no keyfile) → refused with a clear message.
    let (code, _, err) = run_env(&home, &["--vault", vs, "ls"], pw);
    assert_ne!(code, Some(0), "open without keyfile should fail");
    assert!(err.contains("requires a keyfile"), "stderr: {err}");

    // Password + the correct keyfile → opens.
    let (code, out, err) = run_env(&home, &["--vault", vs, "--keyfile", kf, "ls"], pw);
    assert_eq!(code, Some(0), "open with keyfile failed: {err}");
    let _ = out;

    // Password + a WRONG keyfile → refused (both factors must match).
    let wrong = std::env::temp_dir().join(format!("vault-kf-wrong-{}.key", std::process::id()));
    std::fs::write(&wrong, [0u8; 32]).unwrap();
    let (code, _, _) = run_env(
        &home,
        &["--vault", vs, "--keyfile", wrong.to_str().unwrap(), "ls"],
        pw,
    );
    assert_ne!(code, Some(0), "wrong keyfile must not open");

    // Recovery path: `--recovery` with the recovery code (no keyfile) opens via the password path.
    let recovery_stdin = format!("{recovery}\n");
    let (code, _, err) = run_env(&home, &["--vault", vs, "--recovery", "ls"], &recovery_stdin);
    assert_eq!(code, Some(0), "recovery open failed: {err}");

    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_file(&keyfile);
    let _ = std::fs::remove_file(&wrong);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn non_interactive_without_password_channel_exits_5() {
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let home = shared_home();
    let pw = "pw-5\n";
    let fast = &[
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
        "--allow-weak-kdf",
    ];
    let mut init_args = vec!["--vault", vs, "init", "--allow-weak-password"];
    init_args.extend_from_slice(fast);
    assert_eq!(run_env(&home, &init_args, pw).0, Some(0));

    let (code, _, err) = run_env(&home, &["--vault", vs, "ls"], "");
    assert_eq!(code, Some(5), "stderr: {err}");
    assert!(err.contains("non-interactive"), "stderr: {err}");

    let _ = std::fs::remove_file(&vault);
}

#[test]
fn lock_exits_zero_and_documents_per_process_model() {
    let (ok, _, err) = run(&["lock"], "");
    assert!(ok, "lock failed: {err}");
    assert!(err.contains("Locked"), "stderr: {err}");
    assert!(err.contains("no unlock session"), "stderr: {err}");
}

#[cfg(unix)]
#[test]
fn vault_password_file_env_unlocks() {
    use std::os::unix::fs::OpenOptionsExt;

    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let home = shared_home();
    let pw_file = home.join("master.pw");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&pw_file)
            .unwrap();
        f.write_all(b"file-pass\n").unwrap();
    }
    let fast = &[
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
        "--allow-weak-kdf",
    ];
    let mut init_args = vec!["--vault", vs, "init", "--allow-weak-password"];
    init_args.extend_from_slice(fast);
    let (code, _, err) = run_env(&home, &init_args, "file-pass\n");
    assert_eq!(code, Some(0), "init: {err}");

    let child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("share"))
        .env("VAULT_PASSWORD_FILE", &pw_file)
        .args(["--vault", vs, "ls"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_file(&vault);
}

fn fast_kdf() -> [&'static str; 7] {
    [
        "--kdf-m-cost",
        "8192",
        "--kdf-t-cost",
        "1",
        "--kdf-p-cost",
        "1",
        "--allow-weak-kdf",
    ]
}

fn init_vault(home: &Path, vault: &Path, pw: &str) {
    let vs = vault.to_str().unwrap();
    let mut args = vec!["--vault", vs, "init", "--allow-weak-password"];
    args.extend_from_slice(&fast_kdf());
    assert_eq!(run_env(home, &args, pw).0, Some(0), "init");
}

/// C28: imported entry titles with ANSI/control bytes must not reach the terminal raw.
#[test]
fn c28_ls_sanitizes_evil_title() {
    let home = unique_dir("c28-ls-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "c28-pass\n";
    init_vault(&home, &vault, pw);

    let evil = std::env::temp_dir().join(format!("vault-c28-ls-{}.txt", std::process::id()));
    std::fs::write(
        &evil,
        b"evil\x1b[31mname\nghp_FAKE0mZ9xQ2vL7nR4tW8pY1aB3cD5eF6gH7iJ\n",
    )
    .unwrap();
    let ep = evil.to_str().unwrap();
    assert_eq!(
        run_env(
            &home,
            &["--vault", vs, "import", "--format", "raw", ep, "--yes"],
            pw
        )
        .0,
        Some(0),
        "import"
    );

    let (_, out, _) = run_env(&home, &["--vault", vs, "ls"], pw);
    assert!(
        !out.as_bytes().contains(&0x1b),
        "raw ESC must not appear in ls output: {out:?}"
    );
    assert!(out.contains("\\x1b"), "ls: {out}");

    let _ = std::fs::remove_file(&evil);
    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

/// C28: `get --stdout` must sanitize secret bytes before writing to stdout.
#[test]
fn c28_get_stdout_sanitizes_ansi_in_password() {
    let home = unique_dir("c28-get-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "c28-get-pass\n";
    init_vault(&home, &vault, pw);

    let evil = std::env::temp_dir().join(format!("vault-c28-get-{}.txt", std::process::id()));
    std::fs::write(&evil, b"ansi_entry\nghp_FAKE0mZ9\x1b[31mword\n").unwrap();
    let ep = evil.to_str().unwrap();
    assert_eq!(
        run_env(
            &home,
            &["--vault", vs, "import", "--format", "raw", ep, "--yes"],
            pw
        )
        .0,
        Some(0),
        "import"
    );

    let (_, out, _) = run_env(&home, &["--vault", vs, "get", "ansi_entry", "--stdout"], pw);
    assert!(
        !out.as_bytes().contains(&0x1b),
        "raw ESC must not appear in get --stdout: {out:?}"
    );
    assert!(out.contains("\\x1b"), "get: {out}");

    let _ = std::fs::remove_file(&evil);
    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

/// C13: detached helper subcommand accepts stdin and exits promptly when timeout is 0.
#[test]
fn c13_hold_clipboard_zero_exits_immediately() {
    let home = unique_dir("c13-home");
    let (code, _, err) = run_env(&home, &["hold-clipboard", "0"], "clip-secret");
    assert_eq!(code, Some(0), "stderr: {err}");
    let _ = std::fs::remove_dir_all(&home);
}

/// C15: `vault re-enroll-tpm --help` documents PCR brittleness (constraint C15 documentation test).
#[test]
fn c15_re_enroll_tpm_help_documents_pcr() {
    let out = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("re-enroll-tpm")
        .arg("--help")
        .output()
        .expect("spawn vault");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("PCR"), "help: {help}");
    assert!(help.contains("firmware"), "help: {help}");
    assert!(help.contains("re-enroll"), "help: {help}");
}

/// C21: `vault stanzas list` shows enrolled types (password always present after init).
#[test]
fn c21_stanzas_list_after_init() {
    let home = unique_dir("c21-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "test-passphrase-12345\n";
    assert_eq!(
        run_env(&home, &["--vault", vs, "init", "--allow-weak-password"], pw).0,
        Some(0)
    );
    let (_, out, _) = run_env(&home, &["--vault", vs, "stanzas", "list"], pw);
    assert!(out.contains("password"), "out: {out}");
    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}

/// C27: headless Linux sessions refuse clipboard delivery with exit 7.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn c27_headless_get_exits_7_without_stdout() {
    let home = unique_dir("c27-home");
    let vault = unique_vault();
    let vs = vault.to_str().unwrap();
    let pw = "test-passphrase-12345\n";
    assert_eq!(
        run_env(&home, &["--vault", vs, "init", "--allow-weak-password"], pw).0,
        Some(0)
    );
    let sample = sample_path();
    assert_eq!(
        run_env(
            &home,
            &[
                "--vault",
                vs,
                "import",
                "--format",
                "raw",
                sample.to_str().unwrap(),
                "--yes",
            ],
            pw,
        )
        .0,
        Some(0)
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vault"));
    cmd.env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("share"))
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["--vault", vs, "--password-stdin", "get", "github"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(pw.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(7),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no clipboard available"),
        "stderr"
    );
    assert!(!out
        .stdout
        .iter()
        .any(|&b| b.is_ascii_graphic() && b != b'\n'));
    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_dir_all(&home);
}
