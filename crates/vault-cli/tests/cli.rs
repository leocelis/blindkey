//! End-to-end CLI integration test: drives the built `vault` binary against the sample `keys.txt`
//! over piped stdin (the non-interactive password path), and asserts the encrypted file leaks
//! nothing. Covers init → import → ls → get → wrong-password → rm → gen, plus the C18 on-disk check.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Run the `vault` binary with `args`, feeding `stdin`. Returns (success, stdout, stderr).
fn run(args: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
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
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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
