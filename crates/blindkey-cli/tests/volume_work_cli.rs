//! UC-30 CLI: `volume checkout` / `checkin` / `work-status` / `work-discard`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn home() -> PathBuf {
    let p = std::env::temp_dir().join(format!("bk-uc30-home-{}", std::process::id()));
    fs::create_dir_all(&p).ok();
    p
}

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("bk-uc30-{tag}-{}-{nanos}", std::process::id()))
}

fn run(args: &[&str], stdin: &str, extra_env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let mut argv = vec!["--password-stdin"];
    argv.extend(args);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blindkey"));
    cmd.env("HOME", home())
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn blindkey");
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

fn create_volume(brick: &std::path::Path, password_twice: &str) -> (Option<i32>, String) {
    let args = [
        "volume",
        "create",
        brick.to_str().unwrap(),
        "--size",
        "1MiB",
        "--allow-weak-kdf",
    ];
    let (code, _, err) = run(&args, password_twice, &[]);
    (code, err)
}

#[test]
fn checkout_checkin_roundtrip_under_dropbox_name() {
    let base = unique_dir("round");
    let _ = fs::remove_dir_all(&base);
    // Path segment "Dropbox" triggers sync-root detector (C73 / C99).
    let sync = base.join("Dropbox");
    let work_root = base.join("work");
    fs::create_dir_all(&sync).unwrap();
    fs::create_dir_all(&work_root).unwrap();
    let brick = sync.join("workspace.vltd");

    let pw = "uc30-cli-password\nuc30-cli-password\n";
    let (code, err) = create_volume(&brick, pw);
    assert_eq!(code, Some(0), "volume create failed: {err}");
    assert!(brick.is_file());

    // Mount of sync-path must refuse (C73 / C102).
    let mnt = base.join("mnt");
    fs::create_dir_all(&mnt).unwrap();
    let (code, _, err) = run(
        &[
            "volume",
            "mount",
            brick.to_str().unwrap(),
            mnt.to_str().unwrap(),
        ],
        "uc30-cli-password\n",
        &[],
    );
    assert_ne!(code, Some(0), "sync-path mount must refuse: {err}");
    assert!(
        err.to_ascii_lowercase().contains("checkout")
            || err.to_ascii_lowercase().contains("seal")
            || err.to_ascii_lowercase().contains("sync"),
        "refuse should point at checkout/seal: {err}"
    );

    let checkout_args = [
        "volume",
        "checkout",
        brick.to_str().unwrap(),
        "--work-dir",
        work_root.to_str().unwrap(),
    ];
    let (code, stdout, err) = run(&checkout_args, "uc30-cli-password\n", &[]);
    assert_eq!(code, Some(0), "checkout failed: {err}");
    let id = stdout.trim();
    assert!(!id.is_empty(), "checkout must print session id");
    assert!(
        work_root.join(id).join("state.json").is_file(),
        "sidecar missing for {id}"
    );

    let (code, stdout, err) = run(
        &[
            "volume",
            "work-status",
            id,
            "--work-dir",
            work_root.to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert_eq!(code, Some(0), "work-status failed: {err}");
    assert!(stdout.contains(id));

    let (code, _, err) = run(
        &[
            "volume",
            "checkin",
            id,
            "--work-dir",
            work_root.to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert_eq!(code, Some(0), "checkin failed: {err}");
    assert!(brick.is_file());
    assert!(
        !work_root.join(id).join("state.json").is_file(),
        "sidecar should be removed after checkin"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn checkin_refuses_when_remote_brick_changed() {
    let base = unique_dir("e1");
    let _ = fs::remove_dir_all(&base);
    let sync = base.join("Dropbox");
    let work_root = base.join("work");
    fs::create_dir_all(&sync).unwrap();
    fs::create_dir_all(&work_root).unwrap();
    let brick = sync.join("workspace.vltd");

    let pw = "uc30-e1-password\nuc30-e1-password\n";
    let (code, err) = create_volume(&brick, pw);
    assert_eq!(code, Some(0), "create: {err}");

    let (code, stdout, err) = run(
        &[
            "volume",
            "checkout",
            brick.to_str().unwrap(),
            "--work-dir",
            work_root.to_str().unwrap(),
        ],
        "uc30-e1-password\n",
        &[],
    );
    assert_eq!(code, Some(0), "checkout: {err}");
    let id = stdout.trim().to_string();

    // Mutate sync brick after checkout (C101 / E1).
    fs::write(&brick, b"MUTATED-REMOTE-BRICK-BYTES").unwrap();

    let (code, _, err) = run(
        &[
            "volume",
            "checkin",
            &id,
            "--work-dir",
            work_root.to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert_eq!(code, Some(10), "E1 must exit 10, got {code:?}: {err}");
    assert!(
        err.contains("changed") || err.contains("E1") || err.contains("refusing"),
        "E1 message: {err}"
    );

    let (code, _, err) = run(
        &[
            "volume",
            "work-discard",
            &id,
            "--work-dir",
            work_root.to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert_eq!(code, Some(0), "discard: {err}");

    let _ = fs::remove_dir_all(&base);
}
