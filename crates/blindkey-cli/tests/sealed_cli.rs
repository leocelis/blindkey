//! UC-23 CLI integration: `vault seal` / `open` / `peek`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn home() -> PathBuf {
    let p = std::env::temp_dir().join(format!("vault-seal-cli-{}", std::process::id()));
    fs::create_dir_all(&p).ok();
    p
}

fn run(args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let mut argv = vec!["--password-stdin"];
    argv.extend(args);
    let mut child = Command::new(env!("CARGO_BIN_EXE_blindkey"))
        .env("HOME", home())
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

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vault-{tag}-{}-{nanos}", std::process::id()))
}

#[test]
fn seal_open_peek_round_trip() {
    let base = unique_dir("uc23");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("hello.txt");
    fs::write(&src, b"sealed-by-cli").unwrap();
    let vltf = base.join("hello.vltf");
    let out = base.join("out");

    let pw = "cli-seal-password\ncli-seal-password\n";
    let (code, _, err) = run(
        &[
            "seal",
            src.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0), "seal failed: {err}");
    assert!(vltf.is_file());

    let (code, stdout, err) = run(&["peek", vltf.to_str().unwrap()], "cli-seal-password\n");
    assert_eq!(code, Some(0), "peek failed: {err}");
    assert!(stdout.contains("hello.txt"));
    assert!(!stdout.contains("sealed-by-cli"));

    fs::create_dir_all(&out).unwrap();
    let (code, _, err) = run(
        &["open", vltf.to_str().unwrap(), "-C", out.to_str().unwrap()],
        "cli-seal-password\n",
    );
    assert_eq!(code, Some(0), "open failed: {err}");
    assert_eq!(fs::read(out.join("hello.txt")).unwrap(), b"sealed-by-cli");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn open_stdout_warns_and_delivers_single_file() {
    let base = unique_dir("stdout");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("one.bin");
    fs::write(&src, b"pipe-me").unwrap();
    let vltf = base.join("one.vltf");
    let pw = "stdout-pw\nstdout-pw\n";

    let (code, _, err) = run(
        &[
            "seal",
            src.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0), "seal: {err}");

    let (code, stdout, err) = run(&["open", vltf.to_str().unwrap(), "--stdout"], "stdout-pw\n");
    assert_eq!(code, Some(0), "open --stdout: {err}");
    assert!(err.contains("WARNING"));
    assert_eq!(stdout.as_bytes(), b"pipe-me");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn wrong_password_exits_5() {
    let base = unique_dir("auth");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("x.txt");
    fs::write(&src, b"x").unwrap();
    let vltf = base.join("x.vltf");
    let pw = "right-pw\nright-pw\n";
    let (code, _, _) = run(
        &[
            "seal",
            src.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0));

    let (code, _, err) = run(&["peek", vltf.to_str().unwrap()], "wrong-pw\n");
    assert_eq!(code, Some(5), "wrong password should exit 5: {err}");
    assert!(err.contains("auth:"));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn seal_stdin_pipe_round_trip() {
    let base = unique_dir("stdin-seal");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let vltf = base.join("stdin.vltf");
    let out = base.join("out");
    fs::create_dir_all(&out).unwrap();

    let pw_file = base.join("pw");
    fs::write(&pw_file, b"stdin-pw\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pw_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let payload = "piped tarball bytes";
    let mut child = Command::new(env!("CARGO_BIN_EXE_blindkey"))
        .env("HOME", home())
        .env("BLINDKEY_PASSWORD_FILE", &pw_file)
        .args([
            "seal",
            "-",
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vault");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(payload.as_bytes()).unwrap();
    drop(stdin);
    let out_proc = child.wait_with_output().unwrap();
    assert_eq!(out_proc.status.code(), Some(0));
    assert!(vltf.is_file());

    let (code, _, err) = run(
        &["open", vltf.to_str().unwrap(), "-C", out.to_str().unwrap()],
        "stdin-pw\n",
    );
    assert_eq!(code, Some(0), "open failed: {err}");
    assert_eq!(fs::read(out.join("-")).unwrap(), payload.as_bytes());

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn seal_refuses_overwrite() {
    let base = unique_dir("no-clobber");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("a.txt");
    fs::write(&src, b"a").unwrap();
    let vltf = base.join("a.vltf");
    fs::write(&vltf, b"existing").unwrap();
    let pw = "pw\npw\n";
    let (code, _, err) = run(
        &["seal", src.to_str().unwrap(), "-o", vltf.to_str().unwrap()],
        pw,
    );
    assert_ne!(code, Some(0));
    assert!(err.contains("refusing to overwrite"), "{err}");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn stanzas_list_reads_vltf_header_without_unlock() {
    let base = unique_dir("stanzas");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("doc.txt");
    fs::write(&src, b"x").unwrap();
    let vltf = base.join("doc.vltf");
    let pw = "stanza-pw\nstanza-pw\n";
    let (code, _, err) = run(
        &[
            "seal",
            src.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0), "seal: {err}");

    let (code, stdout, err) = run(&["--vault", vltf.to_str().unwrap(), "stanzas", "list"], "");
    assert_eq!(code, Some(0), "stanzas list on .vltf: {err}");
    assert!(
        stdout.contains("password"),
        "expected password stanza: {stdout}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn sealed_keyfile_enroll_and_stanzas_remove() {
    let base = unique_dir("vltf-2fa");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("secret.txt");
    fs::write(&src, b"classified").unwrap();
    let vltf = base.join("secret.vltf");
    let kf = base.join("second.vltf.key");
    let pw = "sealed-2fa-pw\nsealed-2fa-pw\n";

    let (code, _, err) = run(
        &[
            "seal",
            src.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0), "seal: {err}");

    let (code, _, err) = run(
        &[
            "--vault",
            vltf.to_str().unwrap(),
            "enroll",
            "keyfile",
            kf.to_str().unwrap(),
        ],
        "sealed-2fa-pw\n",
    );
    assert_eq!(code, Some(0), "enroll keyfile on .vltf: {err}");
    assert!(kf.is_file());

    let (code, stdout, err) = run(&["--vault", vltf.to_str().unwrap(), "stanzas", "list"], "");
    assert_eq!(code, Some(0), "stanzas list: {err}");
    assert!(
        stdout.contains("pw-keyfile"),
        "expected pw-keyfile stanza: {stdout}"
    );

    let out = base.join("extract");
    fs::create_dir_all(&out).unwrap();
    let (code, _, err) = run(
        &[
            "--keyfile",
            kf.to_str().unwrap(),
            "open",
            vltf.to_str().unwrap(),
            "-C",
            out.to_str().unwrap(),
        ],
        "sealed-2fa-pw\n",
    );
    assert_eq!(code, Some(0), "open with keyfile: {err}");
    assert_eq!(fs::read(out.join("secret.txt")).unwrap(), b"classified");

    let (code, _, err) = run(
        &[
            "--vault",
            vltf.to_str().unwrap(),
            "--keyfile",
            kf.to_str().unwrap(),
            "stanzas",
            "remove",
            "pw-keyfile",
        ],
        "sealed-2fa-pw\n",
    );
    assert_eq!(code, Some(0), "stanzas remove keyfile: {err}");

    let (code, stdout, err) = run(&["--vault", vltf.to_str().unwrap(), "stanzas", "list"], "");
    assert_eq!(code, Some(0), "stanzas list after remove: {err}");
    assert!(
        !stdout.contains("pw-keyfile"),
        "keyfile stanza should be gone: {stdout}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn seal_append_merges_into_existing_container() {
    let base = unique_dir("append");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let a = base.join("a.txt");
    let b = base.join("b.txt");
    fs::write(&a, b"alpha").unwrap();
    fs::write(&b, b"beta").unwrap();
    let vltf = base.join("bundle.vltf");
    let out = base.join("out");
    fs::create_dir_all(&out).unwrap();
    let pw = "append-pw\nappend-pw\n";

    let (code, _, err) = run(
        &[
            "seal",
            a.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0), "initial seal: {err}");

    let (code, _, err) = run(
        &[
            "seal",
            "--append",
            b.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
        ],
        "append-pw\n",
    );
    assert_eq!(code, Some(0), "append: {err}");

    let (code, stdout, err) = run(&["peek", vltf.to_str().unwrap()], "append-pw\n");
    assert_eq!(code, Some(0), "peek: {err}");
    assert!(stdout.contains("a.txt"), "{stdout}");
    assert!(stdout.contains("b.txt"), "{stdout}");

    let (code, _, err) = run(
        &["open", vltf.to_str().unwrap(), "-C", out.to_str().unwrap()],
        "append-pw\n",
    );
    assert_eq!(code, Some(0), "open: {err}");
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(out.join("b.txt")).unwrap(), b"beta");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn sealed_upgrade_kdf_preserves_inner_archive() {
    let base = unique_dir("upgrade-kdf");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("doc.txt");
    fs::write(&src, b"unchanged-body").unwrap();
    let vltf = base.join("doc.vltf");
    let pw = "kdf-pw\nkdf-pw\n";
    let (code, _, err) = run(
        &[
            "seal",
            src.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0), "seal: {err}");

    let (code, _, err) = run(
        &[
            "--vault",
            vltf.to_str().unwrap(),
            "upgrade-kdf",
            "--kdf-m-cost",
            "32768",
            "--kdf-t-cost",
            "3",
            "--kdf-p-cost",
            "2",
        ],
        "kdf-pw\n",
    );
    assert_eq!(code, Some(0), "upgrade-kdf on .vltf: {err}");

    let out = base.join("extract");
    fs::create_dir_all(&out).unwrap();
    let (code, _, err) = run(
        &["open", vltf.to_str().unwrap(), "-C", out.to_str().unwrap()],
        "kdf-pw\n",
    );
    assert_eq!(code, Some(0), "open after upgrade: {err}");
    assert_eq!(fs::read(out.join("doc.txt")).unwrap(), b"unchanged-body");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn sealed_rotate_data_key_reencrypts() {
    let base = unique_dir("rotate");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let src = base.join("secret.bin");
    fs::write(&src, b"rotate-me").unwrap();
    let vltf = base.join("secret.vltf");
    let pw = "rotate-pw\nrotate-pw\n";
    let (code, _, err) = run(
        &[
            "seal",
            src.to_str().unwrap(),
            "-o",
            vltf.to_str().unwrap(),
            "--allow-weak-kdf",
            "--kdf-m-cost",
            "19456",
            "--kdf-t-cost",
            "2",
            "--kdf-p-cost",
            "1",
        ],
        pw,
    );
    assert_eq!(code, Some(0), "seal: {err}");
    let before = fs::read(&vltf).unwrap();

    let (code, _, err) = run(
        &["--vault", vltf.to_str().unwrap(), "rotate-data-key"],
        "rotate-pw\n",
    );
    assert_eq!(code, Some(0), "rotate-data-key on .vltf: {err}");
    let after = fs::read(&vltf).unwrap();
    assert_ne!(before, after, "rotate should rewrite the container");

    let out = base.join("out");
    fs::create_dir_all(&out).unwrap();
    let (code, _, err) = run(
        &["open", vltf.to_str().unwrap(), "-C", out.to_str().unwrap()],
        "rotate-pw\n",
    );
    assert_eq!(code, Some(0), "open after rotate: {err}");
    assert_eq!(fs::read(out.join("secret.bin")).unwrap(), b"rotate-me");

    let _ = fs::remove_dir_all(&base);
}
