//! UC-30 joint satisfaction — one fixture asserts C99–C102 together.

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use blindkey_core::{is_under_sync_root, CheckoutOpts, Error, WorkingCopySession, MAGIC_VLTD};

fn write_fake_vltd(path: &Path, payload: &[u8]) {
    let mut f = File::create(path).unwrap();
    f.write_all(&MAGIC_VLTD).unwrap();
    f.write_all(payload).unwrap();
}

#[test]
fn uc30_joint_satisfaction_checkout_mutate_remote_refuses() {
    let base = std::env::temp_dir().join(format!("vault-uc30-joint-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let sync = base.join("sync");
    let work = base.join("work");
    fs::create_dir_all(&sync).unwrap();
    fs::create_dir_all(&work).unwrap();

    let brick = sync.join("workspace.vltd");
    write_fake_vltd(&brick, &vec![0x44; 8192]);
    let checkout_fp_bytes = fs::read(&brick).unwrap();

    // C99 — checkout to non-sync work root.
    let session = WorkingCopySession::checkout(CheckoutOpts {
        source: &brick,
        work_root: Some(&work),
        skip_idle_probe: true,
        cancel: None,
        progress: None,
    })
    .unwrap();
    assert!(!is_under_sync_root(&session.work_path));
    assert_ne!(session.work_path, brick);

    // Operator edits the working copy.
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&session.work_path)
            .unwrap();
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(b"LOCAL-EDIT").unwrap();
    }
    let work_bytes = fs::read(&session.work_path).unwrap();

    // Another machine (simulated) changes the sync brick.
    {
        let mut f = fs::OpenOptions::new().write(true).open(&brick).unwrap();
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(b"OTHER-MACHINE").unwrap();
    }
    let remote_bytes = fs::read(&brick).unwrap();
    assert_ne!(remote_bytes, checkout_fp_bytes);

    // C101 — checkin refuses; C100 — remote untouched (no truncate/replace).
    let work_path = session.work_path.clone();
    let err = session.checkin().unwrap_err();
    assert!(matches!(err, Error::WorkingCopyRemoteChanged));
    assert_eq!(fs::read(&brick).unwrap(), remote_bytes);
    assert_eq!(fs::read(&work_path).unwrap(), work_bytes);

    // C102 — sync detector still meaningful for refuse paths.
    assert!(is_under_sync_root(Path::new(
        "/Users/x/Dropbox/conflict.vltd"
    )));

    let _ = fs::remove_dir_all(&base);
}
