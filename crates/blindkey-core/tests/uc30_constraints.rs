//! UC-30 constraint tests — C99–C102 (checkout / checkin working copy).

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use blindkey_core::{
    is_under_sync_root, CheckoutOpts, Error, WorkingCopySession, MAGIC_VLTD, WORKING_COPY_ERROR,
};

fn tmp(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vault-uc30-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_fake_vltd(path: &Path, payload: &[u8]) {
    let mut f = File::create(path).unwrap();
    f.write_all(&MAGIC_VLTD).unwrap();
    f.write_all(payload).unwrap();
}

/// C99: checkout lands outside a sync root; work path is distinct from source.
#[test]
fn c99_checkout_not_sync_path() {
    let base = tmp("c99");
    let sync = base.join("local_sync_sim");
    let work = base.join("work");
    fs::create_dir_all(&sync).unwrap();
    fs::create_dir_all(&work).unwrap();
    let brick = sync.join("workspace.vltd");
    write_fake_vltd(&brick, &vec![0x11; 4096]);

    assert!(!is_under_sync_root(&brick));

    let session = WorkingCopySession::checkout(CheckoutOpts {
        source: &brick,
        work_root: Some(&work),
        skip_idle_probe: true,
        cancel: None,
        progress: None,
    })
    .unwrap();

    assert_ne!(session.work_path, brick);
    assert!(!is_under_sync_root(&session.work_path));
    assert!(session.work_path.starts_with(&work));
    assert_eq!(
        fs::read(&session.work_path).unwrap(),
        fs::read(&brick).unwrap()
    );

    // Sync-root work root is refused (E6).
    let dropbox_work = base.join("Dropbox").join("work");
    fs::create_dir_all(&dropbox_work).unwrap();
    let err = WorkingCopySession::checkout(CheckoutOpts {
        source: &brick,
        work_root: Some(&dropbox_work),
        skip_idle_probe: true,
        cancel: None,
        progress: None,
    })
    .unwrap_err();
    assert!(matches!(err, Error::WorkingCopyWorkSyncRoot));
    assert_eq!(err.to_string(), WORKING_COPY_ERROR);

    let _ = fs::remove_dir_all(&base);
}

/// C100: checkin is temp+rename; prior brick bytes replaced atomically (no truncate-in-place API).
#[test]
fn c100_atomic_replace() {
    let base = tmp("c100");
    let sync = base.join("sync");
    let work = base.join("work");
    fs::create_dir_all(&sync).unwrap();
    fs::create_dir_all(&work).unwrap();
    let brick = sync.join("workspace.vltd");
    write_fake_vltd(&brick, &vec![0x22; 2048]);

    let session = WorkingCopySession::checkout(CheckoutOpts {
        source: &brick,
        work_root: Some(&work),
        skip_idle_probe: true,
        cancel: None,
        progress: None,
    })
    .unwrap();

    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&session.work_path)
            .unwrap();
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(b"PATCH").unwrap();
    }
    let expected = fs::read(&session.work_path).unwrap();
    session.checkin().unwrap();
    assert_eq!(fs::read(&brick).unwrap(), expected);
    // No leftover checkin temps.
    for ent in fs::read_dir(&sync).unwrap() {
        let name = ent.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!name.contains("bk-checkin.tmp"), "leftover temp: {name}");
    }

    let _ = fs::remove_dir_all(&base);
}

/// C101: fingerprint mismatch → no overwrite; work retained.
#[test]
fn c101_stale_remote_no_overwrite() {
    let base = tmp("c101");
    let sync = base.join("sync");
    let work = base.join("work");
    fs::create_dir_all(&sync).unwrap();
    fs::create_dir_all(&work).unwrap();
    let brick = sync.join("workspace.vltd");
    write_fake_vltd(&brick, &vec![0x33; 1024]);
    let original = fs::read(&brick).unwrap();

    let session = WorkingCopySession::checkout(CheckoutOpts {
        source: &brick,
        work_root: Some(&work),
        skip_idle_probe: true,
        cancel: None,
        progress: None,
    })
    .unwrap();
    let work_path = session.work_path.clone();

    {
        let mut f = fs::OpenOptions::new().write(true).open(&brick).unwrap();
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(b"REMOTE").unwrap();
    }
    let remote = fs::read(&brick).unwrap();
    assert_ne!(remote, original);

    let err = session.checkin().unwrap_err();
    assert!(matches!(err, Error::WorkingCopyRemoteChanged));
    assert_eq!(
        fs::read(&brick).unwrap(),
        remote,
        "must not overwrite remote"
    );
    assert!(work_path.is_file(), "work retained for discard/resume");

    let _ = fs::remove_dir_all(&base);
}

/// C102: mount-path detector still flags sync roots (docs/CLI refuse stays meaningful).
#[test]
fn c102_sync_root_detector_still_flags_cloud_paths() {
    assert!(is_under_sync_root(Path::new(
        "/Users/x/Library/CloudStorage/Dropbox/a.vltd"
    )));
    assert!(is_under_sync_root(Path::new("/home/x/Dropbox/a.vltd")));
    assert!(!is_under_sync_root(Path::new("/var/tmp/local/a.vltd")));
}
