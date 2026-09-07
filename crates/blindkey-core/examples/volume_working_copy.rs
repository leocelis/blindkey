//! Example: UC-30 volume working copy (checkout → edit → checkin).
//!
//! Run from the workspace root:
//! ```text
//! cargo run -p blindkey-core --example volume_working_copy
//! ```
//!
//! Creates a fake `.vltd` brick under a temp "sync" folder, checks it out to a
//! local work root, patches the working copy, checks it back in, then demonstrates
//! C101 (refuse overwrite when the remote changed).

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use blindkey_core::{CheckoutOpts, Error, WorkingCopySession, MAGIC_VLTD};

fn write_fake_vltd(path: &Path, payload: &[u8]) {
    let mut f = File::create(path).expect("create brick");
    f.write_all(&MAGIC_VLTD).unwrap();
    f.write_all(payload).unwrap();
}

fn main() {
    let base = std::env::temp_dir().join(format!("blindkey-wc-example-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let sync = base.join("DropboxSim"); // name alone is not enough — path has no sync marker token
    let work = base.join("work");
    fs::create_dir_all(&sync).unwrap();
    fs::create_dir_all(&work).unwrap();

    let brick = sync.join("notes.vltd");
    write_fake_vltd(&brick, b"hello-blindfolder");
    println!("1. sync brick: {}", brick.display());

    let session = WorkingCopySession::checkout(CheckoutOpts {
        source: &brick,
        work_root: Some(&work),
        skip_idle_probe: true,
        cancel: None,
        progress: None,
    })
    .expect("checkout");
    println!(
        "2. checked out session {} → {}",
        session.id,
        session.work_path.display()
    );

    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&session.work_path)
            .unwrap();
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(b"\n+edited").unwrap();
    }
    let edited = fs::read(&session.work_path).unwrap();
    session.checkin().expect("checkin");
    assert_eq!(fs::read(&brick).unwrap(), edited);
    println!(
        "3. checkin ok — sync brick matches edited working copy ({} bytes)",
        edited.len()
    );

    // C101 demo
    write_fake_vltd(&brick, b"hello-blindfolder");
    let session2 = WorkingCopySession::checkout(CheckoutOpts {
        source: &brick,
        work_root: Some(&work),
        skip_idle_probe: true,
        cancel: None,
        progress: None,
    })
    .expect("checkout2");
    {
        let mut f = fs::OpenOptions::new().write(true).open(&brick).unwrap();
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(b"\nREMOTE").unwrap();
    }
    match session2.checkin() {
        Err(Error::WorkingCopyRemoteChanged) => {
            println!("4. C101 ok — checkin refused after remote change");
        }
        other => panic!("expected WorkingCopyRemoteChanged, got {other:?}"),
    }

    let _ = fs::remove_dir_all(&base);
    println!("volume_working_copy example: PASS");
}
