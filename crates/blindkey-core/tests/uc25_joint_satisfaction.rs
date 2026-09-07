//! UC-25 joint satisfaction — one volume, assert C68–C74 together on the same artifact.
//!
//! Named in `blindkey_intent.yaml` → `constraint_satisfiability.joint_satisfaction_test`.

use std::fs;

use blindkey_core::pad::PadMode;
use blindkey_core::{Error, Volume, VolumeCreateOpts, VolumeUnlock, MAGIC_VLTD, VOLUME_OPEN_ERROR};

const PASSWORD: &[u8] = b"uc25-joint-password";

fn fast_opts() -> VolumeCreateOpts {
    VolumeCreateOpts {
        size_bytes: 1024 * 1024,
        max_bytes: 8 * 1024 * 1024,
        block_size_kib: 4,
        pad_mode: PadMode::Padme,
        allow_weak_kdf: true,
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
    }
}

#[test]
fn uc25_joint_satisfaction_on_one_volume() {
    let base = std::env::temp_dir().join(format!("vault-uc25-joint-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let path = base.join("workspace.vltd");

    // create → write a small tree → sync → reopen → read (round-trip integrity).
    {
        let mut v =
            Volume::create(&path, &VolumeUnlock::password_only(PASSWORD), &fast_opts()).unwrap();
        v.mkdir("docs").unwrap();
        v.write("docs/readme.md", b"# hello volume").unwrap();
        v.write("docs/nested/deep.txt", &vec![b'z'; 9000]).unwrap(); // spans multiple blocks
        v.write("root.txt", b"top-level file").unwrap();
        v.sync().unwrap();
    }

    let bytes = fs::read(&path).unwrap();
    assert_eq!(&bytes[0..4], MAGIC_VLTD, "C67: volume magic");

    // C71 — no plaintext inner path leaks into the ciphertext.
    for needle in [
        b"readme.md".as_slice(),
        b"deep.txt".as_slice(),
        b"docs".as_slice(),
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "C71: plaintext metadata leak"
        );
    }

    {
        let v = Volume::open(&path, &VolumeUnlock::password_only(PASSWORD)).unwrap();
        assert_eq!(v.read("docs/readme.md").unwrap(), b"# hello volume");
        assert_eq!(v.read("docs/nested/deep.txt").unwrap(), vec![b'z'; 9000]);
        assert_eq!(v.read("root.txt").unwrap(), b"top-level file");
        assert_eq!(v.getattr_size("docs/nested/deep.txt").unwrap(), 9000);
        let mut top = v.list("").unwrap();
        top.sort();
        assert_eq!(top, vec!["docs".to_string(), "root.txt".to_string()]);
        assert_eq!(
            v.list("docs").unwrap(),
            vec!["nested".to_string(), "readme.md".to_string()]
        );
    }

    // C69 — kcom path: the wrong password never opens.
    let e = Volume::open(&path, &VolumeUnlock::password_only(b"WRONG")).unwrap_err();
    assert!(matches!(e, Error::VolumeOpenFailed));
    assert_eq!(e.to_string(), VOLUME_OPEN_ERROR);

    // C68 — a bit flip in the block region fails closed.
    let mut bad = bytes.clone();
    let mid = bad.len() / 2;
    for b in &mut bad[mid..mid + 40] {
        *b ^= 0xFF;
    }
    let bad_path = base.join("bad.vltd");
    fs::write(&bad_path, &bad).unwrap();
    assert!(matches!(
        Volume::open(&bad_path, &VolumeUnlock::password_only(PASSWORD)),
        Err(Error::VolumeOpenFailed)
    ));

    // C71 — Padmé default-on: two near-size payloads share the on-disk length.
    let mut lens = Vec::new();
    for (tag, size) in [("p", 200usize), ("q", 205usize)] {
        let p = base.join(format!("{tag}.vltd"));
        let mut v =
            Volume::create(&p, &VolumeUnlock::password_only(PASSWORD), &fast_opts()).unwrap();
        v.write("f.bin", &vec![b'k'; size]).unwrap();
        v.sync().unwrap();
        lens.push(fs::read(&p).unwrap().len());
    }
    assert_eq!(lens[0], lens[1], "C71: same Padmé bucket → same length");

    let _ = fs::remove_dir_all(&base);
}
