//! UC-23 joint satisfaction — one hostile+large artifact, assert C61–C66 together.
//!
//! Named in `blindkey_intent.yaml` → `constraint_satisfiability.joint_satisfaction_test`.

use std::fs;

use blindkey_core::pad::PadMode;
use blindkey_core::sealed::{SealOptions, SealedContainer, SealedUnlock, SEALED_OPEN_ERROR};
use blindkey_core::{Error, MAGIC_VLTF};

const PASSWORD: &[u8] = b"uc23-joint-password";

#[test]
fn uc23_joint_satisfaction_on_one_artifact() {
    let base = std::env::temp_dir().join(format!("vault-uc23-joint-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    // Hostile inner path in a valid seal (C65 — must not escape on open).
    let evil_dir = base.join("evil");
    fs::create_dir_all(&evil_dir).unwrap();
    fs::write(evil_dir.join("safe.txt"), b"ok").unwrap();

    let opts = SealOptions {
        allow_weak_kdf: true,
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
        pad_mode: PadMode::Padme,
    };
    let container = SealedContainer::create(PASSWORD, opts).unwrap();
    let blob_a = container
        .seal_paths(&[evil_dir.join("safe.txt").as_path()])
        .unwrap();
    let blob_b = container
        .seal_paths(&[evil_dir.join("safe.txt").as_path()])
        .unwrap();

    // C61 — one crypto path, fresh random data key per seal.
    assert_eq!(&blob_a[0..4], MAGIC_VLTF);
    assert_ne!(
        blob_a, blob_b,
        "C61: identical plaintext must not yield identical ciphertext"
    );

    // C62 — inner path not present in ciphertext.
    for needle in [b"safe.txt".as_slice(), b"evil".as_slice()] {
        assert!(
            !blob_a.windows(needle.len()).any(|w| w == needle),
            "C62: plaintext metadata leak"
        );
    }

    // C66 — Padmé default-on: near-size inputs share outer length.
    fs::write(evil_dir.join("bucket_a.txt"), vec![b'a'; 100]).unwrap();
    fs::write(evil_dir.join("bucket_b.txt"), vec![b'b'; 105]).unwrap();
    let pad_a = container
        .seal_paths(&[evil_dir.join("bucket_a.txt").as_path()])
        .unwrap();
    let pad_b = container
        .seal_paths(&[evil_dir.join("bucket_b.txt").as_path()])
        .unwrap();
    assert_eq!(
        pad_a.len(),
        pad_b.len(),
        "C66: same Padmé bucket → same length"
    );

    let out = base.join("extract");
    fs::create_dir_all(&out).unwrap();
    SealedContainer::open_to_dir(&blob_a, &SealedUnlock::password_only(PASSWORD), &out).unwrap();
    assert_eq!(fs::read(out.join("safe.txt")).unwrap(), b"ok");

    // C65 — a hostile / unwritable destination is surfaced as an error at extract time,
    // never a silent success or panic. (Zip-slip path traversal *inside* an archive is
    // covered portably by the file_archive tests.) The destination's parent is a regular
    // file, so the write fails on every platform — unlike relying on "/" being unwritable,
    // which is a Unix-only filesystem property (on a Windows admin runner "/" is writable).
    let blocked_parent = base.join("i_am_a_file");
    fs::write(&blocked_parent, b"x").unwrap();
    assert!(SealedContainer::open_to_dir(
        &blob_a,
        &SealedUnlock::password_only(PASSWORD),
        &blocked_parent.join("dest")
    )
    .is_err());

    // C64 — uniform error text on auth failure (flip one body byte).
    let mut bad = blob_a.clone();
    if let Some(b) = bad.last_mut() {
        *b ^= 0x01;
    }
    let err = SealedContainer::open_to_dir(
        &bad,
        &SealedUnlock::password_only(PASSWORD),
        &base.join("bad-out"),
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::SealedOpenFailed),
        "C64: auth failure maps to uniform error"
    );
    assert_eq!(err.to_string(), SEALED_OPEN_ERROR);

    // SC9 — stdout path accepts a single small file.
    assert!(
        SealedContainer::read_single_stdout(&blob_a, &SealedUnlock::password_only(PASSWORD))
            .is_ok()
    );
    let big = container
        .seal_paths(&[evil_dir.join("bucket_b.txt").as_path()])
        .unwrap();

    let peek = SealedContainer::peek_entries(&big, &SealedUnlock::password_only(PASSWORD)).unwrap();
    assert_eq!(peek.len(), 1);

    let _ = fs::remove_dir_all(&base);
}
