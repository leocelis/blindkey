//! UC-25 — C67 kind table (A1) + C68–C74 volume payload constraints.

use std::fs;

use blindkey_core::format::header::{Header, KdfParams, KDF_ALGORITHM_ARGON2ID};
use blindkey_core::format::stanza::{kind, Stanza};
use blindkey_core::pad::PadMode;
use blindkey_core::{
    ContainerKind, Error, Volume, VolumeCreateOpts, VolumeUnlock, FORMAT_VERSION, MAGIC, MAGIC_VLTD,
    MAGIC_VLTF, VOLUME_OPEN_ERROR,
};

const PASSWORD: &[u8] = b"uc25-volume-password";

/// Fast create opts for tests — below-floor KDF allowed, small blocks (mirrors sealed_constraints).
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

fn tmp(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vault-vol-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample_header(magic: [u8; 4]) -> Header {
    let mut h = Header {
        magic,
        format_version: FORMAT_VERSION,
        vault_id: [0x11; 16],
        kdf: KdfParams {
            algorithm: KDF_ALGORITHM_ARGON2ID,
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: [0x22; 32],
        },
        master_seed: [0x33; 32],
        nonce_prefix: [0x44; 16],
        stanzas: vec![Stanza {
            stanza_type: kind::PASSWORD,
            data: vec![0x55; 72],
        }],
        header_hash: [0; 32],
        header_hmac: [0; 32],
    };
    h.seal(&[0xAB; 32]);
    h
}

/// C67: `VLTD` is a distinct kind; magics stay pairwise distinct (ADR-0005 hygiene).
#[test]
fn c67_vltd_is_distinct_container_kind() {
    assert_eq!(MAGIC_VLTD, *b"VLTD");
    assert_eq!(ContainerKind::Volume.magic(), MAGIC_VLTD);
    assert_eq!(
        ContainerKind::from_magic(MAGIC_VLTD),
        Some(ContainerKind::Volume)
    );
    assert_ne!(MAGIC_VLTD, MAGIC);
    assert_ne!(MAGIC_VLTD, MAGIC_VLTF);
}

/// C67: wrong-kind open of `.vlt` / `.vltf` / `.vltd` → `WrongContainerKind`.
#[test]
fn c67_wrong_kind_open_matrix() {
    let vltd = sample_header(MAGIC_VLTD).serialize();
    let vltf = sample_header(MAGIC_VLTF).serialize();
    let vlt = sample_header(MAGIC).serialize();

    assert!(matches!(
        Header::parse_with_kind(&vltd, Some(ContainerKind::Vault)),
        Err(Error::WrongContainerKind)
    ));
    assert!(matches!(
        Header::parse_with_kind(&vltd, Some(ContainerKind::SealedFile)),
        Err(Error::WrongContainerKind)
    ));
    assert!(Header::parse_with_kind(&vltd, Some(ContainerKind::Volume)).is_ok());

    assert!(matches!(
        Header::parse_with_kind(&vltf, Some(ContainerKind::Volume)),
        Err(Error::WrongContainerKind)
    ));
    assert!(matches!(
        Header::parse_with_kind(&vlt, Some(ContainerKind::Volume)),
        Err(Error::WrongContainerKind)
    ));
}

/// C68: a one-byte flip in the AEAD data-block region fails closed on open.
#[test]
fn c68_block_aead_bitflip_fails() {
    let dir = tmp("c68");
    let path = dir.join("v.vltd");
    {
        let mut v = Volume::create(&path, &VolumeUnlock::password_only(PASSWORD), &fast_opts()).unwrap();
        v.write("notes/todo.txt", b"buy milk and eggs").unwrap();
        v.sync().unwrap();
    }

    let mut bytes = fs::read(&path).unwrap();
    assert!(bytes.len() > 700);
    // XOR a 40-byte run in the middle — guaranteed to hit block ciphertext, not padding/nonce.
    let mid = bytes.len() / 2;
    for b in &mut bytes[mid..mid + 40] {
        *b ^= 0xFF;
    }
    fs::write(&path, &bytes).unwrap();

    let err = Volume::open(&path, &VolumeUnlock::password_only(PASSWORD)).unwrap_err();
    assert!(matches!(err, Error::VolumeOpenFailed));
    let _ = fs::remove_dir_all(&dir);
}

/// C69: an unlock with the wrong key material fails the commitment check → uniform open error.
#[test]
fn c69_kcom_mismatch_fails() {
    let dir = tmp("c69");
    let path = dir.join("v.vltd");
    {
        let mut v = Volume::create(&path, &VolumeUnlock::password_only(PASSWORD), &fast_opts()).unwrap();
        v.write("secret.txt", b"top secret").unwrap();
        v.sync().unwrap();
    }
    let err = Volume::open(&path, &VolumeUnlock::password_only(b"wrong-password")).unwrap_err();
    assert!(matches!(err, Error::VolumeOpenFailed));
    let _ = fs::remove_dir_all(&dir);
}

/// C70: a stale (rolled-back) disk state fails the freshness anchor; `trust_anchor` re-blesses it,
/// and `open_ignoring_anchor` bypasses the check for a new-device flow.
#[test]
fn c70_anchor_mismatch_and_trust_anchor() {
    let dir = tmp("c70");
    let path = dir.join("v.vltd");
    let old = dir.join("v.old");

    {
        let mut v = Volume::create(&path, &VolumeUnlock::password_only(PASSWORD), &fast_opts()).unwrap();
        v.write("a.txt", b"first").unwrap();
        v.sync().unwrap();
    }
    // Snapshot the older-but-valid state.
    fs::copy(&path, &old).unwrap();

    {
        let mut v = Volume::open(&path, &VolumeUnlock::password_only(PASSWORD)).unwrap();
        v.write("b.txt", b"second").unwrap();
        v.sync().unwrap();
        v.trust_anchor().unwrap(); // anchor now pinned to the newer version
    }

    // Restore the stale copy — a sync backend serving an older version.
    fs::copy(&old, &path).unwrap();
    let err = Volume::open(&path, &VolumeUnlock::password_only(PASSWORD)).unwrap_err();
    assert!(matches!(err, Error::VolumeAnchorMismatch));

    // The new-device / trust flow can still open it and re-bless.
    let v = Volume::open_ignoring_anchor(&path, &VolumeUnlock::password_only(PASSWORD)).unwrap();
    assert_eq!(v.read("a.txt").unwrap(), b"first");
    v.trust_anchor().unwrap();
    drop(v);

    // After trusting, a normal open of the same state succeeds.
    let v = Volume::open(&path, &VolumeUnlock::password_only(PASSWORD)).unwrap();
    assert_eq!(v.read("a.txt").unwrap(), b"first");
    let _ = fs::remove_dir_all(&dir);
}

/// C71: Padmé default-on — near-size payloads share an on-disk length, and no plaintext path leaks.
#[test]
fn c71_padme_default_and_no_plaintext_paths() {
    assert_eq!(VolumeCreateOpts::default().pad_mode, PadMode::Padme);

    let dir = tmp("c71");
    let secret_name = "super_secret_filename.txt";

    let mut lens = Vec::new();
    for (tag, size) in [("a", 100usize), ("b", 105usize)] {
        let path = dir.join(format!("{tag}.vltd"));
        let mut v = Volume::create(&path, &VolumeUnlock::password_only(PASSWORD), &fast_opts()).unwrap();
        v.write(secret_name, &vec![b'x'; size]).unwrap();
        v.sync().unwrap();
        let bytes = fs::read(&path).unwrap();
        let needle = secret_name.as_bytes();
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "C71: inner path must not appear in ciphertext"
        );
        lens.push(bytes.len());
    }
    assert_eq!(lens[0], lens[1], "C71: same Padmé bucket → same on-disk length");
    let _ = fs::remove_dir_all(&dir);
}

/// C72: unlock Debug redacts secrets; close syncs and drops keys without panic (mount hygiene core).
#[test]
fn c72_debug_redacts_and_close_ok() {
    let unlock = VolumeUnlock::password_only(PASSWORD);
    let dbg = format!("{unlock:?}");
    assert!(dbg.contains("[redacted]"));
    assert!(!dbg.contains(std::str::from_utf8(PASSWORD).unwrap()));

    let dir = tmp("c72");
    let path = dir.join("v.vltd");
    let mut v = Volume::create(&path, &unlock, &fast_opts()).unwrap();
    v.write("x.txt", b"hello").unwrap();
    v.close().unwrap();
    let v = Volume::open(&path, &unlock).unwrap();
    assert_eq!(v.read("x.txt").unwrap(), b"hello");
    v.close().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// C73: product docs state live cloud sync of RW `.vltd` is unsupported (Seal CTA path).
#[test]
fn c73_docs_forbid_live_cloud_sync() {
    let threat = include_str!("../../../docs/THREAT_MODEL.md");
    let cli = include_str!("../../../docs/CLI.md");
    let blob = format!("{threat}\n{cli}").to_lowercase();
    assert!(
        blob.contains("unsupported") || blob.contains("not supported"),
        "C73: docs must mark live cloud sync unsupported"
    );
    assert!(
        blob.contains("seal") && (blob.contains("dropbox") || blob.contains("cloud") || blob.contains("sync")),
        "C73: docs must point at seal / cloud residual"
    );
}

/// C74: auth/parse failures collapse to the single uniform error string (no format oracle).
#[test]
fn c74_uniform_errors() {
    let dir = tmp("c74");
    let path = dir.join("v.vltd");
    {
        let mut v = Volume::create(&path, &VolumeUnlock::password_only(PASSWORD), &fast_opts()).unwrap();
        v.write("f.txt", b"data").unwrap();
        v.sync().unwrap();
    }

    // Wrong password.
    let e1 = Volume::open(&path, &VolumeUnlock::password_only(b"nope")).unwrap_err();
    assert!(matches!(e1, Error::VolumeOpenFailed));
    assert_eq!(e1.to_string(), VOLUME_OPEN_ERROR);

    // Tampered body.
    let mut bytes = fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    for b in &mut bytes[mid..mid + 40] {
        *b ^= 0x5A;
    }
    fs::write(&path, &bytes).unwrap();
    let e2 = Volume::open(&path, &VolumeUnlock::password_only(PASSWORD)).unwrap_err();
    assert!(matches!(e2, Error::VolumeOpenFailed));
    assert_eq!(e2.to_string(), VOLUME_OPEN_ERROR);
    let _ = fs::remove_dir_all(&dir);
}
