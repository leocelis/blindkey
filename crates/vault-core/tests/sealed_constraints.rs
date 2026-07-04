//! UC-23 distributed constraint tests (A15–A22) — complements `uc23_joint_satisfaction.rs`.

use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use vault_core::format::file_archive::validate_inner_path;
use vault_core::pad::PadMode;
use vault_core::sealed::{
    SealOptions, SealedContainer, SealedIoOpts, SealedUnlock, SEALED_OPEN_ERROR,
};
use vault_core::{Error, MAGIC_VLTF};

const PASSWORD: &[u8] = b"sealed-constraints-password";

fn weak_opts() -> SealOptions {
    SealOptions {
        allow_weak_kdf: true,
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
        pad_mode: PadMode::Padme,
    }
}

fn temp_base(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vault-sealed-{tag}-{}", std::process::id()))
}

/// Best-effort RSS on Linux (`VmRSS`); returns 0 when unavailable (macOS CI skips delta assert).
fn current_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(kb) = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    let _ = ();
    0
}

#[test]
fn c63_cancel_during_seal_aborts() {
    let base = temp_base("cancel-seal");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    fs::write(base.join("a.txt"), b"x").unwrap();
    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let cancel = AtomicBool::new(true);
    let mut io = SealedIoOpts {
        cancel: Some(&cancel),
        progress: None,
    };
    let err = container
        .seal_paths_with(&[base.join("a.txt").as_path()], &mut io)
        .unwrap_err();
    assert!(matches!(err, Error::SealedOpenFailed | Error::Io(_)));
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c63_rss_ceiling_large_on_disk_seal() {
    if cfg!(debug_assertions) {
        return;
    }
    let base = temp_base("rss");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let big = base.join("large.bin");
    const FILE_MB: u64 = 32;
    const CHUNK: usize = 1024 * 1024;
    let total = (FILE_MB * 1024 * 1024) as usize;
    {
        let mut f = fs::File::create(&big).unwrap();
        use std::io::Write;
        let block = vec![0xCDu8; CHUNK];
        let mut written = 0usize;
        while written < total {
            let n = CHUNK.min(total - written);
            f.write_all(&block[..n]).unwrap();
            written += n;
        }
    }

    let before = current_rss_bytes();
    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let _blob = container.seal_paths(&[big.as_path()]).unwrap();
    let after = current_rss_bytes();

    if before > 0 && after > before {
        let growth = after - before;
        let file_bytes = total as u64;
        assert!(
            growth < file_bytes / 2,
            "A20/C63: RSS grew by {growth} bytes during {FILE_MB} MiB on-disk seal (streaming \
             should stay well below input size)"
        );
        assert!(
            growth < 256 * 1024 * 1024,
            "A20/C63: RSS growth {growth} exceeds 256 MiB ceiling"
        );
    }

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c63_single_kdf_create_per_seal_operation() {
    // One `create()` → one Argon2id derivation; `seal_paths` does not re-derive.
    let base = temp_base("single-kdf");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    fs::write(base.join("one.txt"), b"1").unwrap();
    fs::write(base.join("two.txt"), b"2").unwrap();
    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let blob = container
        .seal_paths(&[
            base.join("one.txt").as_path(),
            base.join("two.txt").as_path(),
        ])
        .unwrap();
    SealedContainer::open_to_dir(
        &blob,
        &SealedUnlock::password_only(PASSWORD),
        &base.join("out"),
    )
    .unwrap();
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn round_trip_matrix_file_dir_and_nested() {
    let base = temp_base("matrix");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("nested/deep")).unwrap();
    fs::write(base.join("top.txt"), b"top").unwrap();
    fs::write(base.join("nested/mid.txt"), b"mid").unwrap();
    fs::write(base.join("nested/deep/leaf.txt"), b"leaf").unwrap();

    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let blob = container
        .seal_paths(&[
            base.join("top.txt").as_path(),
            base.join("nested").as_path(),
        ])
        .unwrap();
    assert_eq!(&blob[0..4], MAGIC_VLTF);

    let out = base.join("extract");
    fs::create_dir_all(&out).unwrap();
    SealedContainer::open_to_dir(&blob, &SealedUnlock::password_only(PASSWORD), &out).unwrap();
    let peek =
        SealedContainer::peek_entries(&blob, &SealedUnlock::password_only(PASSWORD)).unwrap();
    assert_eq!(peek.len(), 3);
    assert_eq!(fs::read(out.join("top.txt")).unwrap(), b"top");
    assert_eq!(fs::read(out.join("mid.txt")).unwrap(), b"mid");
    assert_eq!(fs::read(out.join("deep/leaf.txt")).unwrap(), b"leaf");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c62_inner_paths_absent_from_outer_ciphertext() {
    let base = temp_base("c62");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let secret_name = "my-secret-filename.txt";
    fs::write(base.join(secret_name), b"data").unwrap();

    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let blob = container
        .seal_paths(&[base.join(secret_name).as_path()])
        .unwrap();

    for needle in [secret_name.as_bytes(), b"my-secret", b".txt"] {
        assert!(
            !blob.windows(needle.len()).any(|w| w == needle),
            "C62: plaintext path fragment leaked in outer blob"
        );
    }

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c64_body_corruption_matrix_uniform_error() {
    let base = temp_base("c64");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    fs::write(base.join("payload.bin"), vec![0xABu8; 4096]).unwrap();

    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let blob = container
        .seal_paths(&[base.join("payload.bin").as_path()])
        .unwrap();
    let header = vault_core::format::Header::parse_with_kind(
        &blob,
        Some(vault_core::ContainerKind::SealedFile),
    )
    .unwrap();
    let body_start = header.on_disk_len();
    assert!(body_start < blob.len());

    let offsets = [
        body_start,
        body_start + 1,
        body_start + 64,
        body_start + blob.len() / 2,
        blob.len() - 1,
    ];
    let mut messages = Vec::new();
    for off in offsets {
        let mut bad = blob.clone();
        bad[off] ^= 0x55;
        let err = SealedContainer::open_to_dir(
            &bad,
            &SealedUnlock::password_only(PASSWORD),
            &base.join("out"),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::SealedOpenFailed),
            "C64: body corruption at {off} must map to SealedOpenFailed, got {err:?}"
        );
        messages.push(err.to_string());
    }
    assert!(
        messages.iter().all(|m| m == SEALED_OPEN_ERROR),
        "C64: all body corruption sites must share one message: {messages:?}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c65_zip_slip_corpus_rejected_at_parse_and_validate() {
    const CORPUS: &[&str] = &[
        "../etc/passwd",
        "..",
        ".",
        "/etc/passwd",
        "foo/../../bar",
        "foo//bar",
        "foo\\bar",
        "",
        "valid/ok",
    ];
    for path in CORPUS {
        let v = validate_inner_path(path);
        if *path == "valid/ok" {
            assert!(v.is_ok(), "benign path should pass: {path}");
        } else {
            assert!(v.is_err(), "hostile path must fail validation: {path:?}");
        }
    }

    for hostile in ["../etc/passwd", "foo/../../etc/shadow", "..", ""] {
        assert!(
            validate_inner_path(hostile).is_err(),
            "hostile path must fail validation: {hostile:?}"
        );
    }
}

#[test]
fn c66_padme_buckets_equalize_nearby_sizes() {
    let base = temp_base("c66");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    fs::write(base.join("a.bin"), vec![b'a'; 100]).unwrap();
    fs::write(base.join("b.bin"), vec![b'b'; 105]).unwrap();

    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let a = container
        .seal_paths(&[base.join("a.bin").as_path()])
        .unwrap();
    let b = container
        .seal_paths(&[base.join("b.bin").as_path()])
        .unwrap();
    assert_eq!(a.len(), b.len(), "C66: Padmé should bucket nearby sizes");

    let no_pad = SealedContainer::create(
        PASSWORD,
        SealOptions {
            allow_weak_kdf: true,
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
            pad_mode: PadMode::None,
        },
    )
    .unwrap();
    let raw_a = no_pad.seal_paths(&[base.join("a.bin").as_path()]).unwrap();
    let raw_b = no_pad.seal_paths(&[base.join("b.bin").as_path()]).unwrap();
    assert_ne!(
        raw_a.len(),
        raw_b.len(),
        "without Padmé, outer sizes should differ for different payloads"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c63_large_payload_round_trips_without_full_file_buffer() {
    let base = temp_base("c63");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let big = base.join("large.bin");
    fs::write(&big, vec![0xCDu8; 128 * 1024]).unwrap();

    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let blob = container.seal_paths(&[big.as_path()]).unwrap();

    let out = base.join("out");
    fs::create_dir_all(&out).unwrap();
    SealedContainer::open_to_dir(&blob, &SealedUnlock::password_only(PASSWORD), &out).unwrap();
    assert_eq!(
        fs::metadata(out.join("large.bin")).unwrap().len(),
        128 * 1024
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c63_sealed_throughput_release_bench() {
    if cfg!(debug_assertions) {
        return;
    }
    let base = temp_base("throughput");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let size = 16 * 1024 * 1024;
    let big = base.join("bench.bin");
    fs::write(&big, vec![0xEFu8; size]).unwrap();

    let container = SealedContainer::create(PASSWORD, weak_opts()).unwrap();
    let t0 = std::time::Instant::now();
    let blob = container.seal_paths(&[big.as_path()]).unwrap();
    let seal_s = t0.elapsed().as_secs_f64();
    let seal_mib_s = (size as f64 / (1024.0 * 1024.0)) / seal_s.max(1e-9);

    let out = base.join("out");
    fs::create_dir_all(&out).unwrap();
    let t1 = std::time::Instant::now();
    SealedContainer::open_to_dir(&blob, &SealedUnlock::password_only(PASSWORD), &out).unwrap();
    let open_s = t1.elapsed().as_secs_f64();
    let open_mib_s = (size as f64 / (1024.0 * 1024.0)) / open_s.max(1e-9);

    let floor: f64 = std::env::var("VAULT_SEAL_BENCH_MIN_MIB_S")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20.0);

    assert!(
        seal_mib_s >= floor && open_mib_s >= floor,
        "A23: seal={seal_mib_s:.1} MiB/s open={open_mib_s:.1} MiB/s (floor {floor}; set \
         VAULT_SEAL_BENCH_MIN_MIB_S=400 on reference hardware per UC-23 §3.5)"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn c61_reuses_existing_crypto_stack_only() {
    let sealed_src =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sealed.rs")).unwrap();
    for banned in ["use ring", "aes_gcm::", "openssl::", "rustls::", "zip::"] {
        assert!(
            !sealed_src.contains(banned),
            "C61: sealed.rs must not introduce `{banned}`"
        );
    }
    for needle in [
        "crate::crypto::",
        "envelope::",
        "block_stream::",
        "StreamEncryptor",
    ] {
        assert!(
            sealed_src.contains(needle),
            "C61: sealed.rs must reuse existing crypto/format stack ({needle})"
        );
    }
}
