//! Fuzz the volume (`.vltd`) parse path on arbitrary bytes (UC-25 / constraints C74, C30).
//!
//! Two entry points a hostile `.vltd` reaches:
//!   1. `Header::parse_with_kind(_, Volume)` — the plaintext header branch (magic, KDF, stanzas).
//!   2. `Volume::open` — the full path: header → data-key unwrap → inner header → per-block AEAD →
//!      Merkle root → freshness anchor. On arbitrary bytes it must only return `Ok` or a
//!      `blindkey_core::Error` — never panic, hang, or over-allocate (C74 fail-closed, uniform).
//!
//! Run: `cargo +nightly fuzz run volume_block_parse`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header branch — bytes API, no I/O.
    let _ = blindkey_core::format::Header::parse_with_kind(
        data,
        Some(blindkey_core::ContainerKind::Volume),
    );

    // Full open path — Volume::open reads a file, so stage the fuzz bytes on a per-process temp
    // path (overwritten each iteration; never accumulates). Password is fixed; the point is that
    // hostile *bytes* never panic, not that they unlock.
    let path = std::env::temp_dir().join(format!("blindkey-fuzz-vol-{}.vltd", std::process::id()));
    if std::fs::write(&path, data).is_ok() {
        let _ = blindkey_core::Volume::open(
            &path,
            &blindkey_core::VolumeUnlock::password_only(b"fuzz-password"),
        );
    }
});
