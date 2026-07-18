//! Fuzz the header parser on arbitrary bytes (constraints C30, C7–C9).
//!
//! Invariant: parsing untrusted input must never panic, hang, or over-allocate. It may only return
//! `Ok` or a `blindkey_core::Error`. Run: `cargo +nightly fuzz run header_parse`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic or allocate unbounded memory on any input, including hostile KDF params.
    let _ = blindkey_core::format::Header::parse(data);
});
