//! Fuzz the full vault-open path on arbitrary bytes (UC-10 / constraint C30).
//!
//! `Vault::open` is the entry point a malicious sync backend's file reaches: header parse → KDF
//! ceiling check → stanza unwrap → header HMAC → block de-frame → STREAM decrypt → payload parse.
//! On arbitrary bytes it must only ever return `Ok` or a `vault_core::Error` — never panic, hang,
//! or over-allocate. (A structured seed corpus drives it deeper than random bytes.)
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vault_core::Vault::open(data, b"fuzz-password");
});
