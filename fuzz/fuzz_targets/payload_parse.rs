//! Fuzz the decrypted-payload TLV parser (coverage-gap A4 / constraint C30; constraints C18, C19).
//!
//! The payload parser runs on authenticated plaintext, but must still never panic, hang, or
//! over-allocate on arbitrary bytes — only return `Ok` or a `blindkey_core::Error`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = blindkey_core::format::Payload::parse(data);
});
