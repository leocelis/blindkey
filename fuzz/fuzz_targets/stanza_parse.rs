//! Fuzz stanza-record parsing (coverage-gap A4, constraint C5).
//!
//! Stresses bounded-length handling: `stanza_count <= 8`, `stanza_data_len <= 4096`, no overflow.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO(M2): call the stanza parser once it exists:
    // let _ = vault_core::format::stanza::parse(_data);
});
