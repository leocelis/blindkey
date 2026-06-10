//! Fuzz the HmacBlockStream reader (coverage-gap A4, constraint C10).
//!
//! Stresses block-size handling, the end-of-stream marker, and truncation/duplication resistance.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO(M2): call the block-stream reader once it exists:
    // let _ = vault_core::format::block_stream::read(_data);
});
