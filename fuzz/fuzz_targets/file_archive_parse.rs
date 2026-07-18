//! Fuzz the sealed file-archive TLV parser (UC-23 / C30 / C65).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = blindkey_core::format::file_archive::parse_all(data);
    let mut inc = blindkey_core::format::file_archive::ArchiveIncrementalParser::new();
    let _ = inc.feed(data);
    let _ = inc.finish();
});
