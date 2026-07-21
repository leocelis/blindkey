//! Fuzz the KeePassXC CSV importer (UC-12 / C30).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = blindkey_core::import::parse_keepassxc_csv(text);
    }
});
