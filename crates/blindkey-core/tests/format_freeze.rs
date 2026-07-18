//! ADR-0005: format_version 1 is the frozen on-disk format constant.

use blindkey_core::format::Header;
use blindkey_core::{Vault, FORMAT_VERSION};

#[test]
fn format_version_constant_is_one() {
    assert_eq!(FORMAT_VERSION, 1, "frozen format per ADR-0005");
}

#[test]
fn new_vault_serializes_format_version_one() {
    let mut v = Vault::create_default(b"integration-test-password!!").expect("create");
    let bytes = v.save().expect("save");
    let header = Header::parse(&bytes).expect("parse header");
    assert_eq!(header.format_version, FORMAT_VERSION);
}
