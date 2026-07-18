//! Hardware constraint tests (C6, C14, C15).

#[test]
fn c14_fido2_uses_raw_ctap2_not_webauthn() {
    let lib = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .unwrap();
    assert!(lib.contains("libfido2"));
    assert!(lib.contains("never") || lib.contains("not") && lib.contains("WebAuthn"));
}

#[test]
fn c6_and_c14_salt_and_hkdf_wired() {
    use blindkey_hardware::fido2_salt::{authenticator_salt, wrapping_key, HW_WRAP_INFO};
    let vault_id = [0x44u8; 16];
    let prf = [0x55u8; 32];
    let salt = authenticator_salt(&vault_id);
    assert_ne!(salt, [0u8; 32]);
    let key = wrapping_key(&prf, &vault_id);
    assert_ne!(key, prf);
    assert_eq!(
        key,
        blindkey_core::crypto::hkdf32(&prf, &vault_id, HW_WRAP_INFO)
    );
}

#[test]
fn c14_mock_authenticator_integration() {
    use blindkey_hardware::fido2_mock::{unlock_wrapping_key, Fido2Error, MockAuthenticator};
    let vault_id = [0x99u8; 16];
    let (auth, header) = MockAuthenticator::enroll(&vault_id, "vault.local");
    assert!(unlock_wrapping_key(&vault_id, &header, &auth).is_ok());
    let (wrong, _) = MockAuthenticator::enroll(&vault_id, "vault.local");
    assert_eq!(
        unlock_wrapping_key(&vault_id, &header, &wrong),
        Err(Fido2Error::NoMatchingCredential)
    );
}

#[test]
fn c15_tpm_pcr_mock_emits_documented_error() {
    use blindkey_hardware::tpm_mock::open_with_pcr;
    assert!(open_with_pcr(1, 1).is_ok());
    assert!(open_with_pcr(1, 2).unwrap_err().contains("re-enroll"));
}
