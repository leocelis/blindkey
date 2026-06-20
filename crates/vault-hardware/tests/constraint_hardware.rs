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
    use vault_hardware::fido2_salt::{authenticator_salt, wrapping_key, HW_WRAP_INFO};
    let vault_id = [0x44u8; 16];
    let prf = [0x55u8; 32];
    let salt = authenticator_salt(&vault_id);
    assert_ne!(salt, [0u8; 32]);
    let key = wrapping_key(&prf, &vault_id);
    assert_ne!(key, prf);
    assert_eq!(key, vault_core::crypto::hkdf32(&prf, &vault_id, HW_WRAP_INFO));
}

#[test]
fn c15_tpm_policy_strings_present() {
    use vault_hardware::tpm_policy::{ENROLL_COMMAND, PCR_MISMATCH_MESSAGE, RE_ENROLL_COMMAND};
    assert!(PCR_MISMATCH_MESSAGE.contains(RE_ENROLL_COMMAND));
    assert_eq!(ENROLL_COMMAND, "vault enroll-tpm");
}
