//! FIDO2 salt + HKDF wrapping recipe (constraints **C6**, **C14**).
//!
//! Raw CTAP2 hmac-secret via libfido2 lands behind the `fido2` feature; the salt/HKDF math is
//! always compiled and tested here so the construction is locked before hardware FFI ships.

use blindkey_core::crypto::hkdf32;
use sha2::{Digest, Sha256};

/// Suffix mixed into the authenticator salt (constraint C6).
pub const FIDO2_SALT_SUFFIX: &[u8] = b"fido2-hw-v1";
/// HKDF info label for hardware wrapping keys (constraint C6 / C5 hw path).
pub const HW_WRAP_INFO: &[u8] = b"vault-hw-wrap-v1";

/// `SHA-256(vault_id || b"fido2-hw-v1")` — salt passed to the authenticator (C6/C14).
pub fn authenticator_salt(vault_id: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(vault_id);
    h.update(FIDO2_SALT_SUFFIX);
    h.finalize().into()
}

/// Derive the stanza wrapping key from PRF output — **never** use PRF bytes directly (C6).
pub fn wrapping_key(prf_output: &[u8; 32], vault_id: &[u8; 16]) -> [u8; 32] {
    hkdf32(prf_output, vault_id, HW_WRAP_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c6_authenticator_salt_is_sha256_vault_id_plus_suffix() {
        let vault_id = [0x22u8; 16];
        let salt = authenticator_salt(&vault_id);
        let mut h = Sha256::new();
        h.update(vault_id);
        h.update(b"fido2-hw-v1");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(salt, expected);
    }

    #[test]
    fn c6_prf_output_goes_through_hkdf_not_used_raw() {
        let vault_id = [0x33u8; 16];
        let prf = [0xABu8; 32];
        let key = wrapping_key(&prf, &vault_id);
        assert_ne!(key, prf);
        assert_eq!(key, hkdf32(&prf, &vault_id, HW_WRAP_INFO));
    }
}
