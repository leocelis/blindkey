//! Mock CTAP2 authenticator for tests (constraint **C14** — "real or mocked authenticator").
//!
//! Production libfido2 integration lands behind the `fido2` feature in M7; this module lets the
//! salt/HKDF/enroll/unlock contract be verified without hardware.

use getrandom::getrandom;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::fido2_salt::{authenticator_salt, wrapping_key};

type HmacSha256 = Hmac<Sha256>;

/// On-disk FIDO2 stanza header fields (constraint C14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2StanzaHeader {
    pub credential_id: Vec<u8>,
    pub relying_party_id: String,
    pub salt_hash: [u8; 32],
}

/// Simulated FIDO2 device holding one credential.
pub struct MockAuthenticator {
    credential_id: Vec<u8>,
    prf_seed: Zeroizing<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fido2Error {
    NoMatchingCredential,
}

impl MockAuthenticator {
    /// Enroll a mock credential for `vault_id` (returns header stored in the vault file).
    pub fn enroll(vault_id: &[u8; 16], relying_party_id: &str) -> (Self, Fido2StanzaHeader) {
        let salt_hash = authenticator_salt(vault_id);
        let mut credential_id = vec![0u8; 32];
        getrandom(&mut credential_id).expect("os rng");
        let mut prf_seed = [0u8; 32];
        getrandom(&mut prf_seed).expect("os rng");
        let auth = Self {
            credential_id: credential_id.clone(),
            prf_seed: Zeroizing::new(prf_seed),
        };
        let header = Fido2StanzaHeader {
            credential_id,
            relying_party_id: relying_party_id.to_string(),
            salt_hash,
        };
        (auth, header)
    }

    /// CTAP2 hmac-secret mock: deterministic 32-byte output per credential + salt.
    pub fn prf_output(&self, salt: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&*self.prf_seed).expect("hmac key size");
        mac.update(salt);
        mac.finalize().into_bytes().into()
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

/// Unlock path: verify credential, derive wrapping key via C6 recipe.
pub fn unlock_wrapping_key(
    vault_id: &[u8; 16],
    header: &Fido2StanzaHeader,
    auth: &MockAuthenticator,
) -> Result<[u8; 32], Fido2Error> {
    if auth.credential_id != header.credential_id {
        return Err(Fido2Error::NoMatchingCredential);
    }
    if header.salt_hash != authenticator_salt(vault_id) {
        return Err(Fido2Error::NoMatchingCredential);
    }
    let prf = auth.prf_output(&header.salt_hash);
    Ok(wrapping_key(&prf, vault_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido2_salt::HW_WRAP_INFO;
    use blindkey_core::crypto::hkdf32;

    #[test]
    fn c14_mock_enroll_unlock_roundtrip() {
        let vault_id = [0x11u8; 16];
        let (auth, header) = MockAuthenticator::enroll(&vault_id, "vault.local");
        assert_eq!(header.salt_hash, authenticator_salt(&vault_id));
        let key = unlock_wrapping_key(&vault_id, &header, &auth).unwrap();
        let prf = auth.prf_output(&header.salt_hash);
        assert_eq!(key, hkdf32(&prf, &vault_id, HW_WRAP_INFO));
    }

    #[test]
    fn c14_wrong_credential_is_clear_error() {
        let vault_id = [0x22u8; 16];
        let (auth, header) = MockAuthenticator::enroll(&vault_id, "vault.local");
        let (other, _) = MockAuthenticator::enroll(&vault_id, "vault.local");
        assert_eq!(
            unlock_wrapping_key(&vault_id, &header, &other),
            Err(Fido2Error::NoMatchingCredential)
        );
        assert!(auth.credential_id() != other.credential_id());
    }
}
