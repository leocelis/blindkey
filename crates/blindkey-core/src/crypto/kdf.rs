//! Argon2id key derivation from the master password (constraint C2).
//!
//! Produces the 32-byte IKM that the envelope (C5) feeds into HKDF to get the password stanza's
//! wrapping key — this output is **not** used as a key directly. The password is normalized to
//! Unicode **NFC** first, so the same typed password derives the same key on every platform (macOS
//! IMEs commonly emit NFD where Linux emits NFC). Floor/ceiling validation lives in
//! [`super::validate_kdf_params`]; this function assumes the params are already in range.

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::Secret;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const OUTPUT_LEN: usize = 32;

/// Derive the 32-byte Argon2id output from `password` and `salt` (constraint C2).
///
/// `password` is NFC-normalized before hashing (invalid UTF-8 is hashed as-is — a password that is
/// not text cannot be normalized). Returns a `Secret` so the derived bytes are not accidentally
/// logged or cloned; the transient stack buffer is zeroized.
pub fn argon2id(
    password: &[u8],
    salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Secret<[u8; OUTPUT_LEN]>> {
    // NFC normalization (C2). Keep the normalized form in a zeroizing buffer.
    let normalized: Zeroizing<Vec<u8>> = match core::str::from_utf8(password) {
        Ok(s) => Zeroizing::new(s.nfc().collect::<String>().into_bytes()),
        Err(_) => Zeroizing::new(password.to_vec()),
    };

    let params = Params::new(m_cost, t_cost, p_cost, Some(OUTPUT_LEN))
        .map_err(|_| Error::KdfParamsOutOfRange)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; OUTPUT_LEN];
    argon
        .hash_password_into(&normalized, salt, &mut out)
        .map_err(|_| Error::Crypto)?;
    let secret = Secret::new(out);
    out.zeroize(); // wipe the transient stack copy left behind by the move-into-Secret
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    // Small, fast params for tests (m >= 8*p holds); real vaults use the C2 defaults.
    const M: u32 = 64;
    const T: u32 = 1;
    const P: u32 = 1;

    #[test]
    fn deterministic_for_same_inputs() {
        let salt = [7u8; 32];
        let a = argon2id(b"correct horse", &salt, M, T, P).unwrap();
        let b = argon2id(b"correct horse", &salt, M, T, P).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
        assert_eq!(a.expose_secret().len(), 32);
    }

    #[test]
    fn different_salt_changes_output() {
        let a = argon2id(b"pw", &[1u8; 32], M, T, P).unwrap();
        let b = argon2id(b"pw", &[2u8; 32], M, T, P).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn nfc_and_nfd_forms_derive_identical_keys() {
        // C2: "é" as U+00E9 (NFC) vs "e" + U+0301 combining acute (NFD) → same key.
        let salt = [9u8; 32];
        let nfc = "caf\u{00e9}".as_bytes();
        let nfd = "cafe\u{0301}".as_bytes();
        assert_ne!(nfc, nfd); // the raw bytes differ
        let a = argon2id(nfc, &salt, M, T, P).unwrap();
        let b = argon2id(nfd, &salt, M, T, P).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }
}
