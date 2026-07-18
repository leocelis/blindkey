//! Data key and multi-stanza envelope — constraints **C4–C6**.
//!
//! A random 256-bit data key is wrapped by one or more independent stanzas (OR model): any single
//! valid stanza unlocks the vault. The password stanza is always present; hardware/OS-keystore
//! stanzas are additive, so losing a hardware factor never locks the user out (constraint C5).
//!
//! This module implements the **password** stanza (the always-present path). Hardware stanzas
//! (C6/C14/C15) share the same wrapping recipe — `wrapping_key = HKDF(ikm, salt=vault_id, info)`
//! then XChaCha20-Poly1305 seal of the data key — implemented for password, FIDO2, and TPM paths.

pub mod fido2;
pub mod tpm;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, Secret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, kdf};
use crate::format::stanza::{kind, Stanza};
use crate::memory::DataKey;
use crate::{Error, Result};

/// HKDF info label for the password stanza's wrapping key (constraint C5 — exact bytes matter).
const PW_WRAP_INFO: &[u8] = b"vault-pw-wrap-v1";
/// HKDF info label for the composite password+YubiKey 2FA wrapping key (UC-09 AND model).
const TWOFA_WRAP_INFO: &[u8] = b"vault-2fa-wrap-v1";
/// HKDF info label for the composite password+keyfile 2FA wrapping key (domain-separated).
const KEYFILE_WRAP_INFO: &[u8] = b"vault-keyfile-wrap-v1";
/// XChaCha20-Poly1305 nonce length (constraint C5 stanza layout).
const WRAP_NONCE_LEN: usize = 24;
/// Wrapped data-key length: 32-byte key + 16-byte Poly1305 tag (constraint C5).
pub(crate) const WRAPPED_KEY_LEN: usize = 48;
/// Length of the YubiKey challenge stored in a 2FA stanza (sent to the key on every unlock).
const CHALLENGE_LEN: usize = 32;

/// The kind of secret a stanza wraps the data key with (constraint C5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StanzaType {
    /// Password stanza — Argon2id-derived. Always present.
    Password = 1,
    /// FIDO2 hmac-secret / PRF (constraint C6, C14).
    Fido2 = 2,
    /// YubiKey HMAC-SHA1 challenge-response.
    YubiKey = 3,
    /// TPM 2.0 PCR-sealed (constraint C15).
    Tpm = 4,
    /// macOS Secure Enclave.
    Keychain = 5,
    /// Windows DPAPI.
    Dpapi = 6,
}

/// Generate a fresh random data key (constraint C4): 256-bit, CSPRNG, never derived from a password.
pub fn generate_data_key() -> Result<DataKey> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|_| Error::Crypto)?;
    let secret = Secret::new(key);
    key.zeroize();
    Ok(secret)
}

/// Derive the password stanza's wrapping key: `HKDF(ikm=Argon2id(pw,salt), salt=vault_id, info)`.
fn password_wrapping_key(
    password: &[u8],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32]> {
    let ikm = kdf::argon2id(password, salt, m_cost, t_cost, p_cost)?;
    Ok(crypto::hkdf32(ikm.expose_secret(), vault_id, PW_WRAP_INFO))
}

/// Wrap `data_key` in a new password stanza (constraint C5, password path).
///
/// `salt` is the header's Argon2id salt and `vault_id` the header's domain-separation id. The
/// returned stanza's `data` is `wrap_nonce[24] || wrapped_key[48]`.
pub fn wrap_password_stanza(
    data_key: &[u8; 32],
    password: &[u8],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Stanza> {
    let mut wrapping_key = password_wrapping_key(password, salt, vault_id, m_cost, t_cost, p_cost)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Crypto)?;

    let wrapped = cipher
        .encrypt(XNonce::from_slice(&nonce), &data_key[..])
        .map_err(|_| Error::Crypto)?;
    debug_assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);

    let mut data = Vec::with_capacity(WRAP_NONCE_LEN + WRAPPED_KEY_LEN);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&wrapped);
    Ok(Stanza {
        stanza_type: kind::PASSWORD,
        data,
    })
}

/// Unwrap the data key from a password stanza (constraint C5, password path).
///
/// On a wrong password (or any tamper of the wrapped key) the AEAD tag fails and this returns the
/// ambiguous [`Error::HeaderAuth`] — never an oracle distinguishing the two.
pub fn unwrap_password_stanza(
    stanza: &Stanza,
    password: &[u8],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<DataKey> {
    if stanza.stanza_type != kind::PASSWORD {
        return Err(Error::Crypto); // caller passed the wrong stanza kind
    }
    if stanza.data.len() < WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
        return Err(Error::HeaderAuth); // structurally short — treat as a failed unlock, no oracle
    }
    let (nonce, rest) = stanza.data.split_at(WRAP_NONCE_LEN);
    let wrapped = &rest[..WRAPPED_KEY_LEN];

    let mut wrapping_key = password_wrapping_key(password, salt, vault_id, m_cost, t_cost, p_cost)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), wrapped)
            .map_err(|_| Error::HeaderAuth)?,
    );
    if plaintext.len() != 32 {
        return Err(Error::HeaderAuth);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    let secret = Secret::new(key);
    key.zeroize();
    Ok(secret)
}

// ─── composite password + YubiKey 2FA stanza (UC-09 AND model) ──────────────────────────────────

/// Derive a composite-2FA wrapping key from **both** factors: `HKDF(ikm = Argon2id(pw) ‖ factor,
/// salt = vault_id, info)`. `factor` is the second factor's bytes (a YubiKey HMAC response or a
/// keyfile hash) and `info` domain-separates the factor type. Neither factor alone yields the key.
#[allow(clippy::too_many_arguments)]
fn composite_wrapping_key(
    password: &[u8],
    factor: &[u8],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    info: &[u8],
) -> Result<[u8; 32]> {
    let pw_ikm = kdf::argon2id(password, salt, m_cost, t_cost, p_cost)?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + factor.len()));
    ikm.extend_from_slice(pw_ikm.expose_secret());
    ikm.extend_from_slice(factor);
    Ok(crypto::hkdf32(&ikm, vault_id, info))
}

/// Wrap `data_key` in a composite **password + YubiKey** 2FA stanza (`kind::PW_YUBIKEY`).
///
/// `hw_response` is the YubiKey's HMAC-SHA1 response to `challenge`; `challenge` is stored in the
/// stanza so unlock can re-send it to the key. Both the password and the key are required to unwrap.
#[allow(clippy::too_many_arguments)] // mirrors `wrap_password_stanza` + the two extra 2FA inputs
pub fn wrap_yubikey_2fa_stanza(
    data_key: &[u8; 32],
    password: &[u8],
    hw_response: &[u8],
    challenge: &[u8; CHALLENGE_LEN],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Stanza> {
    let mut wrapping_key = composite_wrapping_key(
        password,
        hw_response,
        salt,
        vault_id,
        m_cost,
        t_cost,
        p_cost,
        TWOFA_WRAP_INFO,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Crypto)?;
    let wrapped = cipher
        .encrypt(XNonce::from_slice(&nonce), &data_key[..])
        .map_err(|_| Error::Crypto)?;
    debug_assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);

    let mut data = Vec::with_capacity(CHALLENGE_LEN + WRAP_NONCE_LEN + WRAPPED_KEY_LEN);
    data.extend_from_slice(challenge);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&wrapped);
    Ok(Stanza {
        stanza_type: kind::PW_YUBIKEY,
        data,
    })
}

/// Extract the stored challenge from a `kind::PW_YUBIKEY` stanza (sent to the key on unlock).
pub fn yubikey_challenge(stanza: &Stanza) -> Result<[u8; CHALLENGE_LEN]> {
    if stanza.stanza_type != kind::PW_YUBIKEY || stanza.data.len() < CHALLENGE_LEN {
        return Err(Error::HeaderAuth);
    }
    let mut c = [0u8; CHALLENGE_LEN];
    c.copy_from_slice(&stanza.data[..CHALLENGE_LEN]);
    Ok(c)
}

/// Unwrap the data key from a composite password+YubiKey 2FA stanza. A wrong password **or** a
/// wrong/absent YubiKey response yields the ambiguous [`Error::HeaderAuth`] (no oracle).
pub fn unwrap_yubikey_2fa_stanza(
    stanza: &Stanza,
    password: &[u8],
    hw_response: &[u8],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<DataKey> {
    if stanza.stanza_type != kind::PW_YUBIKEY {
        return Err(Error::Crypto);
    }
    if stanza.data.len() < CHALLENGE_LEN + WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
        return Err(Error::HeaderAuth);
    }
    let nonce = &stanza.data[CHALLENGE_LEN..CHALLENGE_LEN + WRAP_NONCE_LEN];
    let wrapped = &stanza.data
        [CHALLENGE_LEN + WRAP_NONCE_LEN..CHALLENGE_LEN + WRAP_NONCE_LEN + WRAPPED_KEY_LEN];

    let mut wrapping_key = composite_wrapping_key(
        password,
        hw_response,
        salt,
        vault_id,
        m_cost,
        t_cost,
        p_cost,
        TWOFA_WRAP_INFO,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), wrapped)
            .map_err(|_| Error::HeaderAuth)?,
    );
    if plaintext.len() != 32 {
        return Err(Error::HeaderAuth);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    let secret = Secret::new(key);
    key.zeroize();
    Ok(secret)
}

// ─── composite password + keyfile 2FA stanza (no hardware needed) ─────────────────────────────────

/// The 32-byte keyfile factor: SHA-256 of the keyfile's contents (any file works; random bytes are
/// strongest). A keyfile you keep on a separate device is a second factor without any hardware.
fn keyfile_factor(keyfile: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(keyfile);
    h.finalize().into()
}

/// Wrap `data_key` in a composite **password + keyfile** 2FA stanza (`kind::PW_KEYFILE`). Both the
/// password and the exact keyfile are required to unwrap. Layout: `wrap_nonce[24] || wrapped[48]`.
pub fn wrap_keyfile_2fa_stanza(
    data_key: &[u8; 32],
    password: &[u8],
    keyfile: &[u8],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Stanza> {
    let factor = keyfile_factor(keyfile);
    let mut wrapping_key = composite_wrapping_key(
        password,
        &factor,
        salt,
        vault_id,
        m_cost,
        t_cost,
        p_cost,
        KEYFILE_WRAP_INFO,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Crypto)?;
    let wrapped = cipher
        .encrypt(XNonce::from_slice(&nonce), &data_key[..])
        .map_err(|_| Error::Crypto)?;

    let mut data = Vec::with_capacity(WRAP_NONCE_LEN + WRAPPED_KEY_LEN);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&wrapped);
    Ok(Stanza {
        stanza_type: kind::PW_KEYFILE,
        data,
    })
}

/// Unwrap the data key from a composite password+keyfile stanza. A wrong password **or** wrong
/// keyfile yields the ambiguous [`Error::HeaderAuth`] (no oracle).
pub fn unwrap_keyfile_2fa_stanza(
    stanza: &Stanza,
    password: &[u8],
    keyfile: &[u8],
    salt: &[u8; 32],
    vault_id: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<DataKey> {
    if stanza.stanza_type != kind::PW_KEYFILE {
        return Err(Error::Crypto);
    }
    if stanza.data.len() < WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
        return Err(Error::HeaderAuth);
    }
    let (nonce, rest) = stanza.data.split_at(WRAP_NONCE_LEN);
    let wrapped = &rest[..WRAPPED_KEY_LEN];

    let factor = keyfile_factor(keyfile);
    let mut wrapping_key = composite_wrapping_key(
        password,
        &factor,
        salt,
        vault_id,
        m_cost,
        t_cost,
        p_cost,
        KEYFILE_WRAP_INFO,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), wrapped)
            .map_err(|_| Error::HeaderAuth)?,
    );
    if plaintext.len() != 32 {
        return Err(Error::HeaderAuth);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    let secret = Secret::new(key);
    key.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 32] = [0x11; 32];
    const VID: [u8; 16] = [0x22; 16];
    // small, fast Argon2id params for tests
    const M: u32 = 64;
    const T: u32 = 1;
    const P: u32 = 1;

    #[test]
    fn data_keys_are_random() {
        let a = generate_data_key().unwrap();
        let b = generate_data_key().unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn wrap_then_unwrap_round_trip() {
        let dk = [0xAB; 32];
        let stanza = wrap_password_stanza(&dk, b"open sesame", &SALT, &VID, M, T, P).unwrap();
        assert_eq!(stanza.stanza_type, kind::PASSWORD);
        assert_eq!(stanza.data.len(), WRAP_NONCE_LEN + WRAPPED_KEY_LEN);
        // Data key must not appear in the stanza bytes (C4: never stored in plaintext).
        assert!(stanza.data.windows(32).all(|w| w != dk));

        let out = unwrap_password_stanza(&stanza, b"open sesame", &SALT, &VID, M, T, P).unwrap();
        assert_eq!(out.expose_secret(), &dk);
    }

    #[test]
    fn wrong_password_is_ambiguous_error() {
        let dk = [0x01; 32];
        let stanza = wrap_password_stanza(&dk, b"right", &SALT, &VID, M, T, P).unwrap();
        assert!(matches!(
            unwrap_password_stanza(&stanza, b"wrong", &SALT, &VID, M, T, P),
            Err(Error::HeaderAuth)
        ));
    }

    #[test]
    fn wrong_vault_id_fails() {
        let dk = [0x02; 32];
        let stanza = wrap_password_stanza(&dk, b"pw", &SALT, &VID, M, T, P).unwrap();
        let other_vid = [0x33; 16];
        assert!(matches!(
            unwrap_password_stanza(&stanza, b"pw", &SALT, &other_vid, M, T, P),
            Err(Error::HeaderAuth)
        ));
    }

    #[test]
    fn tampered_wrapped_key_fails() {
        let dk = [0x03; 32];
        let mut stanza = wrap_password_stanza(&dk, b"pw", &SALT, &VID, M, T, P).unwrap();
        *stanza.data.last_mut().unwrap() ^= 0x01; // flip a tag byte
        assert!(matches!(
            unwrap_password_stanza(&stanza, b"pw", &SALT, &VID, M, T, P),
            Err(Error::HeaderAuth)
        ));
    }

    // ── composite 2FA (password + YubiKey) ──────────────────────────────────
    const CHALLENGE: [u8; CHALLENGE_LEN] = [0x44; CHALLENGE_LEN];
    const HW: &[u8] = b"yubikey-hmac-sha1-resp\x00\x01\x02\x03"; // mock 20-ish byte response

    #[test]
    fn twofa_round_trip_needs_both_factors() {
        let dk = [0xCD; 32];
        let s = wrap_yubikey_2fa_stanza(&dk, b"pw", HW, &CHALLENGE, &SALT, &VID, M, T, P).unwrap();
        assert_eq!(s.stanza_type, kind::PW_YUBIKEY);
        assert_eq!(
            s.data.len(),
            CHALLENGE_LEN + WRAP_NONCE_LEN + WRAPPED_KEY_LEN
        );
        // the challenge is recoverable for the unlock flow…
        assert_eq!(yubikey_challenge(&s).unwrap(), CHALLENGE);
        // …and the data key never appears in plaintext.
        assert!(s.data.windows(32).all(|w| w != dk));

        // both correct → opens
        let out = unwrap_yubikey_2fa_stanza(&s, b"pw", HW, &SALT, &VID, M, T, P).unwrap();
        assert_eq!(out.expose_secret(), &dk);
    }

    #[test]
    fn twofa_fails_without_each_factor() {
        let dk = [0x10; 32];
        let s = wrap_yubikey_2fa_stanza(&dk, b"pw", HW, &CHALLENGE, &SALT, &VID, M, T, P).unwrap();
        // wrong password (key correct) → fail
        assert!(matches!(
            unwrap_yubikey_2fa_stanza(&s, b"WRONG", HW, &SALT, &VID, M, T, P),
            Err(Error::HeaderAuth)
        ));
        // wrong YubiKey response (password correct) → fail
        assert!(matches!(
            unwrap_yubikey_2fa_stanza(&s, b"pw", b"wrong-response", &SALT, &VID, M, T, P),
            Err(Error::HeaderAuth)
        ));
        // missing the hardware factor entirely → fail
        assert!(matches!(
            unwrap_yubikey_2fa_stanza(&s, b"pw", b"", &SALT, &VID, M, T, P),
            Err(Error::HeaderAuth)
        ));
    }

    #[test]
    fn twofa_challenge_rejects_wrong_kind() {
        let pw = wrap_password_stanza(&[0u8; 32], b"pw", &SALT, &VID, M, T, P).unwrap();
        assert!(yubikey_challenge(&pw).is_err());
    }

    // ── composite 2FA (password + keyfile) ──────────────────────────────────
    #[test]
    fn keyfile_2fa_round_trip_needs_both() {
        let dk = [0xEF; 32];
        let keyfile = b"keyfile-bytes-kept-on-a-separate-usb-stick";
        let s = wrap_keyfile_2fa_stanza(&dk, b"pw", keyfile, &SALT, &VID, M, T, P).unwrap();
        assert_eq!(s.stanza_type, kind::PW_KEYFILE);
        assert_eq!(s.data.len(), WRAP_NONCE_LEN + WRAPPED_KEY_LEN);
        assert!(s.data.windows(32).all(|w| w != dk));

        // both correct → opens
        let out = unwrap_keyfile_2fa_stanza(&s, b"pw", keyfile, &SALT, &VID, M, T, P).unwrap();
        assert_eq!(out.expose_secret(), &dk);
        // wrong password (keyfile correct) → fail
        assert!(matches!(
            unwrap_keyfile_2fa_stanza(&s, b"WRONG", keyfile, &SALT, &VID, M, T, P),
            Err(Error::HeaderAuth)
        ));
        // wrong keyfile (password correct) → fail
        assert!(matches!(
            unwrap_keyfile_2fa_stanza(&s, b"pw", b"a-different-keyfile", &SALT, &VID, M, T, P),
            Err(Error::HeaderAuth)
        ));
    }
}
