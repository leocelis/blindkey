//! Data key and multi-stanza envelope — constraints **C4–C6**.
//!
//! A random 256-bit data key is wrapped by one or more independent stanzas (OR model): any single
//! valid stanza unlocks the vault. The password stanza is always present; hardware/OS-keystore
//! stanzas are additive, so losing a hardware factor never locks the user out (constraint C5).

use crate::memory::DataKey;
use crate::Result;

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
    unimplemented!("M3: CSPRNG data key generation (constraint C4)")
}

/// Unwrap the data key from the first valid stanza (OR model, constraint C5).
pub fn unwrap_data_key(/* stanzas, secret */) -> Result<DataKey> {
    unimplemented!("M3: stanza unwrap via HKDF + XChaCha20-Poly1305 (constraints C5, C6)")
}
