//! Optional hardware-backed unlock stanzas — constraints **C14, C15** (and C5's optional types).
//!
//! Every integration here is **additive**: it wraps the same data key as an extra stanza. The
//! password stanza is always present, so losing a hardware factor never locks the user out
//! (constraint C5). Each backend is behind a Cargo feature so unused device code is not compiled.
//!
//! **Implemented helpers:** YubiKey CR (subprocess), FIDO2 salt/HKDF recipe (C6/C14), TPM policy
//! strings (C15). Full libfido2 / TPM FFI lands behind features in M7.

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod fido2_salt;
pub mod tpm_policy;
pub mod yubikey;

/// FIDO2 hmac-secret / PRF via raw CTAP2 (libfido2) — **never** the browser WebAuthn path.
/// Salt/HKDF math: [`fido2_salt`] (constraints C6, C14).
#[cfg(feature = "fido2")]
pub mod fido2 {}

/// TPM 2.0 PCR-sealed stanza — policy strings in [`tpm_policy`] (constraint C15).
#[cfg(feature = "tpm")]
pub mod tpm {}

/// macOS Secure Enclave (EC secp256r1, ECIES wrap/unwrap, Touch ID gating).
#[cfg(feature = "secure-enclave")]
pub mod secure_enclave {}

/// Windows DPAPI convenience stanza (user+machine bound).
#[cfg(feature = "dpapi")]
pub mod dpapi {}
