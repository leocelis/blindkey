//! Optional hardware-backed unlock stanzas — constraints **C14, C15** (and C5's optional types).
//!
//! Every integration here is **additive**: it wraps the same data key as an extra stanza. The
//! password stanza is always present, so losing a hardware factor never locks the user out
//! (constraint C5). Each backend is behind a Cargo feature so unused device code is not compiled.
//!
//! **Pre-alpha scaffold.** Implementations land in M7 (`ROADMAP.md`).

#![forbid(unsafe_code)]
#![allow(dead_code)]

/// FIDO2 hmac-secret / PRF via raw CTAP2 (libfido2) — **never** the browser WebAuthn path.
/// Salt to authenticator = SHA-256(vault_id || b"fido2-hw-v1"); output → HKDF → wrapping key
/// (constraints C6, C14).
#[cfg(feature = "fido2")]
pub mod fido2 {}

/// TPM 2.0 PCR-sealed stanza with mandatory re-enrollment flow; documents the bus-attack
/// limitation and provides `enroll` / `re-enroll` (constraint C15).
#[cfg(feature = "tpm")]
pub mod tpm {}

/// macOS Secure Enclave (EC secp256r1, ECIES wrap/unwrap, Touch ID gating).
#[cfg(feature = "secure-enclave")]
pub mod secure_enclave {}

/// Windows DPAPI convenience stanza (user+machine bound).
#[cfg(feature = "dpapi")]
pub mod dpapi {}
