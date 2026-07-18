//! Optional hardware-backed unlock stanzas — constraints **C14, C15** (and C5's optional types).
//!
//! Every integration here is **additive**: it wraps the same data key as an extra stanza. The
//! password stanza is always present, so losing a hardware factor never locks the user out
//! (constraint C5). YubiKey CR uses `ykman` subprocess; FIDO2 uses `fido2-token` (libfido2);
//! TPM uses `tpm2-tools` — all without `unsafe` in this crate.

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod fido2;
pub mod fido2_mock;
pub mod fido2_salt;
pub mod tpm;
pub mod tpm_mock;
pub mod tpm_policy;
pub mod yubikey;

/// Re-export mock types for constraint tests (CI path).
pub use fido2_mock::{unlock_wrapping_key, Fido2Error, Fido2StanzaHeader, MockAuthenticator};
