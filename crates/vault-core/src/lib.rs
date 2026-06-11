//! # vault-core
//!
//! The security boundary of Vault. Everything that touches a secret lives here, behind
//! zeroizing types, so the CLI never holds raw key material.
//!
//! This crate is specified by the constraints in `vault_intent.yaml`. Each module maps to a
//! constraint group; see `docs/ARCHITECTURE.md`.
//!
//! ## Status
//! **Pre-alpha scaffold.** The module structure and public surface are laid out; the
//! implementations land by milestone (see `ROADMAP.md`). Functions marked `unimplemented!` are
//! intentionally not done yet.
//!
//! ## Safety posture
//! - `#![forbid(unsafe_code)]` — the only `unsafe` permitted in the project is an isolated,
//!   reviewed crypto-FFI module (not present yet); it will live behind its own crate boundary.
//! - No secret type derives `Debug`/`Clone` that exposes bytes (constraint C11).
//! - No `==` on secret bytes — constant-time only (constraint C25).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(missing_docs)]
// Scaffold phase: stubs intentionally carry unfinished items.
#![allow(dead_code)]

pub mod crypto; // C1–C3   cipher, KDF, primitives
pub mod envelope; // C4–C6   data key + multi-stanza envelope
pub mod format; // C7–C10  on-disk format + integrity
pub mod memory; // C11–C13, C25  secret types, mlock, constant-time
pub mod rollback; // C16     monotonic counter + local anchor

mod error;
pub use error::{Error, Result};

/// The current on-disk format version (constraint C7).
pub const FORMAT_VERSION: u16 = 1;

/// Magic bytes that prefix every vault file: `b"VLT\0"` (constraint C7).
pub const MAGIC: [u8; 4] = [0x56, 0x4C, 0x54, 0x00];

/// A handle to an opened (unlocked) vault. Holds decrypted state in zeroizing, `mlock`'d memory.
///
/// Implementation arrives in M5 (`ROADMAP.md`).
#[derive(Debug)]
pub struct Vault {
    _private: (),
}

impl Vault {
    /// Open and unlock a vault file with the given master password.
    ///
    /// Verification order per C9: keyless header hash → KDF floor **and** ceiling → stanza
    /// unwrap → data-key-keyed header HMAC → body; never returns a plaintext byte before its
    /// authentication tag verifies (constraints C1, C2, C8, C9, C10).
    pub fn open(_path: &std::path::Path, _password: memory::MasterPassword) -> Result<Self> {
        unimplemented!("M5: vault open — see docs/ARCHITECTURE.md 'opening a vault'")
    }
}
