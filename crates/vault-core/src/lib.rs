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

pub mod audit; // health    weak / reused / stale / expiring report (offline)
pub mod crypto; // C1–C3   cipher, KDF, primitives
pub mod envelope; // C4–C6   data key + multi-stanza envelope
pub mod format; // C7–C10  on-disk format + integrity
pub mod frecency; // UC-19   per-entry usage signal (frequency × recency), ciphertext at rest (C36)
pub mod gen; // C26     CSPRNG password generation
pub mod import; // UC-17   lenient keys.txt parser
pub mod memory; // C11–C13, C25  secret types, mlock, constant-time
pub mod pad; // UC-07 §3.2  optional Padmé payload padding
pub mod rollback; // C16     monotonic counter + local anchor
pub mod search; // UC-19   fuzzy keyboard-first omni-search (metadata only — C35)
pub mod totp; // 2FA      RFC 6238 TOTP codes from an entry's otp_secret
              // open/save orchestration (the v0 vault-core API)
mod vault;
pub mod wordlist; // C26     built-in diceware wordlist

mod error;
pub use error::{Error, Result};
pub use vault::Vault;

/// The current on-disk format version (constraint C7).
pub const FORMAT_VERSION: u16 = 1;

/// Magic bytes that prefix every vault file: `b"VLT\0"` (constraint C7).
pub const MAGIC: [u8; 4] = [0x56, 0x4C, 0x54, 0x00];
