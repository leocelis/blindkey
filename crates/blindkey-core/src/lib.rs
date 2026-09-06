//! # blindkey-core
//!
//! The security boundary of Vault. Everything that touches a secret lives here, behind
//! zeroizing types, so the CLI never holds raw key material.
//!
//! This crate is specified by the constraints in `blindkey_intent.yaml`. Each module maps to a
//! constraint group; see `docs/ARCHITECTURE.md`.
//!
//! ## Status
//! **Implemented.** The cryptographic core, CLI integration, search, and rollback paths are
//! functional. Optional hardware stanzas and some constraint-specific integration tests remain
//! in progress — see `ROADMAP.md` and `docs/CONSTRAINT_INDEX.md`.
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
pub mod sealed; // UC-23   sealed file containers (.vltf)
pub mod search; // UC-19   fuzzy keyboard-first omni-search (metadata only — C35)
pub mod totp; // 2FA      RFC 6238 TOTP codes from an entry's otp_secret
pub mod volume; // UC-25   local encrypted workspace volumes (.vltd)
                // open/save orchestration (the v0 blindkey-core API)
mod vault;
pub mod wordlist; // C26     built-in diceware wordlist

mod error;
pub use error::{Error, Result};
pub use sealed::{
    ArchiveEntryMeta, SealedContainer, SealedIoOpts, SealedUnlock, YubiKeyRespond,
    SEALED_OPEN_ERROR, STDOUT_SIZE_LIMIT,
};
pub use vault::{RotateDataKeyOptions, SaveOptions, SaveReport, Vault, YUBIKEY_STALE_WARNING};
pub use volume::{
    assert_hydrated_for_checkout, cleartext_mnt_beside, default_work_root, hash_outer_logical,
    has_unresolved_conflicts, is_under_sync_root, list_work_sessions, orphan_work_sessions,
    orphaned_cleartext_sessions, CheckinOpts, CheckoutOpts, CloseMountError, MaterializedMount,
    NodeKind, OuterFingerprint, Volume, VolumeCreateOpts, VolumeUnlock, WorkPhase,
    WorkSessionInfo, WorkingCopySession, VOLUME_OPEN_ERROR, WORKING_COPY_ERROR,
};

/// The current on-disk format version (constraint C7).
pub const FORMAT_VERSION: u16 = 1;

/// Magic bytes that prefix every vault file: `b"VLT\0"` (constraint C7).
pub const MAGIC: [u8; 4] = [0x56, 0x4C, 0x54, 0x00];

/// Magic bytes that prefix sealed file containers (UC-23 / ADR-0005 sibling format).
pub const MAGIC_VLTF: [u8; 4] = *b"VLTF";

/// Magic bytes that prefix local encrypted volumes (UC-25 / C67 / ADR-0007).
///
/// Same 4-byte peer style as [`MAGIC_VLTF`]. Payload layout is a future `volume/` module —
/// only the kind table and header branch land in A1.
pub const MAGIC_VLTD: [u8; 4] = *b"VLTD";

/// On-disk container kind — header/stanza layout is shared; only the magic differs
/// (UC-23 §3.1 · UC-25 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// Credential vault (`.vlt`).
    Vault,
    /// Sealed file archive (`.vltf`).
    SealedFile,
    /// Local encrypted workspace volume (`.vltd`).
    Volume,
}

impl ContainerKind {
    /// Magic bytes for this kind.
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Self::Vault => MAGIC,
            Self::SealedFile => MAGIC_VLTF,
            Self::Volume => MAGIC_VLTD,
        }
    }

    /// Parse kind from the first four bytes (constraint C7 / C67).
    pub fn from_magic(magic: [u8; 4]) -> Option<Self> {
        if magic == MAGIC {
            Some(Self::Vault)
        } else if magic == MAGIC_VLTF {
            Some(Self::SealedFile)
        } else if magic == MAGIC_VLTD {
            Some(Self::Volume)
        } else {
            None
        }
    }
}
