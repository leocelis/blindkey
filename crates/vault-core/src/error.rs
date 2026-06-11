//! Error types for `vault-core`.
//!
//! Error messages must never include secret material. Note the deliberate ambiguity of
//! [`Error::HeaderAuth`]: a tampered header and a wrong password produce the *same* error, so the
//! error cannot be used as an oracle to distinguish the two (constraint C9).

use thiserror::Error;

/// Result alias for `vault-core`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while reading, writing, or operating on a vault.
#[derive(Debug, Error)]
pub enum Error {
    /// The file did not begin with the vault magic bytes (constraint C7).
    #[error("not a vault file")]
    NotAVault,

    /// The file was created by a newer, unsupported format version (constraint C7).
    #[error("vault was created by a newer version of this tool; please upgrade")]
    NewerVersion,

    /// The plaintext header hash did not match — the file is corrupt (constraint C9).
    #[error("vault header is corrupt")]
    HeaderCorrupt,

    /// Stanza unwrap failed: wrong credentials *or* tampered KDF params — intentionally
    /// indistinguishable (constraint C9 step 3, exit code 5).
    #[error("invalid credentials or tampered header")]
    HeaderAuth,

    /// Header HMAC failed AFTER a stanza unwrapped successfully: the factor was valid, so this
    /// is unambiguous tampering of header fields outside the stanza tag (constraint C9 step 4).
    #[error("header tampered")]
    HeaderTampered,

    /// KDF parameters exceed the enforced ceiling, or the KiB→bytes math overflows —
    /// never legitimate; rejected before any allocation (constraint C2 ceiling).
    /// Below-floor params are NOT this error: they trigger a warning + upgrade prompt (C2).
    #[error("KDF parameters exceed safe limits — possible hostile or corrupt file")]
    KdfParamsOutOfRange,

    /// An authentication tag on the encrypted body failed (constraints C1, C10).
    #[error("authentication failed while decrypting the vault body")]
    BodyAuth,

    /// The decrypted version counter regressed versus the local anchor (constraint C16).
    #[error("vault version regressed; the sync backend may have served an older copy")]
    Rollback,

    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
