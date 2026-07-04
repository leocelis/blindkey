//! Error types for `vault-core`.
//!
//! Error messages must never include secret material. Note the deliberate ambiguity of
//! [`Error::HeaderAuth`]: at the stanza-unwrap stage a tampered header and a wrong password produce
//! the *same* error, so it cannot be used as an oracle to distinguish the two (constraint C9). Once
//! a stanza has unwrapped successfully (the factor is proven correct), a subsequent header-integrity
//! failure is unambiguous tampering and uses the distinct [`Error::HeaderTampered`].

use thiserror::Error;

/// Result alias for `vault-core`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while reading, writing, or operating on a vault.
#[derive(Debug, Error)]
pub enum Error {
    /// The file did not begin with the vault magic bytes (constraint C7).
    #[error("not a vault file")]
    NotAVault,

    /// The file uses the wrong container magic for this operation (UC-23 §3.1).
    #[error("wrong container type for this command")]
    WrongContainerKind,

    /// A sealed container could not be opened — uniform message (C64, no format oracle).
    #[error("sealed container could not be opened")]
    SealedOpenFailed,

    /// The file was created by a newer, unsupported format version (constraint C7).
    #[error("vault was created by a newer version of this tool; please upgrade")]
    NewerVersion,

    /// The plaintext header hash did not match — the file is corrupt (constraint C9).
    #[error("vault header is corrupt")]
    HeaderCorrupt,

    /// Header authentication failed at the unlock stage: tampered header *or* wrong unlock secret —
    /// intentionally indistinguishable so it cannot be used as an oracle (constraint C9).
    #[error("header tampered or wrong password")]
    HeaderAuth,

    /// The header declared a KDF algorithm this version does not support (constraint C8).
    #[error("unsupported KDF algorithm")]
    UnsupportedKdf,

    /// Header HMAC failed *after* a stanza unwrapped successfully: the factor was valid, so this is
    /// unambiguous tampering of header fields outside the stanza tag (constraint C9 step 4).
    #[error("header tampered")]
    HeaderTampered,

    /// KDF parameters exceed the enforced ceiling, or the KiB→bytes math overflows — never
    /// legitimate; rejected before any allocation (constraint C2 ceiling). Below-floor params on
    /// **open** trigger a warning + upgrade offer; on **create/upgrade-kdf** use [`Error::KdfBelowFloor`].
    #[error("KDF parameters exceed safe limits — possible hostile or corrupt file")]
    KdfParamsOutOfRange,

    /// Argon2id parameters are below the enforced floor on a **write** path (init / upgrade-kdf).
    /// Opening an existing weak vault is allowed with a warning (constraint C2).
    #[error(
        "Argon2id parameters are below the minimum floor (m >= 19456 KiB, t >= 2, p >= 1); \
         use stronger params or `vault upgrade-kdf` on an existing vault"
    )]
    KdfBelowFloor,

    /// An internal cryptographic operation failed unexpectedly (e.g. a KDF or AEAD primitive
    /// returned an error for non-secret structural reasons). Carries no secret material.
    #[error("internal cryptographic error")]
    Crypto,

    /// An authentication tag on the encrypted body failed (constraints C1, C10).
    #[error("authentication failed while decrypting the vault body")]
    BodyAuth,

    /// The encrypted body was structurally malformed or truncated (constraint C10): a block size
    /// exceeded the maximum, the end-of-stream marker was missing, or bytes ran out mid-block.
    #[error("vault body is malformed or truncated")]
    BodyMalformed,

    /// The decrypted version counter regressed versus the local anchor (constraint C16).
    #[error("vault version regressed; the sync backend may have served an older copy")]
    Rollback,

    /// A hardware second factor (YubiKey) operation failed — the device is absent, `ykman` is not
    /// installed, or the challenge-response errored. Carries a non-secret human message (C16/UC-09).
    #[error("hardware factor error: {0}")]
    Hardware(String),

    /// A body-writing save was blocked because the YubiKey was absent and strict mode is on (C5).
    #[error(
        "YubiKey required to save (strict mode) — insert the key and retry, or use \
         --allow-stale-yubikey / enroll with --graceful-yubikey"
    )]
    YubiKeyStrictSave,

    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
