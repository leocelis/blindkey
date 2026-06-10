//! Cryptographic primitives — constraints **C1–C3**.
//!
//! **No custom cryptography.** Every operation here is a thin wrapper over an audited library
//! (`chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`). If a primitive is not in an audited
//! library, it does not belong in Vault (constraint C3).

use crate::Result;

/// STREAM chunk size: 64 KiB (constraint C1).
pub const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Default Argon2id parameters: m = 64 MiB, t = 3, p = 4 (constraint C2).
pub const ARGON2_DEFAULT_M_COST_KIB: u32 = 65_536;
/// Default Argon2id time cost.
pub const ARGON2_DEFAULT_T_COST: u32 = 3;
/// Default Argon2id parallelism.
pub const ARGON2_DEFAULT_P_COST: u32 = 4;

/// Minimum acceptable Argon2id parameters — enforced on every open (constraint C2).
pub const ARGON2_FLOOR_M_COST_KIB: u32 = 19_456; // 19 MiB
/// Minimum time cost (we require ≥ 2 even when memory is higher — stricter than OWASP).
pub const ARGON2_FLOOR_T_COST: u32 = 2;
/// Minimum parallelism.
pub const ARGON2_FLOOR_P_COST: u32 = 1;

/// Maximum acceptable Argon2id memory cost — rejects hostile/overflowing files before allocation.
/// (Coverage-gap A1: a missing ceiling is a memory-exhaustion / integer-overflow DoS.)
pub const ARGON2_CEILING_M_COST_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
/// Maximum time cost ceiling.
pub const ARGON2_CEILING_T_COST: u32 = 24;
/// Maximum parallelism ceiling.
pub const ARGON2_CEILING_P_COST: u32 = 16;

/// Validate stored Argon2id parameters against the floor **and** ceiling (constraint C2 + A1).
///
/// Returns `Ok(within_recommended)` where `false` means "valid but below current recommended,
/// warn and offer upgrade". Returns `Err(KdfParamsOutOfRange)` for values that are unsafe to even
/// attempt (below floor or above ceiling), so we never allocate gigabytes for a hostile file.
pub fn validate_kdf_params(_m_cost: u32, _t_cost: u32, _p_cost: u32) -> Result<bool> {
    unimplemented!("M3: KDF param floor+ceiling validation (constraints C2, A1)")
}

/// Encrypt a payload with XChaCha20-Poly1305 in STREAM mode (constraint C1).
///
/// Each 64 KiB chunk is independently sealed; no plaintext is released before its tag verifies.
pub mod stream {
    //! XChaCha20-Poly1305 STREAM (constraint C1).
}

/// Argon2id key derivation (constraint C2).
pub mod kdf {
    //! Argon2id KDF with enforced floor/ceiling (constraints C2, A1).
}
