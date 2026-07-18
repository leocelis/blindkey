//! Cryptographic primitives — constraints **C1–C3**.
//!
//! **No custom cryptography.** Every operation here is a thin wrapper over an audited library
//! (`chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`). If a primitive is not in an audited
//! library, it does not belong in Vault (constraint C3).

use crate::{Error, Result};

use hkdf::Hkdf;
use sha2::Sha256;

pub mod kdf;
pub mod stream;
pub mod tune; // C22  Argon2id benchmark + recommendation

/// HKDF-SHA-256 to a 32-byte key. Shared by the envelope (C5) and the integrity layers (C9/C10).
///
/// An empty `salt` slice is RFC-5869 valid (treated as a zero-filled salt). The output length (32)
/// is always a valid HKDF-SHA-256 length, so expansion cannot fail.
pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 is a valid HKDF-SHA-256 output length");
    okm
}

/// STREAM chunk size: 64 KiB (constraint C1).
pub const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Default Argon2id parameters: m = 64 MiB, t = 3, p = 4 (constraint C2).
pub const ARGON2_DEFAULT_M_COST_KIB: u32 = 65_536;
/// Default Argon2id time cost.
pub const ARGON2_DEFAULT_T_COST: u32 = 3;
/// Default Argon2id parallelism.
pub const ARGON2_DEFAULT_P_COST: u32 = 4;

/// Minimum recommended Argon2id parameters — below this the vault warns and offers an upgrade on
/// open (constraint C2). Below-floor is **not** rejected; only above-ceiling is (see below).
pub const ARGON2_FLOOR_M_COST_KIB: u32 = 19_456; // 19 MiB
/// Minimum recommended time cost (we prefer ≥ 2 even when memory is higher — stricter than OWASP).
pub const ARGON2_FLOOR_T_COST: u32 = 2;
/// Minimum recommended parallelism.
pub const ARGON2_FLOOR_P_COST: u32 = 1;

/// Maximum acceptable Argon2id memory cost — rejected (not warned) before any allocation.
/// (Constraint C2 ceiling: a missing ceiling is a memory-exhaustion / integer-overflow DoS.
/// Also requires `m_cost >= 8 * p_cost` per RFC 9106.)
pub const ARGON2_CEILING_M_COST_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
/// Maximum time cost ceiling.
pub const ARGON2_CEILING_T_COST: u32 = 24;
/// Maximum parallelism ceiling.
pub const ARGON2_CEILING_P_COST: u32 = 16;

/// How stored KDF parameters compare to policy (constraint C2). Returned by
/// [`validate_kdf_params`]; only above-ceiling/overflow params are a hard error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfStrength {
    /// At or above the current recommended defaults — open silently.
    Recommended,
    /// Above the OWASP floor but below recommended — open with a mild note.
    BelowRecommended,
    /// Below the OWASP floor — open is allowed but MUST warn and offer `blindkey upgrade-kdf` (C2).
    BelowFloor,
}

/// Validate stored Argon2id parameters (constraint C2: floor is a *warning*, ceiling is a *reject*).
///
/// Returns `Err(KdfParamsOutOfRange)` only for params that are unsafe to even attempt — above the
/// ceiling, or where the KiB→bytes math would overflow (`m < 8·p`) — so a hostile file can never
/// make us allocate gigabytes before the keyed integrity check runs. Below-floor params are valid
/// on **open** but return [`KdfStrength::BelowFloor`] so the caller can warn and offer an upgrade.
pub fn validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<KdfStrength> {
    // Ceiling FIRST — reject hostile/overflowing params before any allocation or Argon2id (C2).
    if m_cost > ARGON2_CEILING_M_COST_KIB
        || t_cost > ARGON2_CEILING_T_COST
        || p_cost > ARGON2_CEILING_P_COST
    {
        return Err(Error::KdfParamsOutOfRange);
    }

    // RFC 9106: memory must be at least 8 * parallelism (one slice per lane). Checked math; p_cost
    // is already <= ceiling (16) here, so 8 * p_cost cannot overflow, but stay explicit.
    let min_m_for_lanes = p_cost.checked_mul(8).ok_or(Error::KdfParamsOutOfRange)?;
    if m_cost < min_m_for_lanes {
        return Err(Error::KdfParamsOutOfRange);
    }

    // Below the recommended floor: valid, but the caller warns + offers an upgrade (C2).
    if m_cost < ARGON2_FLOOR_M_COST_KIB
        || t_cost < ARGON2_FLOOR_T_COST
        || p_cost < ARGON2_FLOOR_P_COST
    {
        return Ok(KdfStrength::BelowFloor);
    }

    if m_cost >= ARGON2_DEFAULT_M_COST_KIB
        && t_cost >= ARGON2_DEFAULT_T_COST
        && p_cost >= ARGON2_DEFAULT_P_COST
    {
        Ok(KdfStrength::Recommended)
    } else {
        Ok(KdfStrength::BelowRecommended)
    }
}

/// Reject below-floor parameters on **write** paths (init, upgrade-kdf targets) — constraint C2.
///
/// Opening an existing weak vault must NOT call this; use [`validate_kdf_params`] and warn instead.
pub fn reject_kdf_below_floor(m_cost: u32, t_cost: u32, p_cost: u32) -> crate::Result<()> {
    match validate_kdf_params(m_cost, t_cost, p_cost)? {
        KdfStrength::BelowFloor => Err(crate::Error::KdfBelowFloor),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    // `Error` cannot derive `PartialEq` (it wraps `io::Error`), so assert via matches! / unwrap.

    #[test]
    fn defaults_are_recommended() {
        assert_eq!(
            validate_kdf_params(
                ARGON2_DEFAULT_M_COST_KIB,
                ARGON2_DEFAULT_T_COST,
                ARGON2_DEFAULT_P_COST
            )
            .unwrap(),
            KdfStrength::Recommended
        );
    }

    #[test]
    fn exact_floor_is_valid_but_below_recommended() {
        // Floor params are accepted (not an error) but flagged for a warning (C2).
        let s = validate_kdf_params(
            ARGON2_FLOOR_M_COST_KIB,
            ARGON2_FLOOR_T_COST,
            ARGON2_FLOOR_P_COST,
        )
        .unwrap();
        assert_eq!(s, KdfStrength::BelowRecommended);
    }

    #[test]
    fn below_floor_warns_not_rejects() {
        // C2: below-floor is openable with a warning — NOT a hard error.
        assert_eq!(
            validate_kdf_params(8192, 1, 1).unwrap(),
            KdfStrength::BelowFloor
        );
    }

    #[test]
    fn above_ceiling_is_rejected_without_overflow() {
        // C2 ceiling: extreme params rejected cleanly, no panic/overflow.
        assert!(matches!(
            validate_kdf_params(u32::MAX, u32::MAX, u32::MAX),
            Err(Error::KdfParamsOutOfRange)
        ));
        assert!(matches!(
            validate_kdf_params(ARGON2_CEILING_M_COST_KIB + 1, 3, 4),
            Err(Error::KdfParamsOutOfRange)
        ));
    }

    #[test]
    fn ceiling_exact_is_accepted() {
        assert_eq!(
            validate_kdf_params(
                ARGON2_CEILING_M_COST_KIB,
                ARGON2_CEILING_T_COST,
                ARGON2_CEILING_P_COST
            )
            .unwrap(),
            KdfStrength::Recommended
        );
    }

    #[test]
    fn memory_below_eight_times_parallelism_is_rejected() {
        // RFC 9106 m >= 8p: 64 KiB memory with p=16 needs >= 128 KiB.
        assert!(matches!(
            validate_kdf_params(64, 3, 16),
            Err(Error::KdfParamsOutOfRange)
        ));
    }

    #[test]
    fn reject_below_floor_for_write_paths() {
        assert!(matches!(
            super::reject_kdf_below_floor(8192, 1, 1),
            Err(Error::KdfBelowFloor)
        ));
        assert!(super::reject_kdf_below_floor(
            ARGON2_FLOOR_M_COST_KIB,
            ARGON2_FLOOR_T_COST,
            ARGON2_FLOOR_P_COST
        )
        .is_ok());
    }
}
