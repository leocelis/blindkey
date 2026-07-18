//! `blindkey tune` — benchmark Argon2id on this machine and recommend parameters (constraint C22).
//!
//! The interactive-unlock budget is ~300 ms (C22): fast enough that users don't lower the cost or
//! abandon the tool, slow enough to be expensive to crack. We hold `t` at the default and `p` at the
//! machine's core count (capped at the default), and scale the memory cost `m` — Argon2 time is
//! ~linear in `m` for fixed `t`,`p` — to hit the target, then re-measure so the reported time is real.

use std::time::Instant;

use crate::crypto::{
    kdf, ARGON2_CEILING_M_COST_KIB, ARGON2_DEFAULT_P_COST, ARGON2_DEFAULT_T_COST,
    ARGON2_FLOOR_M_COST_KIB,
};
use crate::Result;

/// Target interactive-unlock time in milliseconds (constraint C22: 300 ms ± 100 ms).
const TARGET_MS: f64 = 300.0;
/// Baseline memory cost (KiB) used for the first timing probe before extrapolating.
const BASELINE_M_KIB: u32 = 16 * 1024;

/// A recommended Argon2id parameter set plus the time it actually took on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuneResult {
    /// Recommended memory cost in KiB.
    pub m_cost_kib: u32,
    /// Recommended time cost (iterations).
    pub t_cost: u32,
    /// Recommended parallelism (lanes).
    pub p_cost: u32,
    /// Measured Argon2id time for the recommended set, in milliseconds.
    pub measured_ms: u128,
}

fn parallelism() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(ARGON2_DEFAULT_P_COST)
        .clamp(1, ARGON2_DEFAULT_P_COST)
}

/// Time one Argon2id derivation at the given parameters, in milliseconds.
fn time_kdf(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<f64> {
    let salt = [0u8; 32];
    let start = Instant::now();
    let _ = kdf::argon2id(b"vault-tune-benchmark", &salt, m_cost, t_cost, p_cost)?;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

/// Benchmark Argon2id and recommend parameters targeting ~300 ms on this machine (constraint C22).
pub fn recommend() -> Result<TuneResult> {
    let p_cost = parallelism();
    let t_cost = ARGON2_DEFAULT_T_COST;

    // Probe at a modest memory cost, then linear-extrapolate `m` toward the target.
    let dt0 = time_kdf(BASELINE_M_KIB, t_cost, p_cost)?.max(1.0);
    let scaled = (BASELINE_M_KIB as f64) * (TARGET_MS / dt0);

    // Round to a whole MiB and clamp into the policy floor/ceiling.
    let mut m_cost = scaled as u32;
    m_cost = (m_cost / 1024).max(1) * 1024;
    m_cost = m_cost.clamp(ARGON2_FLOOR_M_COST_KIB, ARGON2_CEILING_M_COST_KIB);

    let measured_ms = time_kdf(m_cost, t_cost, p_cost)?.round() as u128;
    Ok(TuneResult {
        m_cost_kib: m_cost,
        t_cost,
        p_cost,
        measured_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::validate_kdf_params;

    #[test]
    fn recommend_returns_valid_in_policy_params() {
        let r = recommend().unwrap();
        assert!(r.m_cost_kib >= ARGON2_FLOOR_M_COST_KIB);
        assert!(r.m_cost_kib <= ARGON2_CEILING_M_COST_KIB);
        assert_eq!(r.t_cost, ARGON2_DEFAULT_T_COST);
        assert!((1..=ARGON2_DEFAULT_P_COST).contains(&r.p_cost));
        assert!(r.measured_ms > 0);
        // The recommendation must pass policy validation (never below the floor / above the ceiling).
        assert!(validate_kdf_params(r.m_cost_kib, r.t_cost, r.p_cost).is_ok());
    }
}
