//! Rollback detection — constraint **C16**.
//!
//! STREAM segment-binding stops intra-file tampering but not whole-file rollback (a sync backend
//! serving an older, still-valid ciphertext). We keep a monotonic `vault_version` inside the
//! encrypted payload and compare it against a **local** last-seen anchor stored outside the sync
//! backend's control (platform XDG/AppData path).

use crate::Result;

/// Outcome of comparing the decrypted version counter against the local anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackCheck {
    /// `payload_version >= last_seen` — fine; the anchor will be advanced.
    Ok,
    /// `payload_version < last_seen` — the backend may have served an older copy. Abort unless the
    /// user explicitly allows it (and never prompt on a non-TTY — abort with exit code 2).
    Regressed { expected: u64, got: u64 },
}

/// Compare a decrypted vault version against the locally-anchored last-seen value (constraint C16).
pub fn check(_payload_version: u64, _last_seen: u64) -> RollbackCheck {
    unimplemented!("M5: rollback comparison (constraint C16)")
}

/// Path to the non-synced local state anchor for a given vault id (constraint C16, C17).
pub fn anchor_path(_vault_id: &[u8; 16]) -> Result<std::path::PathBuf> {
    unimplemented!("M5: platform XDG/AppData anchor path (constraint C16)")
}
