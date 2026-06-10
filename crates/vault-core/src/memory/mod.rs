//! Secret types and runtime memory hardening — constraints **C11–C13, C25**.
//!
//! All secret material is held in zeroizing wrappers (volatile write + fence, never `memset`),
//! kept off swap with `mlock`, and compared in constant time. No secret type exposes its bytes via
//! `Debug` or `Clone`.

use secrecy::SecretBox;
use zeroize::Zeroizing;

/// A master password, read from a no-echo prompt or stdin — **never** from argv (coverage-gap B1).
pub type MasterPassword = SecretBox<[u8]>;

/// The 256-bit vault data key (constraint C4). Wrapped so it cannot be logged or cloned.
pub type DataKey = SecretBox<[u8; 32]>;

/// A transient buffer of decrypted plaintext that zeroes on drop (constraint C11).
pub type SecretBuffer = Zeroizing<Vec<u8>>;

/// Lock a region of memory so it cannot be swapped to disk (constraint C12).
///
/// Degrades gracefully: if `mlock`/`VirtualLock` is unavailable (e.g. an unprivileged container),
/// logs a warning to stderr and continues — it must never abort the process (constraint C12).
pub fn lock_pages(/* region */) {
    unimplemented!("M4: mlock with graceful degradation (constraint C12)")
}

/// Constant-time equality for secret byte slices (constraint C25).
///
/// Uses `subtle::ConstantTimeEq`. Using `==` on secret bytes is forbidden — it leaks timing.
pub fn ct_eq(_a: &[u8], _b: &[u8]) -> bool {
    unimplemented!("M4: constant-time comparison via subtle (constraint C25)")
}

/// Process-wide runtime hardening applied at startup (constraint C25 + coverage-gaps B3):
/// disable core dumps (`setrlimit(RLIMIT_CORE, 0)`) and block ptrace (`PR_SET_DUMPABLE, 0`).
pub fn harden_process() {
    unimplemented!("M4: core-dump off + anti-ptrace (constraint C25, gap B3)")
}
