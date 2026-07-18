//! Secret types and runtime memory hardening — constraints **C11–C13, C25**.
//!
//! All secret material is held in zeroizing wrappers (volatile write + fence, never `memset`),
//! kept off swap with `mlock`, and compared in constant time. No secret type exposes its bytes via
//! `Debug` or `Clone`.

use secrecy::{Secret, SecretBox};
use zeroize::Zeroizing;

/// A master password, read from a no-echo prompt or stdin — **never** from argv (constraint C31).
pub type MasterPassword = SecretBox<[u8]>;

/// The 256-bit vault data key (constraint C4). Wrapped so it cannot be logged or cloned.
/// `Secret<[u8; 32]>` is one of C11's approved types; a boxed array would not implement `Zeroize`.
pub type DataKey = Secret<[u8; 32]>;

/// A transient buffer of decrypted plaintext that zeroes on drop (constraint C11).
pub type SecretBuffer = Zeroizing<Vec<u8>>;

use subtle::ConstantTimeEq;

use std::sync::atomic::{AtomicBool, Ordering};

static MLOCK_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_mlock_once(errno: i32) {
    if MLOCK_WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!(
        "WARNING: could not lock memory pages (mlock failed: {errno}). Secrets may be swapped to disk. Consider running with CAP_IPC_LOCK or raising ulimit -l."
    );
}

/// Locks a byte buffer's pages into RAM for its lifetime, keeping secrets off swap (constraint C12).
///
/// Unlocks on drop. Borrows the buffer so it cannot outlive it; the buffer must not be reallocated
/// (e.g. a `Vec` grown) while locked. Degrades gracefully — if `mlock` fails (unprivileged
/// container, `RLIMIT_MEMLOCK`), [`PageLock::is_locked`] is `false` and the program continues
/// (constraint C12: never abort). All `unsafe` is isolated in the `blindkey-sys` FFI crate.
#[derive(Debug)]
pub struct PageLock<'a> {
    buf: &'a [u8],
    locked: bool,
}

impl<'a> PageLock<'a> {
    /// Attempt to lock the pages backing `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        let locked = match blindkey_sys::lock_region_errno(buf.as_ptr(), buf.len()) {
            Ok(()) => true,
            Err(errno) => {
                warn_mlock_once(errno);
                false
            }
        };
        PageLock { buf, locked }
    }

    /// Whether the pages were actually locked (false = graceful degradation).
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for PageLock<'_> {
    fn drop(&mut self) {
        if self.locked {
            blindkey_sys::unlock_region(self.buf.as_ptr(), self.buf.len());
        }
    }
}

/// Constant-time equality for secret byte slices (constraint C25).
///
/// Uses `subtle::ConstantTimeEq`. Using `==` on secret bytes is forbidden — it leaks timing.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Process-wide runtime hardening applied at startup (constraint C25, gap B3): disable core dumps
/// (`setrlimit(RLIMIT_CORE, 0)`; on Linux also `PR_SET_DUMPABLE, 0` and `coredump_filter=0`).
/// Best-effort: on failure it prints a one-line warning to stderr and continues (C25 must not
/// abort). Call once from `main`.
pub fn harden_process() {
    if !blindkey_sys::disable_core_dumps() {
        eprintln!(
            "vault: warning — could not disable core dumps; a crash could leave secrets in a core file"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_value_equality() {
        assert!(ct_eq(b"hunter2", b"hunter2"));
        assert!(!ct_eq(b"hunter2", b"hunter3"));
        assert!(!ct_eq(b"short", b"longer"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn page_lock_is_graceful() {
        let buf = vec![0u8; 4096];
        let lock = PageLock::new(&buf);
        // is_locked may be true or false depending on the environment; must not panic, and unlock
        // happens cleanly on drop.
        let _ = lock.is_locked();
    }
}
