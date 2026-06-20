//! `vault-sys` — the **single designated FFI module** for Vault (constraints C12, C25).
//!
//! Every `unsafe` line in the project lives here, behind a tiny safe API, so the rest of the
//! codebase can keep `#![forbid(unsafe_code)]`. It wraps the OS calls for process and memory
//! hardening: disabling core dumps and locking pages out of swap. Each function is **best-effort**
//! and degrades gracefully (returns `false` rather than aborting) — the caller warns and continues
//! (C12: "must never abort the process").
//!
//! Soundness note: `setrlimit`/`prctl`/`mlock`/`munlock` operate on the process and its page
//! tables; they do not dereference the passed memory in a way that could cause UB (a bad pointer or
//! length yields an `errno`, not undefined behavior), so exposing them as safe functions is sound.

#![deny(missing_docs)]

/// Disable core dumps so a crash cannot leave secrets in a core file (constraint C25).
///
/// On Unix: `setrlimit(RLIMIT_CORE, 0)`, plus `prctl(PR_SET_DUMPABLE, 0)` on Linux (which also
/// blocks `ptrace` attach). Returns `true` on success, `false` if unsupported or it failed.
pub fn disable_core_dumps() -> bool {
    #[cfg(unix)]
    {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads `rlim` (a valid local) and adjusts this process's limits.
        let core_ok = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) } == 0;
        #[cfg(target_os = "linux")]
        {
            // SAFETY: prctl with PR_SET_DUMPABLE takes scalar args; no memory is dereferenced.
            let dumpable_ok = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
            core_ok && dumpable_ok
        }
        #[cfg(not(target_os = "linux"))]
        {
            core_ok
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Lock the pages backing `[ptr, ptr + len)` into RAM so secrets stay off swap (constraint C12).
///
/// Best-effort: returns `false` on failure (e.g. `RLIMIT_MEMLOCK` exceeded, or an unprivileged
/// container). `len == 0` is a no-op success.
pub fn lock_region(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[cfg(unix)]
    {
        // SAFETY: mlock operates on page tables for the given range; it does not read/write the
        // bytes. A bad range returns an errno (handled as `false`), never UB.
        unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Unlock pages previously locked with [`lock_region`]. `len == 0` is a no-op.
pub fn unlock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(unix)]
    {
        // SAFETY: see `lock_region`; munlock is the inverse and equally does not touch the bytes.
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
    }
}

/// Take an exclusive advisory lock on the open file descriptor `fd` (constraint C16 anchor write).
///
/// Blocks until the lock is acquired. Best-effort: returns `false` if locking is unsupported or
/// failed (the caller proceeds without mutual exclusion, accepting the documented TOCTOU window).
/// On non-Unix this is a no-op returning `false`.
pub fn flock_exclusive(fd: i32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: flock takes a scalar fd and operation; it does not dereference memory.
        unsafe { libc::flock(fd, libc::LOCK_EX) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        false
    }
}

/// Release an advisory lock previously taken with [`flock_exclusive`].
pub fn flock_unlock(fd: i32) {
    #[cfg(unix)]
    {
        // SAFETY: see `flock_exclusive`; LOCK_UN is the inverse and dereferences nothing.
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
    }
}

/// Read one line (without trailing newline) from an open file descriptor (UC-05 `--password-fd`).
///
/// Does **not** close `fd` on return.
#[cfg(unix)]
pub fn read_line_from_fd(fd: i32) -> std::io::Result<String> {
    use std::io::{BufRead, BufReader};
    use std::mem::ManuallyDrop;
    use std::os::fd::{FromRawFd, RawFd};

    // SAFETY: `fd` is open for read; we wrap it without closing on drop via `ManuallyDrop`.
    let file = unsafe { std::fs::File::from_raw_fd(fd as RawFd) };
    let mut file = ManuallyDrop::new(file);
    let mut reader = BufReader::new(&mut *file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

#[cfg(not(unix))]
pub fn read_line_from_fd(_fd: i32) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this platform does not support --password-fd",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_dumps_disable_on_unix() {
        let ok = disable_core_dumps();
        #[cfg(unix)]
        assert!(ok, "setrlimit(RLIMIT_CORE, 0) should succeed on unix");
        #[cfg(not(unix))]
        let _ = ok;
    }

    #[test]
    fn lock_unlock_does_not_crash() {
        let buf = vec![0u8; 4096];
        // May or may not succeed depending on RLIMIT_MEMLOCK; must not panic either way.
        let _ = lock_region(buf.as_ptr(), buf.len());
        unlock_region(buf.as_ptr(), buf.len());
        // empty region is a trivial success
        assert!(lock_region(buf.as_ptr(), 0));
    }
}
