//! `blindkey-sys` — the **single designated FFI module** for Vault (constraints C12, C25).
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
/// On Unix: `setrlimit(RLIMIT_CORE, 0)`. On Linux, also `prctl(PR_SET_DUMPABLE, 0)` (blocks
/// same-uid `ptrace` attach and non-root `/proc/<pid>/mem` under default Yama — gap B3) and
/// best-effort `"0"` to `/proc/self/coredump_filter` when writable. Returns `true` when the
/// required platform calls succeed; coredump_filter failure does not fail the return value.
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
            write_coredump_filter_zero();
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

#[cfg(target_os = "linux")]
fn write_coredump_filter_zero() {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/coredump_filter")
    {
        let _ = f.write_all(b"0");
    }
}

/// Lock the pages backing `[ptr, ptr + len)` into RAM so secrets stay off swap (constraint C12).
///
/// Best-effort: returns `false` on failure (e.g. `RLIMIT_MEMLOCK` exceeded, or an unprivileged
/// container). `len == 0` is a no-op success. See [`lock_region_errno`] for the failure errno.
pub fn lock_region(ptr: *const u8, len: usize) -> bool {
    lock_region_errno(ptr, len).is_ok()
}

/// Like [`lock_region`], but returns the `errno` from a failed `mlock(2)` (Unix only).
pub fn lock_region_errno(ptr: *const u8, len: usize) -> Result<(), i32> {
    if len == 0 {
        return Ok(());
    }
    #[cfg(unix)]
    {
        // SAFETY: mlock operates on page tables for the given range; it does not read/write the
        // bytes. A bad range returns an errno (handled below), never UB.
        let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
        Err(-1)
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

    /// Gap B3 — non-dumpable process blocks same-uid ptrace under default Yama.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_non_dumpable_after_harden() {
        assert!(
            disable_core_dumps(),
            "RLIMIT_CORE + PR_SET_DUMPABLE must succeed"
        );
        // SAFETY: PR_GET_DUMPABLE returns the dumpable flag; no pointers.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0, "process must be non-dumpable (anti-ptrace B3)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_coredump_filter_zero_when_writable() {
        use std::io::Write;

        assert!(disable_core_dumps());
        let path = "/proc/self/coredump_filter";
        let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) else {
            return; // best-effort: not writable in this environment (C25)
        };
        if f.write_all(b"0").is_err() {
            return;
        }
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(
            raw.trim(),
            "0",
            "coredump_filter should be cleared when writable (C25)"
        );
    }
}
