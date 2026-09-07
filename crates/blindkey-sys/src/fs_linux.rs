//! Linux hole-preserving copy helpers (UC-30 — FICLONE + SEEK_DATA/SEEK_HOLE).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Try `FICLONE` (reflink / CoW) from `src` onto a new `dst` file.
///
/// Returns `Ok(true)` on success, `Ok(false)` if the ioctl is unsupported or failed
/// (caller should fall back). Does not leave a partial `dst` on failure.
pub fn try_ficlone(src: &Path, dst: &Path) -> io::Result<bool> {
    let src_f = File::open(src)?;
    let dst_f = OpenOptions::new().write(true).create_new(true).open(dst)?;
    // FICLONE = _IOW(0x94, 9, int) on Linux.
    const FICLONE: libc::c_ulong = 0x4004_9409;
    // SAFETY: ioctl with two open fds; kernel validates. Failure → errno, not UB.
    let rc = unsafe { libc::ioctl(dst_f.as_raw_fd(), FICLONE, src_f.as_raw_fd()) };
    if rc == 0 {
        dst_f.sync_all()?;
        return Ok(true);
    }
    drop(dst_f);
    let _ = std::fs::remove_file(dst);
    Ok(false)
}

/// Copy `src` → `dst` preserving holes via `SEEK_DATA` / `SEEK_HOLE`.
///
/// Falls back to a dense sequential copy if seek-hole is unavailable.
pub fn copy_seek_hole(src: &Path, dst: &Path) -> io::Result<()> {
    let mut src_f = File::open(src)?;
    let len = src_f.metadata()?.len();
    let mut dst_f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)?;
    // Pre-size so holes exist.
    dst_f.set_len(len)?;

    let mut pos: u64 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        if pos >= len {
            break;
        }
        // SEEK_DATA = 3, SEEK_HOLE = 4 on Linux.
        let data = lseek_u64(src_f.as_raw_fd(), pos, 3);
        let data = match data {
            Ok(d) => d,
            Err(_) => {
                // SEEK_DATA unsupported — dense copy from pos.
                src_f.seek(SeekFrom::Start(pos))?;
                dst_f.seek(SeekFrom::Start(pos))?;
                io::copy(&mut src_f, &mut dst_f)?;
                dst_f.sync_all()?;
                return Ok(());
            }
        };
        if data >= len {
            break;
        }
        let hole = lseek_u64(src_f.as_raw_fd(), data, 4).unwrap_or(len);
        let hole = hole.min(len);
        src_f.seek(SeekFrom::Start(data))?;
        dst_f.seek(SeekFrom::Start(data))?;
        let mut remaining = hole.saturating_sub(data);
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            let read_n = src_f.read(&mut buf[..n])?;
            if read_n == 0 {
                break;
            }
            dst_f.write_all(&buf[..read_n])?;
            remaining -= read_n as u64;
        }
        pos = hole;
        if pos == data {
            // Avoid infinite loop if kernel returns same offset.
            pos = pos.saturating_add(1);
        }
    }
    dst_f.sync_all()?;
    Ok(())
}

/// Lowercased extended-attribute names on `path` (best-effort; empty on failure).
pub fn list_xattr_names(path: &Path) -> Vec<String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return Vec::new();
    };
    let mut buf = vec![0u8; 2048];
    // SAFETY: listxattr into a local buffer (Linux 3-arg form).
    let n = unsafe {
        libc::listxattr(
            c_path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n <= 0 {
        return Vec::new();
    }
    buf[..n as usize]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_ascii_lowercase())
        .collect()
}

fn lseek_u64(fd: i32, offset: u64, whence: i32) -> io::Result<u64> {
    // SAFETY: lseek on a valid fd; bad whence/offset → errno.
    let off = unsafe { libc::lseek(fd, offset as libc::off_t, whence) };
    if off < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(off as u64)
    }
}
