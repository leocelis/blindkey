//! macOS volume working-copy helpers (UC-30 W4).
//!
//! Safe wrappers only — ObjC messaging and `unsafe` stay in this module.
//! Checkin uses real [`NSFileCoordinator`] `ForReplacing`; ubiquitous / conflict
//! probes prefer Foundation resource values, with `mdls` as fallback.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2_foundation::{
    NSArray, NSError, NSFileCoordinator, NSFileCoordinatorWritingOptions, NSFileVersion, NSString,
    NSURLUbiquitousItemDownloadingStatusCurrent, NSURLUbiquitousItemDownloadingStatusDownloaded,
    NSURLUbiquitousItemDownloadingStatusKey, NSURLUbiquitousItemDownloadingStatusNotDownloaded,
    NSURLUbiquitousItemHasUnresolvedConflictsKey, NSURL,
};

/// Mark `path` excluded from Time Machine / device backup (`NSURLIsExcludedFromBackupKey`).
///
/// Best-effort: returns `false` when the attribute cannot be set.
pub fn exclude_from_backup(path: &Path) -> bool {
    // XML plist boolean true — same key NSURLIsExcludedFromBackupKey writes.
    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><true/></plist>"#;
    Command::new("/usr/bin/xattr")
        .args([
            "-w",
            "com.apple.metadata:com_apple_backup_excludeItem",
            PLIST,
        ])
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// True when the file carries `SF_DATALESS` (cloud placeholder / not fully materialised).
pub fn is_dataless(path: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat into a local buffer.
    if unsafe { libc::stat(c_path.as_ptr(), &mut st) } != 0 {
        return false;
    }
    // SF_DATALESS = 0x40000000 (sys/stat.h on modern macOS).
    const SF_DATALESS: u32 = 0x4000_0000;
    (st.st_flags & SF_DATALESS) != 0
}

/// Ubiquitous download status for iCloud / File Provider items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UbiquitousStatus {
    /// Not a ubiquitous item (local disk) — eligible for checkout.
    NotUbiquitous,
    /// `NSURLUbiquitousItemDownloadingStatusCurrent`.
    Current,
    /// `Downloaded` — stale local copy; refuse.
    Downloaded,
    /// `NotDownloaded` — refuse.
    NotDownloaded,
    /// Could not determine (fail closed when under CloudStorage / Mobile Documents).
    Unknown,
}

/// Probe `NSURLUbiquitousItemDownloadingStatusKey` via Foundation, then `mdls`.
///
/// Fail closed: dataless → NotDownloaded; cloud-looking path with unknown status → Unknown.
pub fn ubiquitous_download_status(path: &Path) -> UbiquitousStatus {
    if is_dataless(path) {
        return UbiquitousStatus::NotDownloaded;
    }
    if let Some(status) = nsurl_ubiquitous_status(path) {
        return status;
    }
    if let Some(status) = mdls_ubiquitous_status(path) {
        return status;
    }
    let s = path.to_string_lossy().to_ascii_lowercase();
    if s.contains("/library/mobile documents/")
        || s.contains("/library/cloudstorage/")
        || s.contains("com~apple~clouddocs")
    {
        return UbiquitousStatus::Unknown;
    }
    UbiquitousStatus::NotUbiquitous
}

fn path_to_url(path: &Path) -> Retained<NSURL> {
    let s = NSString::from_str(&path.to_string_lossy());
    NSURL::fileURLWithPath(&s)
}

fn nsurl_ubiquitous_status(path: &Path) -> Option<UbiquitousStatus> {
    let url = path_to_url(path);
    // SAFETY: Foundation exports these as immutable string constants.
    let (status_key, not_dl, dl, current) = unsafe {
        (
            NSURLUbiquitousItemDownloadingStatusKey,
            NSURLUbiquitousItemDownloadingStatusNotDownloaded,
            NSURLUbiquitousItemDownloadingStatusDownloaded,
            NSURLUbiquitousItemDownloadingStatusCurrent,
        )
    };
    let keys = NSArray::from_slice(&[status_key]);
    let values = url.resourceValuesForKeys_error(&keys).ok()?;
    let Some(obj) = values.objectForKey(status_key) else {
        return Some(UbiquitousStatus::NotUbiquitous);
    };
    // Values are NSString status constants.
    let status = obj.downcast_ref::<NSString>()?;
    let raw = status.to_string();
    if raw.is_empty() {
        return Some(UbiquitousStatus::NotUbiquitous);
    }
    if status.isEqualToString(not_dl) {
        return Some(UbiquitousStatus::NotDownloaded);
    }
    if status.isEqualToString(dl) {
        return Some(UbiquitousStatus::Downloaded);
    }
    if status.isEqualToString(current) {
        return Some(UbiquitousStatus::Current);
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("notdownloaded") {
        return Some(UbiquitousStatus::NotDownloaded);
    }
    if lower.contains("downloaded") && !lower.contains("current") {
        return Some(UbiquitousStatus::Downloaded);
    }
    if lower.contains("current") {
        return Some(UbiquitousStatus::Current);
    }
    Some(UbiquitousStatus::Unknown)
}

fn mdls_ubiquitous_status(path: &Path) -> Option<UbiquitousStatus> {
    let out = Command::new("/usr/bin/mdls")
        .args(["-raw", "-name", "NSURLUbiquitousItemDownloadingStatusKey"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    let t = raw.trim();
    if t.is_empty() || t == "(null)" {
        return Some(UbiquitousStatus::NotUbiquitous);
    }
    let lower = t.to_ascii_lowercase();
    if lower.contains("notdownloaded") || lower.contains("not_downloaded") {
        return Some(UbiquitousStatus::NotDownloaded);
    }
    if lower.contains("downloaded")
        && !lower.contains("current")
        && (lower.contains("ubiquitousitemdownloadingstatusdownloaded")
            || lower.ends_with("downloaded"))
    {
        return Some(UbiquitousStatus::Downloaded);
    }
    if lower.contains("current") {
        return Some(UbiquitousStatus::Current);
    }
    None
}

/// True when unresolved `NSFileVersion` / iCloud conflict siblings look present (E9).
pub fn has_unresolved_conflicts(path: &Path) -> bool {
    if nsfileversion_has_conflict(path) {
        return true;
    }
    if nsurl_has_conflict_flag(path) {
        return true;
    }
    if mdls_has_conflict(path) {
        return true;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let Ok(rd) = std::fs::read_dir(parent) else {
        return false;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if s.ends_with(".icloud") && s.contains(stem) {
            return true;
        }
        let lower = s.to_ascii_lowercase();
        if lower.contains("conflict") && lower.contains(&stem.to_ascii_lowercase()) {
            return true;
        }
    }
    false
}

fn nsfileversion_has_conflict(path: &Path) -> bool {
    let url = path_to_url(path);
    match NSFileVersion::unresolvedConflictVersionsOfItemAtURL(&url) {
        Some(arr) => arr.count() > 0,
        None => false,
    }
}

fn nsurl_has_conflict_flag(path: &Path) -> bool {
    use objc2::msg_send;
    use objc2::runtime::AnyObject;

    let url = path_to_url(path);
    let mut value: Option<Retained<AnyObject>> = None;
    // SAFETY: Foundation export; getResourceValue writes into `value`.
    let key = unsafe { NSURLUbiquitousItemHasUnresolvedConflictsKey };
    if unsafe { url.getResourceValue_forKey_error(&mut value, key) }.is_err() {
        return false;
    }
    let Some(obj) = value else {
        return false;
    };
    // NSNumber `-boolValue`.
    let flag: bool = unsafe { msg_send![&*obj, boolValue] };
    flag
}

fn mdls_has_conflict(path: &Path) -> bool {
    let out = Command::new("/usr/bin/mdls")
        .args([
            "-raw",
            "-name",
            "NSURLUbiquitousItemHasUnresolvedConflictsKey",
        ])
        .arg(path)
        .output();
    let Ok(out) = out else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    let t = raw.trim().to_ascii_lowercase();
    t == "1" || t == "true" || t == "yes"
}

/// Atomically replace `dest` with `src` using `rename(2)` (CLI path).
pub fn posix_replace(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::rename(src, dest)
}

/// Coordinated replace for File Provider / iCloud (UC-30 §6.1 GUI macOS / C100).
///
/// Uses `NSFileCoordinator` writing with `ForReplacing`. Stages a same-directory
/// sibling when `src` and `dest` are on different parents, then renames inside the
/// coordinator accessor. Falls back to POSIX rename if the coordinator returns an error
/// that looks like a missing presenter stack (rare); primary path is ObjC.
pub fn coordinated_replace(src: &Path, dest: &Path) -> std::io::Result<()> {
    let (src_for_rename, staged_cleanup): (PathBuf, Option<PathBuf>) =
        if src.parent() == dest.parent() {
            (src.to_path_buf(), None)
        } else {
            let parent = dest.parent().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "dest has no parent")
            })?;
            let staged = parent.join(format!(".bk-coord-{}.tmp", std::process::id()));
            std::fs::copy(src, &staged)?;
            {
                use std::fs::File;
                let f = File::open(&staged)?;
                f.sync_all()?;
            }
            (staged.clone(), Some(staged))
        };

    let dest_url = path_to_url(dest);
    let coordinator = NSFileCoordinator::new();
    let mut err: Option<Retained<NSError>> = None;
    let result = Arc::new(Mutex::new(Ok::<(), std::io::Error>(())));
    let result2 = Arc::clone(&result);
    let src_owned = src_for_rename.clone();
    let block = RcBlock::new(move |new_url: NonNull<NSURL>| {
        let url = unsafe { new_url.as_ref() };
        let Some(ns_path) = url.path() else {
            *result2.lock().unwrap_or_else(|p| p.into_inner()) = Err(std::io::Error::other(
                "NSFileCoordinator returned empty path",
            ));
            return;
        };
        let dest_now = PathBuf::from(ns_path.to_string());
        // If dest already exists, rename over it (APFS same-volume replace).
        if dest_now.exists() {
            let _ = std::fs::remove_file(&dest_now);
        }
        if let Err(e) = std::fs::rename(&src_owned, &dest_now) {
            *result2.lock().unwrap_or_else(|p| p.into_inner()) = Err(e);
        }
    });
    coordinator.coordinateWritingItemAtURL_options_error_byAccessor(
        &dest_url,
        NSFileCoordinatorWritingOptions::ForReplacing,
        Some(&mut err),
        &block,
    );

    if let Some(e) = err {
        if let Some(p) = &staged_cleanup {
            let _ = std::fs::remove_file(p);
        }
        // Last-resort POSIX path so a broken ObjC runtime cannot brick checkin.
        match posix_replace_staged(&src_for_rename, dest, staged_cleanup.is_some()) {
            Ok(()) => return Ok(()),
            Err(posix_err) => {
                return Err(std::io::Error::other(format!(
                    "NSFileCoordinator: {}; posix fallback: {posix_err}",
                    e.localizedDescription()
                )));
            }
        }
    }

    let guard = result.lock().unwrap_or_else(|p| p.into_inner());
    match &*guard {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(p) = &staged_cleanup {
                let _ = std::fs::remove_file(p);
            }
            Err(std::io::Error::new(e.kind(), e.to_string()))
        }
    }
}

fn posix_replace_staged(src: &Path, dest: &Path, src_is_staged: bool) -> std::io::Result<()> {
    match std::fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) => {
            if src_is_staged {
                let _ = std::fs::remove_file(src);
            }
            Err(e)
        }
    }
}

/// True when a macFUSE runtime install looks present (bundle / dylib / mount helper).
///
/// Detection only — Blindkey never embeds or redistributes macFUSE (ADR-0010).
pub fn macfuse_available() -> bool {
    const PATHS: &[&str] = &[
        "/Library/Filesystems/macfuse.fs",
        "/Library/Filesystems/osxfuse.fs",
        "/usr/local/lib/libfuse.dylib",
        "/usr/local/lib/libfuse.2.dylib",
        "/usr/local/lib/libosxfuse.2.dylib",
        "/opt/homebrew/lib/libfuse.dylib",
        "/opt/homebrew/lib/libfuse.2.dylib",
        "/opt/local/lib/libfuse.dylib",
        "/usr/local/bin/mount_macfuse",
        "/usr/sbin/mount_macfuse",
        "/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse",
    ];
    PATHS.iter().any(|p| Path::new(p).exists())
}

/// Lowercased extended-attribute names on `path` (best-effort; empty on failure).
pub fn list_xattr_names(path: &Path) -> Vec<String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return Vec::new();
    };
    let mut buf = vec![0u8; 2048];
    // SAFETY: listxattr into a local buffer (macOS takes options).
    let n = unsafe {
        libc::listxattr(
            c_path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            0,
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
