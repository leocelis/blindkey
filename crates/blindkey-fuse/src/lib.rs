//! UC-25 live-mount adapter (ADR-0009 / ADR-0010).
//!
//! Maps a userspace FUSE session onto an already-unlocked [`blindkey_core::Volume`]. This crate
//! contains **no** cryptography, key unwrap, KDF, or AEAD — every secret operation stays inside
//! `blindkey-core`. The adapter only translates FUSE requests into the `Volume` virtual-FS API and
//! owns the mount lifecycle:
//!
//! - The caller opens/unlocks the `Volume` first, then hands it to [`mount_volume`] (TOCTOU: the
//!   volume is proven openable before any mount fd exists; on failure we never mount — fail closed).
//! - A [`MountGuard`] owns the background FUSE session. On `Drop` it unmounts, flushes the volume
//!   ([`blindkey_core::Volume::sync`]), and lets the `Volume` drop — zeroizing key material (C11/C72).
//! - No path contents or secrets are ever logged (C23/C72): this crate performs no logging at all.
//!
//! ## Platform support
//!
//! | Platform | Default build | Optional |
//! |----------|---------------|----------|
//! | Linux | real FUSE via `fuser` (pure-Rust `fusermount`) | — |
//! | macOS | stub → callers use `MaterializedMount` | `--features macos-fuse` against **user-installed** [macFUSE](https://macfuse.io) (no bundled Fuse-T) |
//!
//! Blindkey does **not** redistribute macFUSE or Fuse-T (ADR-0010).

#![forbid(unsafe_code)]

use std::path::Path;

use blindkey_core::Volume;

/// Errors returned when establishing a mount. Runtime FUSE request errors are reported to the
/// kernel via `errno` and never surface here.
#[derive(Debug)]
pub enum Error {
    /// The FUSE session could not be established (mountpoint missing, no `fusermount`, no
    /// permission, provider not installed, …).
    Mount(std::io::Error),
    /// Live mounting is not available in this build / environment (see the crate docs).
    Unsupported(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Mount(e) => write!(f, "could not mount volume: {e}"),
            Error::Unsupported(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Mount(e) => Some(e),
            Error::Unsupported(_) => None,
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "macos-fuse")
))]
mod session;

#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "macos-fuse")
))]
pub use session::MountGuard;

/// True when a macFUSE runtime install looks present (filesystem bundle / mount helper / dylib).
///
/// Does **not** require the `macos-fuse` Cargo feature — safe to call from any macOS build so UX
/// can say “install macFUSE” vs “rebuild with `--features macos-fuse`”.
#[cfg(target_os = "macos")]
pub fn macfuse_available() -> bool {
    blindkey_sys::macfuse_available()
}

/// Non-macOS: macFUSE is never present.
#[cfg(not(target_os = "macos"))]
pub fn macfuse_available() -> bool {
    false
}

/// Mount an already-unlocked [`Volume`] at `mountpoint` and return a [`MountGuard`] that keeps the
/// session alive. The volume is opened by the caller before this is called, so a bad password or a
/// tampered container fails **before** any mount fd exists (TOCTOU: fail closed).
#[cfg(target_os = "linux")]
pub fn mount_volume(volume: Volume, mountpoint: &Path) -> Result<MountGuard> {
    session::mount_volume(volume, mountpoint)
}

/// macOS FUSE mount against user-installed macFUSE (`macos-fuse` feature).
#[cfg(all(target_os = "macos", feature = "macos-fuse"))]
pub fn mount_volume(volume: Volume, mountpoint: &Path) -> Result<MountGuard> {
    if !macfuse_available() {
        let _ = volume.close();
        return Err(Error::Unsupported(
            "macFUSE is not installed. Install from https://macfuse.io (do not redistribute \
             with Blindkey — ADR-0010), then retry. Blindfolder can still open a cleartext \
             working folder without FUSE."
                .into(),
        ));
    }
    session::mount_volume(volume, mountpoint)
}

/// macOS stub when this binary was built without `macos-fuse` (default OSS builds).
#[cfg(all(target_os = "macos", not(feature = "macos-fuse")))]
#[derive(Debug)]
pub struct MountGuard {
    _private: (),
}

#[cfg(all(target_os = "macos", not(feature = "macos-fuse")))]
impl MountGuard {
    /// The mountpoint this guard is bound to (never reached without `macos-fuse`).
    pub fn mountpoint(&self) -> &Path {
        Path::new("")
    }

    /// Explicitly unmount and flush (never reached without `macos-fuse`).
    pub fn unmount(self) {}
}

#[cfg(all(target_os = "macos", not(feature = "macos-fuse")))]
pub fn mount_volume(volume: Volume, _mountpoint: &Path) -> Result<MountGuard> {
    let _ = volume.close();
    let msg = if macfuse_available() {
        "macFUSE is installed, but this Blindkey binary was built without `--features macos-fuse`. \
         Rebuild with that feature to enable live FUSE mounts (ADR-0010). Blindfolder still works \
         via a cleartext working folder."
            .to_string()
    } else {
        "live FUSE mount on macOS requires user-installed macFUSE (https://macfuse.io) and a \
         Blindkey build with `--features macos-fuse`. Blindfolder opens a cleartext working folder \
         instead (ADR-0010 — Blindkey does not bundle Fuse-T/macFUSE)."
            .to_string()
    };
    Err(Error::Unsupported(msg))
}

/// Other platforms: unsupported.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Debug)]
pub struct MountGuard {
    _private: (),
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl MountGuard {
    /// Never reached on this platform.
    pub fn mountpoint(&self) -> &Path {
        Path::new("")
    }

    /// Never reached on this platform.
    pub fn unmount(self) {}
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn mount_volume(volume: Volume, _mountpoint: &Path) -> Result<MountGuard> {
    let _ = volume.close();
    Err(Error::Unsupported(
        "live volume mount is only available on Linux, or on macOS with user-installed macFUSE \
         and `--features macos-fuse`"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn macfuse_probe_does_not_panic() {
        let _ = super::macfuse_available();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn macfuse_probe_false_off_macos() {
        assert!(!super::macfuse_available());
    }
}
