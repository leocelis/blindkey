//! UC-25 live-mount adapter (ADR-0009).
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
//! The real FUSE backend is **Linux-only** for v1 (ADR-0009/0010): CI mount tests run on Linux via
//! `fuser`'s pure-Rust `fusermount` path. On macOS and other platforms this crate still compiles,
//! but [`mount_volume`] returns [`Error::Unsupported`] — macOS mounting (macFUSE / Fuse-T) is Phase
//! C packaging work and is gated on a Fuse-T commercial-license review before shipping.

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
    /// Live mounting is not available on this platform in this build (see the crate docs).
    Unsupported(&'static str),
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

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::MountGuard;

/// Mount an already-unlocked [`Volume`] at `mountpoint` and return a [`MountGuard`] that keeps the
/// session alive. The volume is opened by the caller before this is called, so a bad password or a
/// tampered container fails **before** any mount fd exists (TOCTOU: fail closed). Default access is
/// read-write; the mount is torn down (and keys zeroized) when the guard drops.
///
/// On non-Linux platforms this returns [`Error::Unsupported`] (macOS mount is Phase C — ADR-0010).
#[cfg(target_os = "linux")]
pub fn mount_volume(volume: Volume, mountpoint: &Path) -> Result<MountGuard> {
    linux::mount_volume(volume, mountpoint)
}

/// A live mount handle. On non-Linux platforms it is never constructed (mounting is unsupported).
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct MountGuard {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
impl MountGuard {
    /// The mountpoint this guard is bound to (never reached on this platform).
    pub fn mountpoint(&self) -> &Path {
        Path::new("")
    }

    /// Explicitly unmount and flush (never reached on this platform).
    pub fn unmount(self) {}
}

/// Non-Linux stub: live mounting is unsupported in this build (ADR-0010). The volume is dropped
/// (and its keys zeroized) rather than mounted.
#[cfg(not(target_os = "linux"))]
pub fn mount_volume(volume: Volume, _mountpoint: &Path) -> Result<MountGuard> {
    // Flush and zeroize instead of leaking an unmounted, unlocked volume.
    let _ = volume.close();
    Err(Error::Unsupported(
        "live volume mount is only available on Linux in this build; on macOS use a Fuse-T / \
         macFUSE packaging build (Phase C), or `blindkey seal` for a cloud-safe archive",
    ))
}
