//! UC-25 local encrypted volume CLI — `blindkey volume …` (Phase B).
//!
//! Mirrors `commands/sealed.rs`: a thin shell over `blindkey_core::volume`. All crypto stays in
//! core; the live-mount adapter lives in the `blindkey-fuse` crate and is only linked under the
//! `volume-mount` Cargo feature (ADR-0009). Passwords come from the shared unlock channels
//! (TTY / `--password-fd` / `--password-stdin` / `BLINDKEY_PASSWORD_FILE`) — never argv (C31).

use std::path::{Path, PathBuf};

use blindkey_core::pad::PadMode;
use blindkey_core::{Error, Volume, VolumeCreateOpts, VolumeUnlock, VOLUME_OPEN_ERROR};
use zeroize::Zeroizing;

use super::{pre_release_notice, OpenOpts, USAGE_ERROR_PREFIX};
use crate::unlock_secret;

type CmdResult = Result<(), String>;

/// `blindkey volume <action>` subcommands (clap).
#[derive(Debug, clap::Subcommand)]
pub enum VolumeAction {
    /// Create a new encrypted volume (`.vltd`).
    Create {
        /// Output volume path (`.vltd`).
        path: PathBuf,
        /// Logical size, e.g. `64M` or `1G` (K/M/G/T = KiB/MiB/GiB/TiB).
        #[arg(long)]
        size: String,
        /// Maximum logical size (defaults to `--size`).
        #[arg(long)]
        max_size: Option<String>,
        /// Data-block plaintext capacity in KiB.
        #[arg(long, default_value_t = 32)]
        block_size_kib: u16,
        /// Disable Padmé size-padding (default: on — C71).
        #[arg(long)]
        no_pad: bool,
        /// Allow Argon2id params below the enforced floor (tests/scripts only).
        #[arg(long, hide = true)]
        allow_weak_kdf: bool,
    },
    /// Mount a volume as a folder (Linux `fuser`; macOS via Fuse-T/macFUSE when packaged).
    Mount {
        /// Volume path (`.vltd`).
        path: PathBuf,
        /// Directory to mount at (must exist).
        mountpoint: PathBuf,
        /// Override the refusal to mount a live volume under a cloud-sync folder (UNSUPPORTED).
        #[arg(long)]
        force_local: bool,
    },
    /// Unmount a mounted volume.
    Umount {
        /// The mountpoint to unmount.
        mountpoint: PathBuf,
    },
    /// Change the advisory logical size of a volume.
    Resize {
        /// Volume path (`.vltd`).
        path: PathBuf,
        /// New logical size, e.g. `128M`.
        #[arg(long)]
        size: String,
    },
    /// Show volume metadata after unlock (size, padding, block size — no secrets).
    Status {
        /// Volume path (`.vltd`).
        path: PathBuf,
    },
    /// Trust the current volume state on this device (writes the local freshness anchor — C70).
    TrustAnchor {
        /// Volume path (`.vltd`).
        path: PathBuf,
    },
    /// Re-wrap the volume header under new Argon2id parameters (block data unchanged).
    UpgradeKdf {
        /// Volume path (`.vltd`).
        path: PathBuf,
        /// Argon2id memory cost in KiB (default 64 MiB).
        #[arg(long, default_value_t = 65_536)]
        kdf_m_cost: u32,
        /// Argon2id time cost (default 3).
        #[arg(long, default_value_t = 3)]
        kdf_t_cost: u32,
        /// Argon2id parallelism (default 4).
        #[arg(long, default_value_t = 4)]
        kdf_p_cost: u32,
    },
}

fn usage_err(msg: impl Into<String>) -> String {
    format!("{USAGE_ERROR_PREFIX} {}", msg.into())
}

/// Map a core open/unlock error to the uniform text (parity with `sealed::map_open_err`).
fn map_open_err(e: Error) -> String {
    match e {
        Error::HeaderAuth => unlock_secret::auth_err("wrong password or tampered header"),
        Error::WrongContainerKind => "wrong container type for this command".to_string(),
        Error::VolumeAnchorMismatch => e.to_string(),
        Error::Io(e) => e.to_string(),
        _ => VOLUME_OPEN_ERROR.to_string(),
    }
}

/// Cloud-sync folder markers checked with a simple case-sensitive path substring test (C73). This
/// is deliberately conservative: a live read-write `.vltd` inside a syncing folder is UNSUPPORTED.
const SYNC_ROOT_MARKERS: &[&str] = &[
    "Dropbox",
    ".dropbox",
    "Google Drive",
    "GoogleDrive",
    "CloudStorage", // macOS ~/Library/CloudStorage/{OneDrive,GoogleDrive,Dropbox}-…
    "OneDrive",
    "iCloud",
    "Mobile Documents",     // iCloud Drive container
    "com~apple~CloudDocs",  // iCloud Drive documents
];

/// Return the sync-root marker matched by `path`, if any.
fn detect_sync_root(path: &Path) -> Option<&'static str> {
    let s = path.to_string_lossy();
    SYNC_ROOT_MARKERS.iter().copied().find(|m| s.contains(m))
}

/// Refuse (or, with `--force-local`, warn about) mounting a live volume under a cloud-sync folder.
/// Always points to `blindkey seal` as the cloud-safe alternative (C73 / MNT-02).
fn sync_root_guard(path: &Path, force_local: bool) -> CmdResult {
    match detect_sync_root(path) {
        Some(marker) if !force_local => Err(usage_err(format!(
            "refusing to mount a live read-write volume under a cloud-sync folder ({marker}). \
             Syncing a mounted volume is UNSUPPORTED and can corrupt it (C73). Use \
             `blindkey seal <PATH>` for a cloud-safe encrypted archive, or pass --force-local to \
             override (unsupported)."
        ))),
        Some(marker) => {
            eprintln!(
                "warning: --force-local — mounting under a cloud-sync folder ({marker}) is \
                 UNSUPPORTED; do not let the backend sync the volume while it is mounted."
            );
            Ok(())
        }
        None => Ok(()),
    }
}

/// Parse a human size like `64M`, `1G`, `512K`, `1048576` into bytes (K/M/G/T = powers of 1024).
fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err(usage_err("size cannot be empty"));
    }
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, suffix) = t.split_at(split);
    if num.is_empty() {
        return Err(usage_err(format!("invalid size {s:?}")));
    }
    let n: u64 = num
        .parse()
        .map_err(|_| usage_err(format!("invalid size {s:?}")))?;
    let mult: u64 = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024_u64 * 1024 * 1024 * 1024,
        other => {
            return Err(usage_err(format!(
                "unknown size suffix {other:?} (use K, M, G, or T)"
            )))
        }
    };
    n.checked_mul(mult)
        .ok_or_else(|| usage_err("size too large"))
}

/// Format a byte count for human display in `status` (never secret).
fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut val = bytes as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.1} {} ({bytes} bytes)", UNITS[unit])
    }
}

/// Owned password + optional keyfile bytes; borrowed by [`build_unlock`] to form a `VolumeUnlock`.
type UnlockMaterial = (Zeroizing<String>, Option<Zeroizing<Vec<u8>>>);

/// Read the master password, then build a `VolumeUnlock` (keyfile stanza when `--keyfile` given).
/// The returned buffers must outlive the `VolumeUnlock` — the caller owns them.
fn read_unlock_material(confirm: bool, opts: &OpenOpts) -> Result<UnlockMaterial, String> {
    let password = unlock_secret::read_master_password(confirm, &opts.unlock)?;
    let keyfile = match opts.keyfile.as_ref() {
        Some(p) => Some(Zeroizing::new(
            std::fs::read(p).map_err(|e| format!("cannot read keyfile {}: {e}", p.display()))?,
        )),
        None => None,
    };
    Ok((password, keyfile))
}

fn build_unlock<'a>(
    password: &'a Zeroizing<String>,
    keyfile: &'a Option<Zeroizing<Vec<u8>>>,
) -> VolumeUnlock<'a> {
    VolumeUnlock {
        password: password.as_bytes(),
        keyfile: keyfile.as_ref().map(|k| k.as_slice()),
    }
}

/// Route a `volume` subcommand to its handler.
pub fn dispatch(opts: &OpenOpts, action: VolumeAction) -> CmdResult {
    match action {
        VolumeAction::Create {
            path,
            size,
            max_size,
            block_size_kib,
            no_pad,
            allow_weak_kdf,
        } => cmd_create(
            &path,
            &size,
            max_size.as_deref(),
            block_size_kib,
            no_pad,
            allow_weak_kdf,
            opts,
        ),
        VolumeAction::Mount {
            path,
            mountpoint,
            force_local,
        } => cmd_mount(&path, &mountpoint, force_local, opts),
        VolumeAction::Umount { mountpoint } => cmd_umount(&mountpoint),
        VolumeAction::Resize { path, size } => cmd_resize(&path, &size, opts),
        VolumeAction::Status { path } => cmd_status(&path, opts),
        VolumeAction::TrustAnchor { path } => cmd_trust_anchor(&path, opts),
        VolumeAction::UpgradeKdf {
            path,
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
        } => cmd_upgrade_kdf(&path, kdf_m_cost, kdf_t_cost, kdf_p_cost, opts),
    }
}

// ─── commands ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_create(
    path: &Path,
    size: &str,
    max_size: Option<&str>,
    block_size_kib: u16,
    no_pad: bool,
    allow_weak_kdf: bool,
    opts: &OpenOpts,
) -> CmdResult {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing file {}",
            path.display()
        ));
    }
    let size_bytes = parse_size(size)?;
    let max_bytes = match max_size {
        Some(m) => parse_size(m)?,
        None => size_bytes,
    };
    if max_bytes < size_bytes {
        return Err(usage_err("--max-size must be >= --size"));
    }
    pre_release_notice();

    let (password, keyfile) = read_unlock_material(true, opts)?;
    let unlock = build_unlock(&password, &keyfile);
    let vopts = VolumeCreateOpts {
        size_bytes,
        max_bytes,
        block_size_kib,
        pad_mode: if no_pad { PadMode::None } else { PadMode::Padme },
        allow_weak_kdf,
        ..VolumeCreateOpts::default()
    };
    eprintln!("Deriving key (Argon2id)…");
    let vol = Volume::create(path, &unlock, &vopts).map_err(|e| e.to_string())?;
    // Trust the freshly created state on this device so later opens get rollback protection (C70).
    vol.trust_anchor().map_err(|e| e.to_string())?;
    vol.close().map_err(|e| e.to_string())?;
    eprintln!("Created volume at {}.", path.display());
    Ok(())
}

fn cmd_mount(path: &Path, mountpoint: &Path, force_local: bool, opts: &OpenOpts) -> CmdResult {
    if !path.is_file() {
        return Err(format!("{}: not a volume file", path.display()));
    }
    if !mountpoint.is_dir() {
        return Err(usage_err(format!(
            "mountpoint {} does not exist or is not a directory",
            mountpoint.display()
        )));
    }
    sync_root_guard(path, force_local)?;

    // Residual-cleartext honesty (C27 does NOT cover a mounted tree — MNT-04 banner).
    eprintln!(
        "note: while mounted, files are cleartext to the OS and to any process (or AI agent) with \
         filesystem access — the same class as an unlocked FileVault/LUKS volume. Unmount when done."
    );

    // TOCTOU: open + unlock the volume BEFORE any mount fd exists; a bad factor fails closed here.
    let (password, keyfile) = read_unlock_material(false, opts)?;
    let unlock = build_unlock(&password, &keyfile);
    eprintln!("Deriving key (Argon2id)…");
    let vol = Volume::open(path, &unlock).map_err(map_open_err)?;
    run_mount(vol, mountpoint)
}

#[cfg(feature = "volume-mount")]
fn run_mount(vol: Volume, mountpoint: &Path) -> CmdResult {
    let _guard = blindkey_fuse::mount_volume(vol, mountpoint).map_err(|e| e.to_string())?;
    eprintln!("Mounted at {}.", mountpoint.display());
    eprintln!(
        "Unmount with `blindkey volume umount {}` (or `fusermount -u`). Press Ctrl-C to stop.",
        mountpoint.display()
    );
    // Keep the process (and therefore the mount + guard) alive until signaled/unmounted.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(not(feature = "volume-mount"))]
fn run_mount(vol: Volume, _mountpoint: &Path) -> CmdResult {
    // Flush + zeroize the volume we just opened rather than leaking it unlocked.
    let _ = vol.close();
    Err(
        "this build has no mount support — reinstall with `cargo install blindkey-cli --features \
         volume-mount` (Linux; macOS needs a Fuse-T/macFUSE packaging build). Use `blindkey seal` \
         for a portable encrypted archive."
            .to_string(),
    )
}

fn cmd_umount(mountpoint: &Path) -> CmdResult {
    // Try the userspace helpers first (Linux), then a plain umount. No secrets involved.
    let attempts: &[(&str, &[&str])] = &[
        ("fusermount", &["-u"]),
        ("fusermount3", &["-u"]),
        ("umount", &[]),
    ];
    for (bin, args) in attempts {
        let mut cmd = std::process::Command::new(bin);
        cmd.args(*args).arg(mountpoint);
        match cmd.status() {
            Ok(status) if status.success() => {
                eprintln!("Unmounted {}.", mountpoint.display());
                return Ok(());
            }
            _ => continue,
        }
    }
    Err(format!(
        "could not unmount {} — try `fusermount -u {}` or `umount {}` manually",
        mountpoint.display(),
        mountpoint.display(),
        mountpoint.display()
    ))
}

fn cmd_resize(path: &Path, size: &str, opts: &OpenOpts) -> CmdResult {
    let new_size = parse_size(size)?;
    let (password, keyfile) = read_unlock_material(false, opts)?;
    let unlock = build_unlock(&password, &keyfile);
    eprintln!("Deriving key (Argon2id)…");
    let mut vol = Volume::open(path, &unlock).map_err(map_open_err)?;
    vol.resize(new_size).map_err(|_| {
        usage_err(format!(
            "new size {} exceeds the volume's maximum ({})",
            human_size(new_size),
            human_size(vol.max_bytes())
        ))
    })?;
    vol.close().map_err(|e| e.to_string())?;
    eprintln!("Resized {} to {}.", path.display(), human_size(new_size));
    Ok(())
}

fn cmd_status(path: &Path, opts: &OpenOpts) -> CmdResult {
    let (password, keyfile) = read_unlock_material(false, opts)?;
    let unlock = build_unlock(&password, &keyfile);
    eprintln!("Deriving key (Argon2id)…");
    let vol = Volume::open(path, &unlock).map_err(map_open_err)?;
    let entries = vol.list("").map_err(|e| e.to_string())?;
    // Metadata only — no file contents, no key material (C27/C71).
    println!("path:        {}", path.display());
    println!("size:        {}", human_size(vol.size_bytes()));
    println!("max size:    {}", human_size(vol.max_bytes()));
    println!("block size:  {} KiB", vol.block_size_kib());
    println!(
        "padding:     {}",
        match vol.pad_mode() {
            PadMode::Padme => "Padmé (size hidden)",
            PadMode::None => "none",
        }
    );
    println!("version:     {}", vol.version());
    println!("top-level entries: {}", entries.len());
    Ok(())
}

fn cmd_trust_anchor(path: &Path, opts: &OpenOpts) -> CmdResult {
    let (password, keyfile) = read_unlock_material(false, opts)?;
    let unlock = build_unlock(&password, &keyfile);
    eprintln!("Deriving key (Argon2id)…");
    // Open ignoring the anchor: this is the new-device trust path (C70 / MSV-19).
    let vol = Volume::open_ignoring_anchor(path, &unlock).map_err(map_open_err)?;
    vol.trust_anchor().map_err(|e| e.to_string())?;
    eprintln!(
        "Trusted the current state of {} on this device (freshness anchor written).",
        path.display()
    );
    Ok(())
}

fn cmd_upgrade_kdf(path: &Path, m: u32, t: u32, p: u32, opts: &OpenOpts) -> CmdResult {
    blindkey_core::crypto::reject_kdf_below_floor(m, t, p).map_err(|e| e.to_string())?;
    let (password, keyfile) = read_unlock_material(false, opts)?;
    let unlock = build_unlock(&password, &keyfile);
    eprintln!("Deriving key (Argon2id)…");
    let mut vol = Volume::open(path, &unlock).map_err(map_open_err)?;
    eprintln!("Re-deriving with Argon2id (m={m} KiB, t={t}, p={p})…");
    vol.upgrade_kdf(&unlock, m, t, p).map_err(|e| e.to_string())?;
    eprintln!("Upgraded KDF parameters (block data unchanged).");
    Ok(())
}

/// `blindkey peek PATH.vltd` — list the inner tree (paths + sizes) after unlock, never contents.
pub fn cmd_peek(path: &Path, opts: &OpenOpts) -> CmdResult {
    let (password, keyfile) = read_unlock_material(false, opts)?;
    let unlock = build_unlock(&password, &keyfile);
    eprintln!("Deriving key (Argon2id)…");
    let vol = Volume::open(path, &unlock).map_err(map_open_err)?;

    // Walk the tree breadth-first from the root, printing path + size (dirs show as <dir>).
    let mut stack = vec![String::new()];
    let mut rows: Vec<(String, String)> = Vec::new();
    while let Some(dir) = stack.pop() {
        let mut children = vol.list(&dir).map_err(|e| e.to_string())?;
        children.sort();
        for name in children {
            let child = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            match vol.node_kind(&child) {
                Some(blindkey_core::NodeKind::Dir) => {
                    rows.push((child.clone(), "<dir>".to_string()));
                    stack.push(child);
                }
                Some(blindkey_core::NodeKind::File(len)) => {
                    rows.push((child, len.to_string()));
                }
                None => {}
            }
        }
    }

    if rows.is_empty() {
        eprintln!("(empty volume)");
        return Ok(());
    }
    rows.sort();
    let mut width = 4usize;
    for (p, _) in &rows {
        width = width.max(p.len());
    }
    for (p, size) in &rows {
        // Paths are user-controlled → sanitize before the terminal (C28).
        println!("{:<width$}  {:>10}", crate::terminal::sanitize_for_terminal(p), size);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_refuses_sync_roots() {
        // Refuse under common cloud-sync roots without --force-local (C73).
        for p in [
            "/Users/leo/Dropbox/work.vltd",
            "/Users/leo/Library/CloudStorage/OneDrive-Personal/work.vltd",
            "/home/leo/OneDrive/work.vltd",
            "/Users/leo/Google Drive/work.vltd",
            "/Users/leo/Library/Mobile Documents/com~apple~CloudDocs/work.vltd",
        ] {
            let path = Path::new(p);
            assert!(detect_sync_root(path).is_some(), "should detect: {p}");
            assert!(
                sync_root_guard(path, false).is_err(),
                "should refuse without --force-local: {p}"
            );
            // --force-local downgrades the refusal to a warning.
            assert!(
                sync_root_guard(path, true).is_ok(),
                "should allow with --force-local: {p}"
            );
        }
    }

    #[test]
    fn allows_local_paths() {
        for p in ["/tmp/work.vltd", "/home/leo/vaults/work.vltd", "./work.vltd"] {
            let path = Path::new(p);
            assert!(detect_sync_root(path).is_none(), "should be local: {p}");
            assert!(sync_root_guard(path, false).is_ok(), "should allow: {p}");
        }
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("64M").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512K").unwrap(), 512 * 1024);
        assert!(parse_size("").is_err());
        assert!(parse_size("M").is_err());
        assert!(parse_size("10X").is_err());
    }
}
