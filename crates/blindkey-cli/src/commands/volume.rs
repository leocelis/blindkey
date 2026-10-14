//! UC-25 local encrypted volume CLI — `blindkey volume …` (Phase B).
//!
//! Mirrors `commands/sealed.rs`: a thin shell over `blindkey_core::volume`. All crypto stays in
//! core; the live-mount adapter lives in the `blindkey-fuse` crate and is only linked under the
//! `volume-mount` Cargo feature (ADR-0009). Passwords come from the shared unlock channels
//! (TTY / `--password-fd` / `--password-stdin` / `BLINDKEY_PASSWORD_FILE`) — never argv (C31).

use std::path::{Path, PathBuf};

use blindkey_core::pad::PadMode;
use blindkey_core::{
    is_under_sync_root, orphan_work_sessions, CheckoutOpts, Error, Volume, VolumeCreateOpts,
    VolumeUnlock, WorkPhase, WorkingCopySession, VOLUME_OPEN_ERROR, WORKING_COPY_ERROR,
};
use zeroize::Zeroizing;

use super::{pre_release_notice, OpenOpts, USAGE_ERROR_PREFIX};
use crate::unlock_secret;

type CmdResult = Result<(), String>;

/// UC-30 E1 fingerprint mismatch (exit 10).
pub const WORK_E1_PREFIX: &str = "work-e1:";
/// UC-30 E5 hydration refuse (exit 11).
pub const WORK_E5_PREFIX: &str = "work-e5:";
/// UC-30 E6 work path under sync root (exit 12).
pub const WORK_E6_PREFIX: &str = "work-e6:";
/// UC-30 E8 rename/replace fail (exit 13).
pub const WORK_E8_PREFIX: &str = "work-e8:";

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
    /// UC-30: copy a sync-folder `.vltd` to a local working path (does not mount unless `--mount`).
    Checkout {
        /// Sync-folder (or any) volume path (`.vltd`).
        path: PathBuf,
        /// Override work root (default: platform `…/blindkey/volumes/work`).
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// After checkout, unlock + mount the **work** copy at this directory (W2 chain).
        #[arg(long)]
        mount: Option<PathBuf>,
    },
    /// UC-30: atomically replace the sync-folder brick from the working copy.
    Checkin {
        /// Working-copy session id (from checkout). Default: sole active session.
        work_id: Option<String>,
        /// Override work root (must match checkout).
        #[arg(long)]
        work_dir: Option<PathBuf>,
    },
    /// UC-30: show working-copy session status.
    WorkStatus {
        /// Session id (default: list all under work root).
        work_id: Option<String>,
        #[arg(long)]
        work_dir: Option<PathBuf>,
    },
    /// UC-30: discard a working copy without writing the sync path.
    WorkDiscard {
        /// Session id to discard.
        work_id: String,
        #[arg(long)]
        work_dir: Option<PathBuf>,
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

/// Cloud-sync folder detection is centralized in `blindkey_core::is_under_sync_root` (UC-30 W0).
/// Refuse (or, with `--force-local`, warn about) mounting a live volume under a cloud-sync folder.
/// Points to `volume checkout` (UC-30) and `blindkey seal` (UC-23).
fn sync_root_guard(path: &Path, force_local: bool) -> CmdResult {
    if !is_under_sync_root(path) {
        return Ok(());
    }
    if !force_local {
        return Err(usage_err(
            "refusing to mount a live read-write volume under a cloud-sync folder. \
             Syncing a mounted volume is UNSUPPORTED and can corrupt it (C73). Use \
             `blindkey volume checkout` (UC-30 working copy) or `blindkey seal <PATH>` \
             for a cloud-safe archive, or pass --force-local to override (unsupported).",
        ));
    }
    eprintln!(
        "warning: --force-local — mounting under a cloud-sync folder is UNSUPPORTED; \
         do not let the backend sync the volume while it is mounted."
    );
    Ok(())
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
        Some(p) => {
            Some(Zeroizing::new(std::fs::read(p).map_err(|e| {
                format!("cannot read keyfile {}: {e}", p.display())
            })?))
        }
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
    warn_orphan_sessions();
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
        VolumeAction::Checkout {
            path,
            work_dir,
            mount,
        } => cmd_checkout(&path, work_dir.as_deref(), mount.as_deref(), opts),
        VolumeAction::Checkin { work_id, work_dir } => {
            cmd_checkin(work_id.as_deref(), work_dir.as_deref())
        }
        VolumeAction::WorkStatus { work_id, work_dir } => {
            cmd_work_status(work_id.as_deref(), work_dir.as_deref())
        }
        VolumeAction::WorkDiscard { work_id, work_dir } => {
            cmd_work_discard(&work_id, work_dir.as_deref())
        }
        VolumeAction::UpgradeKdf {
            path,
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
        } => cmd_upgrade_kdf(&path, kdf_m_cost, kdf_t_cost, kdf_p_cost, opts),
    }
}

fn warn_orphan_sessions() {
    let Ok(orphans) = orphan_work_sessions(None) else {
        return;
    };
    if orphans.is_empty() {
        return;
    }
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
    for o in &orphans {
        eprintln!(
            "note: orphan working-copy session {} (phase={:?})\n\
             source: {}\n\
             work:   {}\n\
             Resume: `blindkey volume checkin {}`  or discard: `blindkey volume work-discard {}`",
            o.id,
            o.phase,
            o.source_path.display(),
            o.work_path.display(),
            o.id,
            o.id
        );
    }
    if !interactive {
        // Non-interactive: surface on stderr only; commands still run (checkin/discard handle).
        let _ = interactive;
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
        pad_mode: if no_pad {
            PadMode::None
        } else {
            PadMode::Padme
        },
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
         volume-mount` (Linux). On macOS add `--features macos-fuse` after installing macFUSE \
         from https://macfuse.io (Blindkey does not bundle it). Use Blindfolder or `blindkey seal` \
         for sync-folder workflows."
            .to_string(),
    )
}

fn cmd_umount(mountpoint: &Path) -> CmdResult {
    // Try the userspace helpers first (Linux / macFUSE), then a plain umount. No secrets involved.
    let attempts: &[(&str, &[&str])] = &[
        ("fusermount", &["-u"]),
        ("fusermount3", &["-u"]),
        ("umount", &[]),
        ("diskutil", &["unmount"]),
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
    vol.upgrade_kdf(&unlock, m, t, p)
        .map_err(|e| e.to_string())?;
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
        println!(
            "{:<width$}  {:>10}",
            crate::terminal::sanitize_for_terminal(p),
            size
        );
    }
    Ok(())
}

fn map_work_err(e: Error) -> String {
    match e {
        Error::WorkingCopyRemoteChanged => format!("{WORK_E1_PREFIX} {e}"),
        Error::WorkingCopyHydration => format!("{WORK_E5_PREFIX} {WORKING_COPY_ERROR}"),
        Error::WorkingCopyWorkSyncRoot => format!("{WORK_E6_PREFIX} {WORKING_COPY_ERROR}"),
        Error::WorkingCopyRenameFailed => format!("{WORK_E8_PREFIX} {e}"),
        Error::WorkingCopyUnresolvedConflicts => e.to_string(),
        Error::WorkingCopyStillMounted => e.to_string(),
        Error::WorkingCopyFailed => WORKING_COPY_ERROR.to_string(),
        // Generic I/O (not rename/replace) — exit 1 via main, not E8.
        Error::Io(e) => e.to_string(),
        _ => WORKING_COPY_ERROR.to_string(),
    }
}

fn resolve_work_root(work_dir: Option<&Path>) -> Result<PathBuf, String> {
    match work_dir {
        Some(p) => Ok(p.to_path_buf()),
        None => blindkey_core::default_work_root().map_err(|e| e.to_string()),
    }
}

fn find_sole_session(work_root: &Path) -> Result<String, String> {
    let mut ids = Vec::new();
    if work_root.is_dir() {
        for ent in std::fs::read_dir(work_root).map_err(|e| e.to_string())? {
            let ent = ent.map_err(|e| e.to_string())?;
            if ent.path().join("state.json").is_file() {
                ids.push(ent.file_name().to_string_lossy().into_owned());
            }
        }
    }
    match ids.len() {
        1 => Ok(ids.remove(0)),
        0 => Err("no active working-copy session — run `blindkey volume checkout` first".into()),
        _ => Err(format!(
            "multiple working-copy sessions ({}); pass WORK_ID explicitly",
            ids.join(", ")
        )),
    }
}

fn cmd_checkout(
    path: &Path,
    work_dir: Option<&Path>,
    mountpoint: Option<&Path>,
    opts: &OpenOpts,
) -> CmdResult {
    if !path.is_file() {
        return Err(format!("{}: not a volume file", path.display()));
    }
    let work_root = resolve_work_root(work_dir)?;
    let session = WorkingCopySession::checkout(CheckoutOpts {
        source: path,
        work_root: Some(&work_root),
        skip_idle_probe: false,
        cancel: None,
        progress: None,
    })
    .map_err(map_work_err)?;
    let work_path = session.work_path.clone();
    let id = session.id.clone();
    eprintln!(
        "Checked out working copy {} (session {}).",
        work_path.display(),
        id
    );
    if let Some(mp) = mountpoint {
        // W2: chain unlock+mount of the work brick (never the sync path).
        let mut session = session;
        session
            .set_phase(WorkPhase::Mounted)
            .map_err(map_work_err)?;
        eprintln!("Mounting work copy at {}…", mp.display());
        // Drop session handle before mount keeps process alive; sidecar already Mounted.
        drop(session);
        cmd_mount(&work_path, mp, false, opts)?;
        // After mount returns (umount/signal), mark unmounted for checkin.
        if let Ok(mut s) = WorkingCopySession::resume_in(&id, &work_root) {
            let _ = s.set_phase(WorkPhase::Unmounted);
        }
        eprintln!("When done: blindkey volume checkin {id}");
    } else {
        drop(session);
        eprintln!(
            "Mount with: blindkey volume mount {} <MOUNTPOINT>\n\
             When done:  blindkey volume checkin {}",
            work_path.display(),
            id
        );
    }
    println!("{id}");
    Ok(())
}

fn cmd_checkin(work_id: Option<&str>, work_dir: Option<&Path>) -> CmdResult {
    let work_root = resolve_work_root(work_dir)?;
    let id = match work_id {
        Some(id) => id.to_string(),
        None => find_sole_session(&work_root)?,
    };
    let session_dir = work_root.join(&id);
    let session = WorkingCopySession::resume_from_dir(&session_dir).map_err(map_work_err)?;
    let source = session.source_path.clone();
    let work = session.work_path.clone();
    let sid = session.id.clone();
    session.checkin().map_err(|e| match e {
        Error::WorkingCopyRemoteChanged => format!(
            "{WORK_E1_PREFIX} sync-folder brick changed since checkout; refusing overwrite.\n\
             sync: {}\n\
             work: {}\n\
             Resolve manually, or: blindkey volume work-discard {}",
            source.display(),
            work.display(),
            sid
        ),
        other => map_work_err(other),
    })?;
    eprintln!("Checked in to {}.", source.display());
    Ok(())
}

fn cmd_work_status(work_id: Option<&str>, work_dir: Option<&Path>) -> CmdResult {
    let work_root = resolve_work_root(work_dir)?;
    if let Some(id) = work_id {
        let session =
            WorkingCopySession::resume_from_dir(&work_root.join(id)).map_err(map_work_err)?;
        println!(
            "id={}\nphase={:?}\nsource={}\nwork={}\nsize={}",
            session.id,
            session.phase,
            session.source_path.display(),
            session.work_path.display(),
            session.fingerprint.size
        );
        return Ok(());
    }
    if !work_root.is_dir() {
        eprintln!("No working-copy sessions.");
        return Ok(());
    }
    let mut any = false;
    for ent in std::fs::read_dir(&work_root).map_err(|e| e.to_string())? {
        let ent = ent.map_err(|e| e.to_string())?;
        if !ent.path().join("state.json").is_file() {
            continue;
        }
        any = true;
        match WorkingCopySession::resume_from_dir(&ent.path()) {
            Ok(s) => println!("{}\t{:?}\t{}", s.id, s.phase, s.source_path.display()),
            Err(_) => println!("{}\t(unreadable)", ent.file_name().to_string_lossy()),
        }
    }
    if !any {
        eprintln!("No working-copy sessions.");
    }
    Ok(())
}

fn cmd_work_discard(work_id: &str, work_dir: Option<&Path>) -> CmdResult {
    let work_root = resolve_work_root(work_dir)?;
    let session =
        WorkingCopySession::resume_from_dir(&work_root.join(work_id)).map_err(map_work_err)?;
    session.discard().map_err(map_work_err)?;
    eprintln!("Discarded working-copy session {work_id}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_refuses_sync_roots() {
        for p in [
            "/Users/x/Dropbox/work.vltd",
            "/Users/x/Library/CloudStorage/OneDrive-Personal/work.vltd",
            "/home/x/OneDrive/work.vltd",
            "/Users/x/Google Drive/work.vltd",
            "/Users/x/Library/Mobile Documents/com~apple~CloudDocs/work.vltd",
            "/home/x/syncthing/share/work.vltd",
        ] {
            let path = Path::new(p);
            assert!(is_under_sync_root(path), "should detect: {p}");
            assert!(
                sync_root_guard(path, false).is_err(),
                "should refuse without --force-local: {p}"
            );
            assert!(
                sync_root_guard(path, true).is_ok(),
                "should allow with --force-local: {p}"
            );
        }
    }

    #[test]
    fn allows_local_paths() {
        for p in ["/tmp/work.vltd", "/home/x/vaults/work.vltd", "./work.vltd"] {
            let path = Path::new(p);
            assert!(!is_under_sync_root(path), "should be local: {p}");
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
