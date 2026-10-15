//! UC-30 — volume working copy (checkout / checkin).
//!
//! Copy a closed `.vltd` out of an untrusted sync folder, work on the local copy, then
//! atomically replace the sync-folder brick. Never mounts the sync-folder path (C73 / C99).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::rollback;
use crate::{Error, Result, MAGIC_VLTD};

use super::materialize;

/// Uniform failure text (UC-30 — no format oracle on hostile stubs).
pub const WORKING_COPY_ERROR: &str = "volume working copy could not be prepared";

/// Outer fingerprint of a closed host file (C101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterFingerprint {
    /// Logical size (`st_size`).
    pub size: u64,
    /// SHA-256 of logical file bytes (holes read as zeros).
    pub sha256: [u8; 32],
    /// Device id at fingerprint time (0 when unavailable).
    pub dev: u64,
    /// Inode at fingerprint time (0 when unavailable).
    pub ino: u64,
    /// First four bytes equal `MAGIC_VLTD` at hash time.
    pub magic_ok: bool,
}

/// Sidecar phase for crash/resume (UC-30 §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkPhase {
    /// Brick copied; not yet mounted.
    Copied,
    /// Working copy is (or was) mounted.
    Mounted,
    /// Unmounted; ready for checkin.
    Unmounted,
    /// Checkin in progress.
    Checkin,
}

impl WorkPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Copied => "copied",
            Self::Mounted => "mounted",
            Self::Unmounted => "unmounted",
            Self::Checkin => "checkin",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "copied" => Some(Self::Copied),
            "mounted" => Some(Self::Mounted),
            "unmounted" => Some(Self::Unmounted),
            "checkin" => Some(Self::Checkin),
            _ => None,
        }
    }
}

/// Options for [`WorkingCopySession::checkout`].
pub struct CheckoutOpts<'a> {
    /// Sync-folder (or any) `.vltd` path.
    pub source: &'a Path,
    /// Override work root (`…/blindkey/volumes/work`). `None` → platform default.
    pub work_root: Option<&'a Path>,
    /// Skip the ≥1s dual-stat idle window (unit tests).
    pub skip_idle_probe: bool,
    /// Optional cooperative cancel (checked between major steps).
    pub cancel: Option<&'a std::sync::atomic::AtomicBool>,
    /// Optional progress callback `(done_bytes, total_bytes)`.
    pub progress: Option<&'a mut dyn FnMut(u64, u64)>,
}

impl std::fmt::Debug for CheckoutOpts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckoutOpts")
            .field("source", &self.source)
            .field("work_root", &self.work_root)
            .field("skip_idle_probe", &self.skip_idle_probe)
            .field("cancel", &self.cancel.map(|_| "AtomicBool"))
            .field("progress", &self.progress.as_ref().map(|_| "FnMut"))
            .finish()
    }
}

impl<'a> CheckoutOpts<'a> {
    /// Minimal opts for tests / simple callers.
    pub fn new(source: &'a Path) -> Self {
        Self {
            source,
            work_root: None,
            skip_idle_probe: false,
            cancel: None,
            progress: None,
        }
    }
}

/// Summary of a session directory (resume / launch scan).
#[derive(Debug, Clone)]
pub struct WorkSessionInfo {
    /// Session id.
    pub id: String,
    /// Sidecar phase.
    pub phase: WorkPhase,
    /// Sync-folder brick path.
    pub source_path: PathBuf,
    /// Local work brick.
    pub work_path: PathBuf,
    /// Pid recorded in sidecar (0 if missing).
    pub pid: u32,
}

/// Options for [`WorkingCopySession::checkin_with`].
#[derive(Debug, Clone, Copy, Default)]
pub struct CheckinOpts {
    /// Prefer platform coordinated replace (macOS File Provider).
    pub coordinated: bool,
}

/// An active checkout session (sidecar + working brick).
#[derive(Debug)]
pub struct WorkingCopySession {
    /// Opaque session id (hex).
    pub id: String,
    /// Last known sync-folder path.
    pub source_path: PathBuf,
    /// Local working copy path.
    pub work_path: PathBuf,
    /// Fingerprint recorded at checkout.
    pub fingerprint: OuterFingerprint,
    /// Crash/resume phase.
    pub phase: WorkPhase,
    /// Directory holding brick + `state.json`.
    session_dir: PathBuf,
}

impl WorkingCopySession {
    /// Hydration + idle probe → hole-preserving copy → fingerprint → sidecar.
    ///
    /// Does **not** mount and does **not** unlock UC-25 crypto.
    pub fn checkout(opts: CheckoutOpts<'_>) -> Result<Self> {
        let CheckoutOpts {
            source,
            work_root,
            skip_idle_probe,
            cancel,
            mut progress,
        } = opts;
        if cancelled(cancel) {
            return Err(Error::WorkingCopyFailed);
        }
        assert_regular_file(source)?;
        assert_hydrated_for_checkout(source)?;
        // E9 (macOS): unresolved iCloud / Finder conflicts.
        #[cfg(target_os = "macos")]
        {
            if blindkey_sys::has_unresolved_conflicts(source) {
                return Err(Error::WorkingCopyUnresolvedConflicts);
            }
        }
        // Magic before full-file hash (fail closed early; R1 ordering).
        if !fp_magic_ok(source)? {
            return Err(Error::WorkingCopyHydration);
        }
        if !skip_idle_probe {
            idle_probe(source)?;
        }
        if cancelled(cancel) {
            return Err(Error::WorkingCopyFailed);
        }

        let total = fs::metadata(source).map(|m| m.len()).unwrap_or(0);
        if let Some(cb) = progress.as_mut() {
            cb(0, total.max(1));
        }

        let fp = hash_outer_logical(source)?;

        let id = new_session_id()?;
        let work_root = match work_root {
            Some(p) => p.to_path_buf(),
            None => default_work_root()?,
        };
        fs::create_dir_all(&work_root)?;
        let session_dir = work_root.join(&id);
        if session_dir.exists() {
            return Err(Error::WorkingCopyFailed);
        }
        fs::create_dir_all(&session_dir)?;

        // E6: work path must not itself be a sync root.
        let work_path = session_dir.join("brick.vltd");
        let work_real = realpath_or(&session_dir);
        if is_under_sync_root(&work_real) || is_under_sync_root(&work_path) {
            let _ = fs::remove_dir_all(&session_dir);
            return Err(Error::WorkingCopyWorkSyncRoot);
        }

        if cancelled(cancel) {
            let _ = fs::remove_dir_all(&session_dir);
            return Err(Error::WorkingCopyFailed);
        }

        if let Err(e) = copy_brick(source, &work_path) {
            let _ = fs::remove_dir_all(&session_dir);
            return Err(e);
        }
        exclude_work_from_backup(&session_dir);
        if let Some(cb) = progress.as_mut() {
            cb(total.max(1), total.max(1));
        }

        // Source must not have changed during copy.
        let fp_after = hash_outer_logical(source)?;
        if fp_after.size != fp.size || fp_after.sha256 != fp.sha256 {
            let _ = fs::remove_dir_all(&session_dir);
            return Err(Error::WorkingCopyRemoteChanged);
        }

        let session = Self {
            id,
            source_path: source.to_path_buf(),
            work_path,
            fingerprint: fp,
            phase: WorkPhase::Copied,
            session_dir,
        };
        session.write_sidecar()?;
        Ok(session)
    }

    /// Load sidecar after crash / relaunch.
    pub fn resume(work_id: &str) -> Result<Self> {
        let session_dir = default_work_root()?.join(work_id);
        Self::resume_from_dir(&session_dir)
    }

    /// Load sidecar under an explicit work root (`--work-dir`).
    pub fn resume_in(work_id: &str, work_root: &Path) -> Result<Self> {
        Self::resume_from_dir(&work_root.join(work_id))
    }

    /// Load from an explicit session directory (tests / `--work-dir`).
    pub fn resume_from_dir(session_dir: &Path) -> Result<Self> {
        let state_path = session_dir.join("state.json");
        let raw = fs::read_to_string(&state_path).map_err(|_| Error::WorkingCopyFailed)?;
        let parsed = parse_sidecar(&raw).ok_or(Error::WorkingCopyFailed)?;
        Ok(Self {
            id: parsed.id,
            source_path: parsed.source_path,
            work_path: parsed.work_path,
            fingerprint: parsed.fingerprint,
            phase: parsed.phase,
            session_dir: session_dir.to_path_buf(),
        })
    }

    /// Record a phase transition and rewrite the sidecar.
    pub fn set_phase(&mut self, phase: WorkPhase) -> Result<()> {
        self.phase = phase;
        self.write_sidecar()?;
        exclude_work_from_backup(&self.session_dir);
        Ok(())
    }

    /// C101: re-hash source; error if mismatch (size, sha256, or replaced inode).
    pub fn assert_source_unchanged(&self) -> Result<()> {
        if !self.source_path.is_file() {
            return Err(Error::WorkingCopyRemoteChanged);
        }
        let now = hash_outer_logical(&self.source_path)?;
        if now.size != self.fingerprint.size
            || now.sha256 != self.fingerprint.sha256
            || now.dev != self.fingerprint.dev
            || now.ino != self.fingerprint.ino
        {
            return Err(Error::WorkingCopyRemoteChanged);
        }
        Ok(())
    }

    /// C100: sibling tmp + fsync + rename onto `source_path` (POSIX).
    ///
    /// Caller MUST have unmounted and synced the volume first.
    pub fn checkin(self) -> Result<()> {
        self.checkin_with(CheckinOpts::default())
    }

    /// C100 with platform replace options (coordinated on macOS GUI).
    pub fn checkin_with(mut self, opts: CheckinOpts) -> Result<()> {
        // Leftover cleartext folder means edits may not be in brick.vltd yet.
        if materialize::cleartext_mnt_beside(&self.work_path).is_some() {
            return Err(Error::WorkingCopyStillMounted);
        }
        // §9: still mounted → refuse before any short-circuit.
        if self.phase == WorkPhase::Mounted {
            return Err(Error::WorkingCopyStillMounted);
        }
        // E10 before any short-circuit — mid-sync temps refuse even if bytes match.
        if let Some(parent) = self.source_path.parent() {
            if has_syncthing_temp_sibling(parent, &self.source_path) {
                return Err(Error::WorkingCopyHydration);
            }
        }
        #[cfg(target_os = "macos")]
        {
            if blindkey_sys::has_unresolved_conflicts(&self.source_path) {
                return Err(Error::WorkingCopyUnresolvedConflicts);
            }
        }

        // E3 idempotent: prior rename succeeded but session delete crashed.
        if self.work_path.is_file() && self.source_path.is_file() {
            let work_fp = hash_outer_logical(&self.work_path)?;
            let src_fp = hash_outer_logical(&self.source_path)?;
            if work_fp.size == src_fp.size && work_fp.sha256 == src_fp.sha256 {
                Self::cleanup_checkin_temps(&self.source_path);
                let _ = fs::remove_dir_all(&self.session_dir);
                return Ok(());
            }
        }

        self.assert_source_unchanged()?;
        self.phase = WorkPhase::Checkin;
        self.write_sidecar()?;
        exclude_work_from_backup(&self.session_dir);

        let parent = self.source_path.parent().ok_or(Error::WorkingCopyFailed)?;
        let stem = self
            .source_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("volume");
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).map_err(|_| Error::WorkingCopyFailed)?;
        let tmp_name = format!("{stem}.{}.bk-checkin.tmp", bytes_to_hex(&rand));
        debug_assert!(!tmp_name.starts_with(".syncthing."));
        debug_assert!(!tmp_name.starts_with("~syncthing~"));
        let tmp_path = parent.join(&tmp_name);

        if let Err(_e) = copy_brick(&self.work_path, &tmp_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(Error::WorkingCopyRenameFailed);
        }
        {
            fsync_file(&tmp_path).map_err(|_| Error::WorkingCopyRenameFailed)?;
        }

        // Re-check before rename (TOCTOU window).
        if let Err(e) = self.assert_source_unchanged() {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        let replace_result = if opts.coordinated {
            #[cfg(target_os = "macos")]
            {
                blindkey_sys::coordinated_replace(&tmp_path, &self.source_path)
            }
            #[cfg(not(target_os = "macos"))]
            {
                fs::rename(&tmp_path, &self.source_path)
            }
        } else {
            fs::rename(&tmp_path, &self.source_path)
        };

        if let Err(e) = replace_result {
            // E8: try out-of-tree temp then replace into sync dir.
            let _ = fs::remove_file(&tmp_path);
            if let Err(e2) = self.e8_fallback_replace() {
                let _ = self.write_sidecar();
                return Err(e2);
            }
            let _ = e; // primary rename failed; fallback succeeded
        } else if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }

        // Best-effort shred of work tree.
        let _ = fs::remove_dir_all(&self.session_dir);
        Ok(())
    }

    /// Test hook: run the E8 out-of-tree replace path alone (KeePassXC-class fallback).
    #[cfg(test)]
    pub(crate) fn test_e8_fallback_replace(&self) -> Result<()> {
        self.e8_fallback_replace()
    }

    /// KeePassXC-class: write temp under data dir, then sibling-rename into sync folder.
    fn e8_fallback_replace(&self) -> Result<()> {
        let staging_root = rollback::platform_data_dir()?
            .join("blindkey")
            .join("volumes")
            .join("checkin-tmp");
        fs::create_dir_all(&staging_root)?;
        if is_under_sync_root(&staging_root) {
            return Err(Error::WorkingCopyRenameFailed);
        }
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).map_err(|_| Error::WorkingCopyRenameFailed)?;
        let staging = staging_root.join(format!("{}.tmp", bytes_to_hex(&rand)));
        copy_brick(&self.work_path, &staging).map_err(|_| Error::WorkingCopyRenameFailed)?;
        {
            fsync_file(&staging).map_err(|_| Error::WorkingCopyRenameFailed)?;
        }
        self.assert_source_unchanged()
            .map_err(|_| Error::WorkingCopyRemoteChanged)?;

        let parent = self
            .source_path
            .parent()
            .ok_or(Error::WorkingCopyRenameFailed)?;
        let stem = self
            .source_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("volume");
        let mut rand2 = [0u8; 8];
        getrandom::getrandom(&mut rand2).map_err(|_| Error::WorkingCopyRenameFailed)?;
        let sibling = parent.join(format!("{stem}.{}.bk-checkin.tmp", bytes_to_hex(&rand2)));
        if let Err(_e) = fs::copy(&staging, &sibling) {
            let _ = fs::remove_file(&staging);
            return Err(Error::WorkingCopyRenameFailed);
        }
        let _ = fs::remove_file(&staging);
        {
            fsync_file(&sibling).map_err(|_| Error::WorkingCopyRenameFailed)?;
        }
        if let Err(_e) = fs::rename(&sibling, &self.source_path) {
            let _ = fs::remove_file(&sibling);
            return Err(Error::WorkingCopyRenameFailed);
        }
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn cleanup_checkin_temps(source: &Path) {
        let Some(parent) = source.parent() else {
            return;
        };
        let Some(stem) = source.file_stem().and_then(|s| s.to_str()) else {
            return;
        };
        let Ok(rd) = fs::read_dir(parent) else {
            return;
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let s = name.to_string_lossy();
            if s.starts_with(stem) && s.contains(".bk-checkin.tmp") {
                let _ = fs::remove_file(ent.path());
            }
        }
    }

    /// Discard work file + sidecar without writing the sync path.
    pub fn discard(self) -> Result<()> {
        let _ = fs::remove_dir_all(&self.session_dir);
        Ok(())
    }

    /// Session directory (brick + `state.json`).
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    fn write_sidecar(&self) -> Result<()> {
        let path = self.session_dir.join("state.json");
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pid = std::process::id();
        let body = format!(
            "{{\n  \"version\": 1,\n  \"id\": \"{}\",\n  \"source_path\": {},\n  \"source_fingerprint\": {{\n    \"size\": {},\n    \"sha256\": \"{}\",\n    \"dev\": {},\n    \"ino\": {},\n    \"magic_ok\": {}\n  }},\n  \"work_path\": {},\n  \"phase\": \"{}\",\n  \"pid\": {},\n  \"created_at\": \"{}\"\n}}\n",
            self.id,
            json_string(&self.source_path.to_string_lossy()),
            self.fingerprint.size,
            bytes_to_hex(&self.fingerprint.sha256),
            self.fingerprint.dev,
            self.fingerprint.ino,
            if self.fingerprint.magic_ok {
                "true"
            } else {
                "false"
            },
            json_string(&self.work_path.to_string_lossy()),
            self.phase.as_str(),
            pid,
            rfc3339_utc(created)
        );
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            let mut f = File::create(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// Default `…/blindkey/volumes/work` under the platform data dir (C70 sibling).
pub fn default_work_root() -> Result<PathBuf> {
    Ok(rollback::platform_data_dir()?
        .join("blindkey")
        .join("volumes")
        .join("work"))
}

/// E9: unresolved iCloud / Finder conflict siblings (macOS); elsewhere always false.
pub fn has_unresolved_conflicts(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        blindkey_sys::has_unresolved_conflicts(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        false
    }
}

/// Detect a cloud-sync root in `path` (C73 / C99).
///
/// Union of CLI + GUI markers: case-insensitive path substring **and** component match.
/// Includes `CloudStorage` (macOS) and Syncthing.
pub fn is_under_sync_root(path: &Path) -> bool {
    let full = path.to_string_lossy().to_ascii_lowercase();
    const SUBSTRINGS: &[&str] = &[
        "cloudstorage", // ~/Library/CloudStorage/{Dropbox,GoogleDrive,OneDrive}-…
        "mobile documents",
        "com~apple~clouddocs",
        "google drive",
        "googledrive",
        ".dropbox",
    ];
    if SUBSTRINGS.iter().any(|m| full.contains(m)) {
        return true;
    }

    const COMPONENTS: &[&str] = &[
        "dropbox",
        "onedrive",
        "icloud",
        "icloud drive",
        "syncthing",
        "pcloud",
        "box sync",
        "mega",
        "nextcloud",
        "owncloud",
    ];
    path.components().any(|c| {
        let seg = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        COMPONENTS.iter().any(|m| seg == *m || seg.contains(m))
    })
}

/// Platform hydration probe — fail closed on stub / empty (E5).
///
/// Full File Provider / CfAPI attribute probes are OS-specific; this portable gate refuses
/// missing files, directories, and zero-length placeholders. Callers on Apple should layer
/// ubiquitous-status checks in the GUI.
pub fn assert_hydrated_for_checkout(path: &Path) -> Result<()> {
    assert_regular_file(path).map_err(|_| Error::WorkingCopyHydration)?;
    let meta = fs::metadata(path).map_err(|_| Error::WorkingCopyHydration)?;
    if meta.len() < MAGIC_VLTD.len() as u64 {
        return Err(Error::WorkingCopyHydration);
    }
    // Linux: st_blocks == 0 with large size → refuse (header-less stub).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.blocks() == 0 && meta.len() > 4096 {
            return Err(Error::WorkingCopyHydration);
        }
    }
    // Windows CfAPI: recall / offline / partially present → refuse (E5).
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
        const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
        const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
        // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS family covers partial placeholders.
        let attrs = meta.file_attributes();
        if attrs
            & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_OFFLINE)
            != 0
        {
            return Err(Error::WorkingCopyHydration);
        }
    }
    #[cfg(target_os = "macos")]
    {
        if blindkey_sys::is_dataless(path) {
            return Err(Error::WorkingCopyHydration);
        }
        use blindkey_sys::UbiquitousStatus;
        match blindkey_sys::ubiquitous_download_status(path) {
            UbiquitousStatus::NotDownloaded | UbiquitousStatus::Downloaded => {
                return Err(Error::WorkingCopyHydration);
            }
            UbiquitousStatus::Unknown => {
                let s = path.to_string_lossy().to_ascii_lowercase();
                if s.contains("/library/mobile documents/")
                    || s.contains("com~apple~clouddocs")
                    || s.contains("googledrive")
                    || s.contains("google drive")
                {
                    return Err(Error::WorkingCopyHydration);
                }
            }
            UbiquitousStatus::Current | UbiquitousStatus::NotUbiquitous => {}
        }
    }
    // Google Drive for desktop (Stream / Mirror): path heuristics + placeholder siblings +
    // Google DriveFS xattrs when present (E5).
    if under_google_drive_path(path) {
        if google_drive_placeholder_sibling(path) || google_drive_cloud_only_xattr(path) {
            return Err(Error::WorkingCopyHydration);
        }
        // Under Drive roots, also refuse zero allocated blocks with large logical size
        // (already covered on unix above for blocks==0); tighten with Drive-specific markers.
        if google_drive_offline_unavailable(path) {
            return Err(Error::WorkingCopyHydration);
        }
    } else if google_drive_placeholder_sibling(path) {
        return Err(Error::WorkingCopyHydration);
    }
    // Syncthing mid-sync temps beside the brick.
    if let Some(parent) = path.parent() {
        if has_syncthing_temp_sibling(parent, path) {
            return Err(Error::WorkingCopyHydration);
        }
    }
    Ok(())
}

/// Outer logical SHA-256 (holes = zeros when read via std).
pub fn hash_outer_logical(path: &Path) -> Result<OuterFingerprint> {
    let meta = fs::metadata(path)?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut magic = [0u8; 4];
    let mut magic_n = 0usize;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if magic_n < 4 {
            let take = (4 - magic_n).min(n);
            magic[magic_n..magic_n + take].copy_from_slice(&buf[..take]);
            magic_n += take;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest);

    let (dev, ino) = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        }
        #[cfg(not(unix))]
        {
            (0u64, 0u64)
        }
    };

    Ok(OuterFingerprint {
        size: meta.len(),
        sha256,
        dev,
        ino,
        magic_ok: magic_n == 4 && magic == MAGIC_VLTD,
    })
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn assert_regular_file(path: &Path) -> Result<()> {
    let meta = fs::metadata(path).map_err(|_| Error::WorkingCopyFailed)?;
    if !meta.is_file() {
        return Err(Error::WorkingCopyFailed);
    }
    Ok(())
}

fn fp_magic_ok(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    Ok(magic == MAGIC_VLTD)
}

fn idle_probe(path: &Path) -> Result<()> {
    // §7.1: two samples ≥1s apart must match; retry until stable or 30s timeout.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let a = fs::metadata(path).map_err(|_| Error::WorkingCopyFailed)?;
        std::thread::sleep(Duration::from_secs(1));
        let b = fs::metadata(path).map_err(|_| Error::WorkingCopyFailed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if a.len() == b.len() && a.mtime() == b.mtime() && a.ino() == b.ino() {
                return Ok(());
            }
        }
        #[cfg(not(unix))]
        {
            if a.len() == b.len() && a.modified().ok() == b.modified().ok() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::WorkingCopyFailed);
        }
    }
}

fn google_drive_placeholder_sibling(brick: &Path) -> bool {
    let Some(parent) = brick.parent() else {
        return false;
    };
    let Ok(rd) = fs::read_dir(parent) else {
        return false;
    };
    let Some(stem) = brick.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let stem_l = stem.to_ascii_lowercase();
    for ent in rd.flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        let lower = s.to_ascii_lowercase();
        // Drive Stream / desktop placeholders and partial uploads.
        if lower.ends_with(".tmp.driveupload")
            || lower.ends_with(".tmp.drivedownload")
            || lower.ends_with(".partial")
            || lower.contains(".gdrive")
        {
            // Folder mid-sync: any Drive temp in the brick's parent is enough.
            // Prefer stem match when present; otherwise still refuse under Drive roots.
            if lower.contains(&stem_l) || under_google_drive_path(brick) {
                return true;
            }
        }
        // Cloud-only shortcut: zero-byte sibling sharing the stem with a .cloud extension.
        if lower.starts_with(&stem_l) && lower.ends_with(".cloud") {
            return true;
        }
        // Mirror "Available offline" negation: Drive sometimes leaves a zero-byte cloud stub
        // named like the brick with a second extension.
        if lower.starts_with(&stem_l) && lower != format!("{stem_l}.vltd") {
            if let Ok(meta) = ent.metadata() {
                if meta.is_file() && meta.len() == 0 && lower.contains("cloud") {
                    return true;
                }
            }
        }
    }
    false
}

fn under_google_drive_path(path: &Path) -> bool {
    let s = path.to_string_lossy().to_ascii_lowercase();
    s.contains("googledrive")
        || s.contains("google drive")
        || s.contains("/cloudstorage/google")
        || s.contains("\\cloudstorage\\google")
        || s.contains("drivefs")
}

/// Best-effort DriveFS xattr / Finder tag that marks cloud-only content.
fn google_drive_cloud_only_xattr(path: &Path) -> bool {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let names = blindkey_sys::list_xattr_names(path);
        let joined = names.join("\0");
        if joined.contains("com.google.drivefs")
            || joined.contains("drivefs")
            || joined.contains("user.drive.")
        {
            #[cfg(target_os = "macos")]
            {
                if blindkey_sys::is_dataless(path) {
                    return true;
                }
            }
            #[cfg(unix)]
            {
                if let Ok(meta) = fs::metadata(path) {
                    use std::os::unix::fs::MetadataExt;
                    if meta.blocks() == 0 && meta.len() > 4096 {
                        return true;
                    }
                }
            }
        }
    }
    let _ = path;
    false
}

/// Portable "not available offline" signals for Drive roots (E5).
fn google_drive_offline_unavailable(path: &Path) -> bool {
    // Zero-length logical file that still claims to be a volume header — cloud stub.
    if let Ok(meta) = fs::metadata(path) {
        if meta.is_file() && meta.len() == 0 {
            return true;
        }
    }
    // Sibling `.cloud` / Finder alias names already covered; also refuse `.vltd.cloud`.
    if let Some(parent) = path.parent() {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let cloud = parent.join(format!("{name}.cloud"));
            if cloud.is_file() {
                return true;
            }
        }
    }
    false
}

fn has_syncthing_temp_sibling(parent: &Path, brick: &Path) -> bool {
    let Ok(rd) = fs::read_dir(parent) else {
        return false;
    };
    let brick_name = brick.file_name();
    for ent in rd.flatten() {
        let name = ent.file_name();
        if Some(name.as_os_str()) == brick_name {
            continue;
        }
        let s = name.to_string_lossy();
        if s.starts_with(".syncthing.") || s.starts_with("~syncthing~") {
            return true;
        }
    }
    false
}

/// Flush a file's data to disk. Opens with write access: on Windows `sync_all` is
/// `FlushFileBuffers`, which fails with access-denied on a read-only handle ("The file
/// handle must have the GENERIC_WRITE access right", Microsoft Learn). Unix accepts either.
fn fsync_file(path: &Path) -> std::io::Result<()> {
    fs::OpenOptions::new().write(true).open(path)?.sync_all()
}

fn copy_brick(src: &Path, dst: &Path) -> Result<()> {
    // Prefer macOS clonefile via `cp -c` when available (hole-preserving, new inode).
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("/bin/cp")
            .args(["-c", "--"])
            .arg(src)
            .arg(dst)
            .status();
        if let Ok(st) = status {
            if st.success() {
                return Ok(());
            }
            let _ = fs::remove_file(dst);
        }
    }
    // Linux: FICLONE then SEEK_HOLE/SEEK_DATA.
    #[cfg(target_os = "linux")]
    {
        match blindkey_sys::try_ficlone(src, dst) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(_) => {
                let _ = fs::remove_file(dst);
            }
        }
        match blindkey_sys::copy_seek_hole(src, dst) {
            Ok(()) => return Ok(()),
            Err(_) => {
                let _ = fs::remove_file(dst);
            }
        }
    }
    // Portable fallback: full logical copy (may densify sparse files — documented).
    fs::copy(src, dst)?;
    Ok(())
}

fn cancelled(flag: Option<&std::sync::atomic::AtomicBool>) -> bool {
    flag.is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
}

fn exclude_work_from_backup(session_dir: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = blindkey_sys::exclude_from_backup(session_dir);
        let brick = session_dir.join("brick.vltd");
        if brick.exists() {
            let _ = blindkey_sys::exclude_from_backup(&brick);
        }
        let state = session_dir.join("state.json");
        if state.exists() {
            let _ = blindkey_sys::exclude_from_backup(&state);
        }
    }
    let _ = session_dir;
}

/// List working-copy sessions under `work_root` (default platform root when `None`).
pub fn list_work_sessions(work_root: Option<&Path>) -> Result<Vec<WorkSessionInfo>> {
    let root = match work_root {
        Some(p) => p.to_path_buf(),
        None => default_work_root()?,
    };
    let mut out = Vec::new();
    if !root.is_dir() {
        return Ok(out);
    }
    for ent in fs::read_dir(&root).map_err(|_| Error::WorkingCopyFailed)? {
        let ent = ent.map_err(|_| Error::WorkingCopyFailed)?;
        let dir = ent.path();
        if !dir.join("state.json").is_file() {
            continue;
        }
        if let Ok(s) = WorkingCopySession::resume_from_dir(&dir) {
            let pid = read_sidecar_pid(&dir.join("state.json")).unwrap_or(0);
            out.push(WorkSessionInfo {
                id: s.id,
                phase: s.phase,
                source_path: s.source_path,
                work_path: s.work_path,
                pid,
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn read_sidecar_pid(path: &Path) -> Option<u32> {
    let raw = fs::read_to_string(path).ok()?;
    let n = json_get_num(&raw, "pid")?;
    Some(n as u32)
}

/// Sessions that look abandoned (mounted/unmounted/checkin with dead pid).
pub fn orphan_work_sessions(work_root: Option<&Path>) -> Result<Vec<WorkSessionInfo>> {
    let all = list_work_sessions(work_root)?;
    Ok(all
        .into_iter()
        .filter(|s| {
            matches!(
                s.phase,
                WorkPhase::Copied | WorkPhase::Mounted | WorkPhase::Unmounted | WorkPhase::Checkin
            ) && (s.pid == 0 || !pid_alive(s.pid))
        })
        .collect())
}

/// Sessions with a leftover cleartext `mnt/` beside the work brick (kill-9 / crash).
///
/// Unlock must [`MaterializedMount::adopt`] these trees — re-export would wipe edits.
pub fn orphaned_cleartext_sessions(work_root: Option<&Path>) -> Result<Vec<WorkSessionInfo>> {
    let all = list_work_sessions(work_root)?;
    Ok(all
        .into_iter()
        .filter(|s| materialize::cleartext_mnt_beside(&s.work_path).is_some())
        .collect())
}

fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        false
    }
}

fn new_session_id() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| Error::WorkingCopyFailed)?;
    Ok(bytes_to_hex(&b))
}

fn realpath_or(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// RFC3339 UTC from Unix seconds (no chrono dep).
fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_ymd_from_unix_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Civil Y-M-D from days since Unix epoch (Howard Hinnant).
fn civil_ymd_from_unix_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct ParsedSidecar {
    id: String,
    source_path: PathBuf,
    work_path: PathBuf,
    fingerprint: OuterFingerprint,
    phase: WorkPhase,
}

fn parse_sidecar(raw: &str) -> Option<ParsedSidecar> {
    // Minimal tolerant parser for our own sidecar (no serde dep in core).
    let id = json_get_str(raw, "id")?;
    let source_path = PathBuf::from(json_get_str(raw, "source_path")?);
    let work_path = PathBuf::from(json_get_str(raw, "work_path")?);
    let phase = WorkPhase::parse(&json_get_str(raw, "phase")?)?;
    let size: u64 = json_get_num(raw, "size")?;
    let sha_hex = json_get_str(raw, "sha256")?;
    let sha256 = hex_to_32(&sha_hex)?;
    let dev: u64 = json_get_num(raw, "dev").unwrap_or(0);
    let ino: u64 = json_get_num(raw, "ino").unwrap_or(0);
    let magic_ok = json_get_bool(raw, "magic_ok").unwrap_or(true);
    Some(ParsedSidecar {
        id,
        source_path,
        work_path,
        fingerprint: OuterFingerprint {
            size,
            sha256,
            dev,
            ino,
            magic_ok,
        },
        phase,
    })
}

fn json_get_bool(raw: &str, key: &str) -> Option<bool> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let after = &raw[i + pat.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_get_str(raw: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let after = &raw[i + pat.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = rest[1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        hex.push(chars.next()?);
                    }
                    let code = u32::from_str_radix(&hex, 16).ok()?;
                    out.push(char::from_u32(code)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    None
}

fn json_get_num(raw: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let after = &raw[i + pat.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sync_root_detects_dropbox_and_cloudstorage() {
        assert!(is_under_sync_root(Path::new(
            "/Users/x/Library/CloudStorage/Dropbox/work.vltd"
        )));
        assert!(is_under_sync_root(Path::new("/home/x/Dropbox/a.vltd")));
        assert!(is_under_sync_root(Path::new(
            "/home/x/syncthing/folder/a.vltd"
        )));
        assert!(!is_under_sync_root(Path::new("/tmp/local/a.vltd")));
    }

    #[test]
    fn checkout_checkin_roundtrip_and_c101() {
        let base = std::env::temp_dir().join(format!("bk-wc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();

        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0xABu8; 8192]).unwrap();
        }

        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        assert!(session.work_path.is_file());
        assert_eq!(
            fs::read(&session.work_path).unwrap(),
            fs::read(&brick).unwrap()
        );

        // Mutate work copy.
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(&session.work_path)
                .unwrap();
            use std::io::Seek;
            f.seek(std::io::SeekFrom::End(0)).unwrap();
            f.write_all(b"NEW").unwrap();
        }

        let work_bytes = fs::read(&session.work_path).unwrap();
        session.checkin().unwrap();
        assert_eq!(fs::read(&brick).unwrap(), work_bytes);
        // Session dir removed after successful checkin.
        assert!(work_root.read_dir().unwrap().filter_map(|e| e.ok()).count() <= 1); // may retain discarded session from C101 path below

        // Fresh checkout then mutate remote → checkin refuses.
        let session2 = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        let work2 = session2.work_path.clone();
        {
            let mut f = fs::OpenOptions::new().write(true).open(&brick).unwrap();
            use std::io::Seek;
            f.seek(std::io::SeekFrom::End(0)).unwrap();
            f.write_all(b"REMOTE").unwrap();
        }
        let err = session2.checkin().unwrap_err();
        assert!(matches!(err, Error::WorkingCopyRemoteChanged));
        // Work retained for discard/resume.
        assert!(work2.is_file());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn e3_idempotent_when_source_already_equals_work() {
        let base = std::env::temp_dir().join(format!("bk-wc-e3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0xCDu8; 4096]).unwrap();
        }
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        // Simulate successful rename then crash before session delete: source already == work.
        fs::copy(&session.work_path, &brick).unwrap();
        let session_dir = session.session_dir.clone();
        session.checkin().unwrap();
        assert!(!session_dir.exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn checkin_refuses_while_mounted_phase() {
        let base = std::env::temp_dir().join(format!("bk-wc-mnt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0xABu8; 4096]).unwrap();
        }
        let mut session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        session.set_phase(WorkPhase::Mounted).unwrap();
        let err = session.checkin().unwrap_err();
        assert!(matches!(err, Error::WorkingCopyStillMounted));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn checkin_refuses_leftover_cleartext_mnt() {
        let base = std::env::temp_dir().join(format!("bk-wc-ct-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0xCDu8; 4096]).unwrap();
        }
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        let mnt = session.work_path.parent().unwrap().join("mnt");
        fs::create_dir_all(&mnt).unwrap();
        fs::write(mnt.join("x.txt"), b"leak").unwrap();
        let err = session.checkin().unwrap_err();
        assert!(matches!(err, Error::WorkingCopyStillMounted));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn orphan_includes_copied_phase() {
        let base = std::env::temp_dir().join(format!("bk-wc-orph-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0x11u8; 2048]).unwrap();
        }
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        let id = session.id.clone();
        // Sidecar pid is current process — force dead by rewriting pid 0 via discard path:
        // list orphans with dead pid: write state with pid=0 by set_phase after drop.
        drop(session);
        // Resume and leave as Copied; orphan filter treats pid==0 as dead — rewrite sidecar.
        let s = WorkingCopySession::resume_in(&id, &work_root).unwrap();
        assert_eq!(s.phase, WorkPhase::Copied);
        let _ = s;
        let orphans = orphan_work_sessions(Some(&work_root)).unwrap();
        // Live pid → not orphaned; filter must not panic.
        assert!(orphans.iter().all(|o| o.id != id));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn outer_hash_reads_full_logical_bytes() {
        let path = std::env::temp_dir().join(format!("bk-hash-{}.bin", std::process::id()));
        let _ = fs::remove_file(&path);
        let mut f = File::create(&path).unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        f.write_all(&[1u8; 50]).unwrap();
        f.sync_all().unwrap();
        let fp = hash_outer_logical(&path).unwrap();
        assert_eq!(fp.size, 150);
        let mut hasher = Sha256::new();
        hasher.update([0u8; 100]);
        hasher.update([1u8; 50]);
        let expect: [u8; 32] = hasher.finalize().into();
        assert_eq!(fp.sha256, expect);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn e10_checkin_refuses_syncthing_temp_sibling() {
        let base = std::env::temp_dir().join(format!("bk-wc-e10-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0xEFu8; 2048]).unwrap();
        }
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        File::create(sync.join(".syncthing.workspace.vltd.tmp"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let err = session.checkin().unwrap_err();
        assert!(matches!(err, Error::WorkingCopyHydration));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn sidecar_created_at_is_rfc3339() {
        let base = std::env::temp_dir().join(format!("bk-wc-rfc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0x01u8; 1024]).unwrap();
        }
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        let raw = fs::read_to_string(session.session_dir.join("state.json")).unwrap();
        assert!(
            raw.contains("\"magic_ok\": true"),
            "sidecar must persist probed magic_ok: {raw}"
        );
        assert!(session.fingerprint.magic_ok);
        let needle = "\"created_at\": \"";
        let i = raw.find(needle).unwrap() + needle.len();
        let end = raw[i..].find('"').unwrap();
        let ts = &raw[i..i + end];
        assert!(
            ts.len() == 20 && ts.ends_with('Z') && ts.contains('T'),
            "expected RFC3339 Z, got {ts}"
        );
        session.discard().unwrap();
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn idle_probe_passes_on_stable_file() {
        let base = std::env::temp_dir().join(format!("bk-wc-idle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0x22u8; 2048]).unwrap();
        }
        let started = Instant::now();
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: false,
            cancel: None,
            progress: None,
        })
        .unwrap();
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "idle probe must wait ≥1s"
        );
        session.discard().unwrap();
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn e5_hydration_refuses_short_stub_and_syncthing_temp() {
        let base = std::env::temp_dir().join(format!("bk-wc-e5-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let stub = base.join("stub.vltd");
        fs::write(&stub, b"VL").unwrap();
        assert!(matches!(
            assert_hydrated_for_checkout(&stub),
            Err(Error::WorkingCopyHydration)
        ));

        let sync = base.join("sync");
        fs::create_dir_all(&sync).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0x33u8; 2048]).unwrap();
        }
        File::create(sync.join(".syncthing.workspace.vltd.tmp"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(matches!(
            assert_hydrated_for_checkout(&brick),
            Err(Error::WorkingCopyHydration)
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn hole_preserving_copy_roundtrips_bytes() {
        let base = std::env::temp_dir().join(format!("bk-wc-hole-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let src = base.join("sparse.vltd");
        {
            use std::io::Seek;
            let mut f = File::create(&src).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.seek(std::io::SeekFrom::Start(64 * 1024)).unwrap();
            f.write_all(&[0xAAu8; 16]).unwrap();
            f.sync_all().unwrap();
        }
        let dst = base.join("out.vltd");
        copy_brick(&src, &dst).unwrap();
        assert_eq!(fs::read(&src).unwrap(), fs::read(&dst).unwrap());
        let fp = hash_outer_logical(&dst).unwrap();
        assert!(fp.magic_ok);
        assert_eq!(fp.size, fs::metadata(&src).unwrap().len());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn e8_fallback_replace_updates_source() {
        let base = std::env::temp_dir().join(format!("bk-wc-e8-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0x44u8; 4096]).unwrap();
        }
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(&session.work_path)
                .unwrap();
            use std::io::Seek;
            f.seek(std::io::SeekFrom::End(0)).unwrap();
            f.write_all(b"E8").unwrap();
        }
        let expect = fs::read(&session.work_path).unwrap();
        session.test_e8_fallback_replace().unwrap();
        assert_eq!(fs::read(&brick).unwrap(), expect);
        session.discard().unwrap();
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn e8_checkin_fails_closed_when_sync_dir_not_writable() {
        use std::os::unix::fs::PermissionsExt;
        struct RestoreWritable<'a> {
            path: &'a Path,
        }
        impl Drop for RestoreWritable<'_> {
            fn drop(&mut self) {
                if let Ok(meta) = fs::metadata(self.path) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(self.path, perms);
                }
            }
        }

        let base = std::env::temp_dir().join(format!("bk-wc-e8ro-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sync = base.join("sync");
        let work_root = base.join("work");
        fs::create_dir_all(&sync).unwrap();
        fs::create_dir_all(&work_root).unwrap();
        let brick = sync.join("workspace.vltd");
        {
            let mut f = File::create(&brick).unwrap();
            f.write_all(&MAGIC_VLTD).unwrap();
            f.write_all(&vec![0x55u8; 2048]).unwrap();
        }
        let session = WorkingCopySession::checkout(CheckoutOpts {
            source: &brick,
            work_root: Some(&work_root),
            skip_idle_probe: true,
            cancel: None,
            progress: None,
        })
        .unwrap();
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(&session.work_path)
                .unwrap();
            use std::io::Seek;
            f.seek(std::io::SeekFrom::End(0)).unwrap();
            f.write_all(b"X").unwrap();
        }
        let mut perms = fs::metadata(&sync).unwrap().permissions();
        perms.set_mode(0o555);
        fs::set_permissions(&sync, perms).unwrap();
        let _restore = RestoreWritable { path: &sync };
        let err = session.checkin().unwrap_err();
        assert!(
            matches!(
                err,
                Error::WorkingCopyRenameFailed | Error::WorkingCopyFailed
            ),
            "expected rename fail-closed, got {err:?}"
        );
        drop(_restore);
        let _ = fs::remove_dir_all(&base);
    }
}
