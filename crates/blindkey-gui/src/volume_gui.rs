//! UC-25 local encrypted volume GUI — create / mount / eject over `blindkey_core::volume`
//! (Phase C). A thin UC-18 shell: every byte that touches a secret stays in `blindkey-core`;
//! this module only collects paths/passphrases, drives a worker thread, and renders honest copy.
//!
//! Honesty posture (C72 / SC10): while a volume is mounted the OS sees cleartext — same class as
//! an unlocked FileVault. The residual-risk banner states this once per session. Live RW mount of
//! a `.vltd` on a cloud-sync folder is unsupported (C73) — we refuse and point to Blindfolder /
//! `blindkey seal`. Unlock materializes a cleartext working folder via
//! [`blindkey_core::MaterializedMount`] (ADR-0010 degraded path when FUSE packaging is absent).
//! With `--features volume-mount` on Linux, unlock prefers [`blindkey_fuse`] when `fusermount`
//! works; otherwise MaterializedMount. macOS always uses MaterializedMount (ADR-0010).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use blindkey_core::pad::PadMode;
use blindkey_core::{
    cleartext_mnt_beside, has_unresolved_conflicts, orphan_work_sessions,
    orphaned_cleartext_sessions, CheckinOpts, CheckoutOpts, Error, MaterializedMount, Volume,
    VolumeCreateOpts, VolumeUnlock, WorkPhase, WorkingCopySession, MAGIC_VLTD, VOLUME_OPEN_ERROR,
    WORKING_COPY_ERROR,
};
use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

/// Residual-risk banner (C72 / SC10) — shown once per session before the first mount. Honest: the
/// model-blind retrieval guarantee (C27) does **not** cover files a mounted volume exposes to the OS.
pub const RESIDUAL_RISK_BANNER: &str =
    "While this volume is mounted, its files are cleartext to the \
operating system and to any app or agent with filesystem access — the same class as an unlocked \
FileVault disk. Blindkey's model-blind retrieval (C27) does not cover Finder/Explorer reads of a \
mounted volume. Eject when you're done.";

/// Lock-on-sleep policy note — honest about best-effort (MNT-04b): auto-eject on sleep/lock is a UX
/// policy, not a cryptographic guarantee, and the platform may not always deliver the event.
pub const LOCK_ON_SLEEP_NOTE: &str =
    "Lock/sleep policy is best-effort: Blindkey tries to eject on \
sleep or screen-lock, but this is a convenience, not a guarantee — eject manually before leaving \
the machine unattended.";

/// True when `path` looks like a Blindkey volume — `.vltd` extension or `VLTD` magic (C67).
pub fn is_vltd_path(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("vltd"))
    {
        return true;
    }
    let mut magic = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        if f.read_exact(&mut magic).is_ok() && magic == MAGIC_VLTD {
            return true;
        }
    }
    false
}

/// Detect a cloud-sync root in `path` by name segment (C73 — no network probe; purely local, C23).
/// Delegates to [`blindkey_core::is_under_sync_root`] (UC-30 unified detector).
pub fn is_under_sync_root(path: &Path) -> bool {
    blindkey_core::is_under_sync_root(path)
}

/// Seal / checkout CTA (C73) when `path` is under a sync root. `None` when the path is local.
pub fn sync_root_seal_cta(path: &Path) -> Option<String> {
    if is_under_sync_root(path) {
        Some(
            "Live mount of a .vltd on Dropbox/Drive/iCloud/Syncthing is unsupported and can \
             corrupt the volume. Use Open Blindfolder (checkout) or Seal files instead."
                .to_string(),
        )
    } else {
        None
    }
}

/// Map a core error to an honest, non-oracle GUI string (C74 — uniform open failure).
fn map_volume_err(e: Error) -> String {
    match e {
        Error::VolumeOpenFailed | Error::HeaderAuth => VOLUME_OPEN_ERROR.to_string(),
        Error::VolumeAnchorMismatch => e.to_string(),
        Error::WrongContainerKind => "That file is not a Blindkey volume (.vltd).".to_string(),
        Error::Io(e) => e.to_string(),
        _ => VOLUME_OPEN_ERROR.to_string(),
    }
}

fn default_volume_output() -> String {
    // IA-10: default to a local path (never Dropbox/iCloud). Prefer ~/Documents.
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    if let Some(h) = home {
        let docs = PathBuf::from(h).join("Documents").join("blindkey-workspace.vltd");
        return docs.display().to_string();
    }
    "blindkey-workspace.vltd".to_string()
}

// ─── dialogs ──────────────────────────────────────────────────────────────────

/// Create-volume wizard state. Password buffers zeroize on drop.
pub struct CreateVolumeDialog {
    pub output_path: String,
    pub password: String,
    pub confirm: String,
    pub size_mib: u64,
    pub max_size_mib: u64,
    pub show_password: bool,
    /// Request focus on passphrase field once when dialog opens (CRAFT-S05).
    pub focus_password: bool,
    pub error: Option<String>,
}

impl CreateVolumeDialog {
    fn new() -> Self {
        Self {
            output_path: default_volume_output(),
            password: String::new(),
            confirm: String::new(),
            size_mib: 64,
            max_size_mib: 256,
            show_password: false,
            focus_password: true,
            error: None,
        }
    }
}

impl Drop for CreateVolumeDialog {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
    }
}

/// Mount (open/validate) dialog state. Password buffer zeroizes on drop.
pub struct MountDialog {
    pub volume_path: PathBuf,
    pub password: String,
    pub keyfile_path: String,
    pub show_password: bool,
    /// Request focus on passphrase field once when dialog opens (CRAFT-S05).
    pub focus_password: bool,
    pub error: Option<String>,
}

impl MountDialog {
    fn new(path: PathBuf) -> Self {
        Self {
            volume_path: path,
            password: String::new(),
            keyfile_path: String::new(),
            show_password: false,
            focus_password: true,
            error: None,
        }
    }
}

impl Drop for MountDialog {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

// ─── worker (mirror of sealed_gui: thread + cancel + coarse progress) ────────────

enum JobUpdate {
    Progress { done: u64, total: u64 },
    Finished(Result<String, String>),
}

struct VolumeWorker {
    cancel: Arc<AtomicBool>,
    rx: Receiver<JobUpdate>,
    handle: Option<thread::JoinHandle<()>>,
    label: String,
    started: Instant,
    done: u64,
    total: u64,
}

impl VolumeWorker {
    fn poll(&mut self) -> Option<Result<String, String>> {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                JobUpdate::Progress { done, total } => {
                    self.done = done;
                    self.total = total.max(1);
                }
                JobUpdate::Finished(result) => {
                    if let Some(h) = self.handle.take() {
                        let _ = h.join();
                    }
                    return Some(result);
                }
            }
        }
        None
    }

    fn running(&self) -> bool {
        self.handle.is_some()
    }

    fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    fn elapsed_secs(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }
}

/// Workspace volume session for chrome (UC-26 IA-01 / Phase D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VolumeSessionKind {
    #[default]
    Locked,
    /// Credentials validated; folder open when `mount_path` is set (C79 honesty).
    Unlocked,
}

/// Live open folder: cleartext materialization and/or FUSE (`volume-mount` / `macos-fuse`).
enum LiveMount {
    Materialized(MaterializedMount),
    #[cfg(any(
        all(feature = "volume-mount", target_os = "linux"),
        all(feature = "macos-fuse", target_os = "macos")
    ))]
    Fuse(blindkey_fuse::MountGuard),
}

impl LiveMount {
    fn mountpoint(&self) -> &Path {
        match self {
            Self::Materialized(m) => m.mountpoint(),
            #[cfg(any(
                all(feature = "volume-mount", target_os = "linux"),
                all(feature = "macos-fuse", target_os = "macos")
            ))]
            Self::Fuse(g) => g.mountpoint(),
        }
    }

    /// Seal / unmount. Materialized returns the volume for an explicit close; FUSE syncs on disk.
    fn seal(self) -> Result<(), (Error, Option<LiveMount>)> {
        match self {
            Self::Materialized(mat) => match mat.close() {
                Ok(vol) => {
                    let _ = vol.close();
                    Ok(())
                }
                Err(close_err) => Err((close_err.error, Some(Self::Materialized(close_err.mount)))),
            },
            #[cfg(any(
                all(feature = "volume-mount", target_os = "linux"),
                all(feature = "macos-fuse", target_os = "macos")
            ))]
            Self::Fuse(guard) => {
                guard.unmount();
                Ok(())
            }
        }
    }
}

/// UC-25 volume GUI controller — Create / Unlock / Eject / Blindfolder over `blindkey_core::volume`.
pub struct VolumeGui {
    create_dialog: Option<CreateVolumeDialog>,
    mount_dialog: Option<MountDialog>,
    worker: Option<VolumeWorker>,
    status: Option<String>,
    error: Option<String>,
    /// Residual-risk banner acknowledged this session (C72 — once, not a daily nag).
    banner_acknowledged: bool,
    /// A mount request waiting behind the once-per-session residual banner.
    pending_mount: Option<PathBuf>,
    /// Last volume path touched this session (create/unlock).
    active_path: Option<PathBuf>,
    session: VolumeSessionKind,
    /// Cleartext / FUSE folder path while a [`LiveMount`] is held (Reveal gate).
    mount_path: Option<PathBuf>,
    /// Live folder mount (MaterializedMount and/or FUSE).
    live_mount: Option<LiveMount>,
    /// Worker → UI handoff for the open mount (avoids serializing `Volume` on the channel).
    mount_handoff: Option<Arc<Mutex<Option<LiveMount>>>>,
    /// C73 recovery: open Seal files flow (picker) from sync-refuse UI.
    seal_request: bool,
    /// Last sync-root refuse message (survives `take_error` for Workspace CTA).
    sync_refuse_cta: Option<String>,
    /// Pending Blindfolder checkout path (sync-root `.vltd`).
    pending_blindfolder: Option<PathBuf>,
    /// Active Blindfolder session: (work_id, sync source path).
    blindfolder: Option<(String, PathBuf)>,
    /// E2 resume dialog candidates.
    resume_orphans: Vec<(String, PathBuf, PathBuf, WorkPhase)>,
    /// Which orphan resume dialog is open (`Some(index)`).
    resume_dialog: Option<usize>,
}

impl Default for VolumeGui {
    fn default() -> Self {
        Self::new()
    }
}

impl VolumeGui {
    pub fn new() -> Self {
        let mut gui = Self {
            create_dialog: None,
            mount_dialog: None,
            worker: None,
            status: None,
            error: None,
            banner_acknowledged: false,
            pending_mount: None,
            active_path: None,
            session: VolumeSessionKind::Locked,
            mount_path: None,
            live_mount: None,
            mount_handoff: None,
            seal_request: false,
            sync_refuse_cta: None,
            pending_blindfolder: None,
            blindfolder: None,
            resume_orphans: Vec::new(),
            resume_dialog: None,
        };
        gui.scan_resume_orphans();
        gui
    }

    fn scan_resume_orphans(&mut self) {
        self.resume_orphans.clear();
        let mut seen = std::collections::BTreeSet::new();
        let mut push = |o: blindkey_core::WorkSessionInfo| {
            if seen.insert(o.id.clone()) {
                self.resume_orphans
                    .push((o.id, o.source_path, o.work_path, o.phase));
            }
        };
        if let Ok(orphans) = orphan_work_sessions(None) {
            for o in orphans {
                push(o);
            }
        }
        // kill-9 leftover cleartext: surface even if phase/pid heuristics differed.
        if let Ok(clear) = orphaned_cleartext_sessions(None) {
            for o in clear {
                push(o);
            }
        }
        if !self.resume_orphans.is_empty() {
            self.resume_dialog = Some(0);
        }
    }

    /// True once when Workspace asked to open the Seal files flow (C73).
    pub fn take_seal_request(&mut self) -> bool {
        std::mem::take(&mut self.seal_request)
    }

    pub fn job_running(&self) -> bool {
        self.worker.as_ref().is_some_and(|w| w.running())
    }

    pub fn take_status(&mut self) -> Option<String> {
        self.status.take()
    }

    pub fn take_error(&mut self) -> Option<String> {
        self.error.take()
    }

    /// Whether the residual-risk banner must be shown before mounting this session (C72).
    pub fn banner_pending(&self) -> bool {
        self.pending_mount.is_some() && !self.banner_acknowledged
    }

    pub fn open_create_dialog(&mut self) {
        if self.job_running() {
            return;
        }
        self.create_dialog = Some(CreateVolumeDialog::new());
    }

    /// Begin a mount: pick a `.vltd` and route it behind the residual-risk banner (once/session).
    pub fn choose_and_mount(&mut self) {
        if self.job_running() {
            return;
        }
        if let Some(p) = rfd::FileDialog::new()
            .set_title("Open a Blindkey volume")
            .add_filter("Blindkey volume", &["vltd"])
            .pick_file()
        {
            self.request_mount(p);
        }
    }

    /// Route a mount request behind the once-per-session banner; refuse cloud-sync roots (C73).
    pub fn request_mount(&mut self, path: PathBuf) {
        if let Some(cta) = sync_root_seal_cta(&path) {
            self.sync_refuse_cta = Some(cta.clone());
            self.error = Some(cta);
            self.pending_blindfolder = Some(path);
            return;
        }
        if self.banner_acknowledged {
            self.mount_dialog = Some(MountDialog::new(path));
        } else {
            self.pending_mount = Some(path);
        }
    }

    /// UC-30 Open Blindfolder: checkout sync-path brick → unlock work copy.
    pub fn open_blindfolder(&mut self, path: PathBuf) {
        if self.job_running() {
            return;
        }
        if has_unresolved_conflicts(&path) {
            self.error = Some(
                "This cloud file has unresolved conflict versions. Resolve them in Finder, then try again."
                    .into(),
            );
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let c_cancel = cancel.clone();
        let path_job = path.clone();
        let handle = thread::spawn(move || {
            let mut progress_cb = |done: u64, total: u64| {
                let _ = tx.send(JobUpdate::Progress { done, total });
            };
            let result = WorkingCopySession::checkout(CheckoutOpts {
                source: &path_job,
                work_root: None,
                skip_idle_probe: false,
                cancel: Some(&c_cancel),
                progress: Some(&mut progress_cb),
            });
            match result {
                Ok(mut session) => {
                    let _ = session.set_phase(WorkPhase::Copied);
                    let msg = format!(
                        "BLINDFOLDER\t{}\t{}\t{}",
                        session.id,
                        session.work_path.display(),
                        session.source_path.display()
                    );
                    let _ = tx.send(JobUpdate::Finished(Ok(msg)));
                }
                Err(e) => {
                    let msg = match e {
                        Error::WorkingCopyHydration | Error::WorkingCopyFailed => {
                            WORKING_COPY_ERROR.to_string()
                        }
                        Error::WorkingCopyWorkSyncRoot => WORKING_COPY_ERROR.to_string(),
                        Error::WorkingCopyUnresolvedConflicts => e.to_string(),
                        other => other.to_string(),
                    };
                    let _ = tx.send(JobUpdate::Finished(Err(msg)));
                }
            }
        });
        self.worker = Some(VolumeWorker {
            cancel,
            rx,
            handle: Some(handle),
            label: "Opening Blindfolder…".into(),
            started: Instant::now(),
            done: 0,
            total: 1,
        });
        self.pending_blindfolder = None;
        self.sync_refuse_cta = None;
        self.error = None;
    }

    /// Begin Blindfolder from the last refused sync-path (or file picker).
    pub fn choose_and_open_blindfolder(&mut self) {
        if self.job_running() {
            return;
        }
        if let Some(p) = self.pending_blindfolder.take() {
            self.open_blindfolder(p);
            return;
        }
        if let Some(p) = rfd::FileDialog::new()
            .set_title("Open Blindfolder (sync-folder .vltd)")
            .add_filter("Blindkey volume", &["vltd"])
            .pick_file()
        {
            self.open_blindfolder(p);
        }
    }

    /// Route egui file drops for `.vltd` files — returns `true` if consumed.
    pub fn handle_drops(&mut self, dropped: &[egui::DroppedFile]) -> bool {
        if self.job_running() {
            return true;
        }
        let vltd = dropped
            .iter()
            .filter_map(|f| f.path.clone())
            .find(|p| p.is_file() && is_vltd_path(p));
        if let Some(path) = vltd {
            self.request_mount(path);
            return true;
        }
        false
    }

    pub fn poll_worker(&mut self, ctx: &egui::Context) {
        let Some(worker) = &mut self.worker else {
            return;
        };
        if let Some(result) = worker.poll() {
            self.worker = None;
            match result {
                Ok(msg) if msg.starts_with("BLINDFOLDER\t") => {
                    let parts: Vec<&str> = msg.splitn(4, '\t').collect();
                    if parts.len() == 4 {
                        let id = parts[1].to_string();
                        let work = PathBuf::from(parts[2]);
                        let source = PathBuf::from(parts[3]);
                        self.blindfolder.replace((id, source));
                        self.status = Some(
                            "Blindfolder ready — unlock the local working copy.".into(),
                        );
                        self.request_mount(work);
                    } else {
                        self.error =
                            Some("Blindfolder checkout returned a malformed result.".into());
                    }
                }
                Ok(msg) if msg.starts_with("MOUNTED\t") => {
                    let parts: Vec<&str> = msg.splitn(3, '\t').collect();
                    if let Some(slot) = self.mount_handoff.take() {
                        self.live_mount = slot.lock().ok().and_then(|mut g| g.take());
                    }
                    if let Some(mp) = parts.get(1).map(PathBuf::from) {
                        self.mount_path = Some(mp.clone());
                        self.session = VolumeSessionKind::Unlocked;
                        if let Some((id, _)) = &self.blindfolder {
                            if let Ok(mut s) = WorkingCopySession::resume(id) {
                                let _ = s.set_phase(WorkPhase::Mounted);
                            }
                        }
                        reveal_in_file_manager(&mp);
                        self.status = Some(if parts.len() >= 3 {
                            parts[2].to_string()
                        } else {
                            format!("Folder open at {}.", mp.display())
                        });
                    } else {
                        self.error = Some("Mount handoff returned a malformed result.".into());
                    }
                }
                Ok(msg) => {
                    if msg.contains("unlocked (validated") || msg.starts_with("Volume created:") {
                        self.session = VolumeSessionKind::Unlocked;
                        // Validate-only fallback (materialize failed) — C79: no mount_path.
                        if !msg.starts_with("Volume created:") {
                            self.mount_path = None;
                            self.live_mount = None;
                        }
                    }
                    self.status = Some(msg);
                }
                Err(e) => {
                    self.mount_handoff = None;
                    self.error = Some(e);
                }
            }
        } else if worker.running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn start_worker(
        &mut self,
        label: String,
        spawn: impl FnOnce(Arc<AtomicBool>, Sender<JobUpdate>) + Send + 'static,
    ) {
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let c_cancel = cancel.clone();
        let handle = thread::spawn(move || spawn(c_cancel, tx));
        self.worker = Some(VolumeWorker {
            cancel,
            rx,
            handle: Some(handle),
            label,
            started: Instant::now(),
            done: 0,
            total: 1,
        });
    }

    fn try_start_create(&mut self) {
        let Some(mut dlg) = self.create_dialog.take() else {
            return;
        };
        if let Some(cta) = sync_root_seal_cta(Path::new(&dlg.output_path)) {
            dlg.error = Some(cta);
            self.create_dialog = Some(dlg);
            return;
        }
        if dlg.password.is_empty() {
            dlg.error = Some("Passphrase required.".into());
            self.create_dialog = Some(dlg);
            return;
        }
        if dlg.password != dlg.confirm {
            dlg.error = Some("Passphrases don't match — retype confirm.".into());
            self.create_dialog = Some(dlg);
            return;
        }
        let output = PathBuf::from(&dlg.output_path);
        if output.exists() {
            dlg.error = Some(format!("Refusing to overwrite {}.", output.display()));
            self.create_dialog = Some(dlg);
            return;
        }
        if dlg.max_size_mib < dlg.size_mib {
            dlg.error = Some("Max size must be at least the initial size.".into());
            self.create_dialog = Some(dlg);
            return;
        }
        let size_bytes = dlg.size_mib.saturating_mul(1024 * 1024);
        let max_bytes = dlg.max_size_mib.saturating_mul(1024 * 1024);
        let password = Zeroizing::new(dlg.password.clone());
        dlg.password.zeroize();
        dlg.confirm.zeroize();
        drop(dlg);

        self.active_path = Some(output.clone());
        self.start_worker("Creating volume…".into(), move |cancel, tx| {
            run_create_job(cancel, tx, output, password, size_bytes, max_bytes);
        });
    }

    fn try_start_mount(&mut self) {
        let Some(mut dlg) = self.mount_dialog.take() else {
            return;
        };
        if dlg.password.is_empty() {
            dlg.error = Some("Passphrase required.".into());
            self.mount_dialog = Some(dlg);
            return;
        }
        let path = dlg.volume_path.clone();
        let password = Zeroizing::new(dlg.password.clone());
        let keyfile_path = dlg.keyfile_path.clone();
        dlg.password.zeroize();
        drop(dlg);

        self.active_path = Some(path.clone());
        let slot = Arc::new(Mutex::new(None));
        self.mount_handoff = Some(slot.clone());
        self.start_worker("Opening folder…".into(), move |cancel, tx| {
            run_mount_job(cancel, tx, path, password, keyfile_path, slot);
        });
    }

    /// Chrome status for Workspace mode (IA-01).
    pub fn session_status(&self) -> crate::gui_mode::SessionStatus {
        use crate::gui_mode::SessionStatus;
        match (self.session, self.mount_path.is_some()) {
            (_, true) => SessionStatus::Mounted,
            (VolumeSessionKind::Unlocked, false) => SessionStatus::Unlocked,
            (VolumeSessionKind::Locked, false) => SessionStatus::Locked,
        }
    }

    /// Clear validated session (UC-26 IA-01 / IA-12). Blindfolder: close folder → checkin.
    pub fn eject(&mut self) {
        // Flush cleartext folder / FUSE back into the work `.vltd` before checkin.
        if let Some(live) = self.live_mount.take() {
            if let Err((err, remount)) = live.seal() {
                self.live_mount = remount;
                self.error = Some(format!(
                    "Could not seal open folder: {err}. Edits are still in the open folder — retry Eject."
                ));
                return;
            }
        }
        self.mount_path = None;
        self.mount_handoff = None;

        if let Some((id, source)) = self.blindfolder.take() {
            if let Ok(mut s) = WorkingCopySession::resume(&id) {
                let _ = s.set_phase(WorkPhase::Unmounted);
            }
            match WorkingCopySession::resume(&id) {
                Ok(session) => {
                    let work = session.work_path.clone();
                    if cleartext_mnt_beside(&work).is_some() {
                        self.error = Some(
                            "A cleartext working folder is still on disk beside the brick. \
                             Unlock that working copy again so Blindkey can import it, then Eject — \
                             or Discard Blindfolder (loses unsynced folder edits)."
                                .into(),
                        );
                        self.blindfolder = Some((id, source));
                        self.session = VolumeSessionKind::Locked;
                        return;
                    }
                    let opts = CheckinOpts {
                        coordinated: cfg!(target_os = "macos"),
                    };
                    match session.checkin_with(opts) {
                        Ok(()) => {
                            self.status = Some(format!(
                                "Blindfolder sealed back to {}.",
                                source.display()
                            ));
                        }
                        Err(Error::WorkingCopyRemoteChanged) => {
                            self.error = Some(format!(
                                "Sync-folder brick changed since checkout; refusing overwrite.\n\
                                 sync: {}\n\
                                 work: {}\n\
                                 Use Discard Blindfolder or resolve manually.",
                                source.display(),
                                work.display()
                            ));
                            self.blindfolder = Some((id, source));
                        }
                        Err(Error::WorkingCopyUnresolvedConflicts) => {
                            self.error = Some(
                                "Cloud file has unresolved conflict versions. Resolve them in Finder, then try again."
                                    .into(),
                            );
                            self.blindfolder = Some((id, source));
                        }
                        Err(e) => {
                            self.error = Some(e.to_string());
                            self.blindfolder = Some((id, source));
                        }
                    }
                }
                Err(e) => {
                    self.error = Some(format!("Could not resume Blindfolder session: {e}"));
                }
            }
        } else {
            self.status = Some("Ejected — files locked.".into());
        }
        self.session = VolumeSessionKind::Locked;
    }

    /// Called when the app is about to quit — same chain as Eject.
    pub fn prepare_quit(&mut self) {
        if self.live_mount.is_some() || self.blindfolder.is_some() || self.mount_path.is_some() {
            self.eject();
        }
    }

    /// True while a cleartext folder is still held (quit should cancel close).
    pub fn live_mount_open(&self) -> bool {
        self.live_mount.is_some()
    }

    /// Cryptomator-class Workspace home (UC-26 Phase D / UC-27 CRAFT-12).
    pub fn workspace_home(&mut self, ui: &mut egui::Ui) -> bool {
        use crate::theme::{self, SPACE_M, SPACE_S, SPACE_XL, SPACE_XS};
        let mut acted = false;
        let path_label = self
            .active_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let session = self.session;
        let can_reveal = self.mount_path.is_some();
        let reveal_path = self.mount_path.clone();
        // Sparse home CTA width (Cryptomator-class; under FORM_WIDTH).
        const HOME_CTA_W: f32 = 280.0;

        ui.vertical_centered(|ui| {
            ui.add_space(SPACE_XL);
            ui.heading("Workspace");
            ui.add_space(SPACE_XS);
            ui.label(format!("Volume status: {}", self.session_status().label()));
            ui.add_space(SPACE_XS);
            theme::muted_label(ui, "Workspace = edit as a folder. Seal = encrypt files for Dropbox/USB.");
            ui.add_space(SPACE_M);

            if !path_label.is_empty() {
                ui.monospace(egui::RichText::new(&path_label).small());
                ui.add_space(SPACE_S);
            }

            let seal_recovery = self.sync_refuse_cta.clone();
            if let Some(cta) = seal_recovery {
                ui.colored_label(theme::WARN, cta);
                ui.add_space(SPACE_S);
                if theme::primary_button(ui, "Open Blindfolder", HOME_CTA_W).clicked() {
                    self.choose_and_open_blindfolder();
                    acted = true;
                }
                ui.add_space(SPACE_S);
                if theme::secondary_button(ui, "Seal files…", HOME_CTA_W).clicked() {
                    self.seal_request = true;
                    self.sync_refuse_cta = None;
                    self.error = None;
                    acted = true;
                }
                ui.add_space(SPACE_M);
            }

            match session {
                VolumeSessionKind::Locked => {
                    if path_label.is_empty() {
                        ui.label("No volumes yet — create one, or unlock an existing local volume.");
                        ui.add_space(SPACE_M);
                    }
                    if theme::primary_button(ui, "Create volume", HOME_CTA_W).clicked() {
                        self.open_create_dialog();
                        acted = true;
                    }
                    ui.add_space(SPACE_S);
                    if theme::primary_button(ui, "Unlock", HOME_CTA_W).clicked() {
                        self.choose_and_mount();
                        acted = true;
                    }
                }
                VolumeSessionKind::Unlocked => {
                    if can_reveal {
                        ui.label("Folder open — cleartext until Eject.");
                    } else {
                        ui.label("Volume unlocked (validated).");
                    }
                    ui.add_space(SPACE_M);
                    if can_reveal {
                        let reveal_label = {
                            #[cfg(target_os = "macos")]
                            {
                                "Reveal in Finder"
                            }
                            #[cfg(target_os = "windows")]
                            {
                                "Reveal in Explorer"
                            }
                            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
                            {
                                "Reveal in file manager"
                            }
                        };
                        if theme::secondary_button(ui, reveal_label, HOME_CTA_W).clicked() {
                            if let Some(p) = &reveal_path {
                                reveal_in_file_manager(p);
                            }
                            acted = true;
                        }
                        ui.add_space(SPACE_S);
                    } else {
                        theme::muted_label(
                            ui,
                            "Reveal appears when the cleartext working folder is open.",
                        );
                        ui.add_space(SPACE_S);
                    }
                    if theme::secondary_button(ui, "Eject", HOME_CTA_W).clicked() {
                        self.eject();
                        acted = true;
                    }
                    ui.add_space(SPACE_M);
                    if ui.button("Unlock another…").clicked() {
                        self.choose_and_mount();
                        acted = true;
                    }
                }
            }
        });
        acted
    }

    pub fn windows(&mut self, ctx: &egui::Context) {
        self.resume_window(ctx);
        self.residual_banner_window(ctx);
        self.create_window(ctx);
        self.mount_window(ctx);
        self.progress_window(ctx);
    }

    /// E2: orphan working-copy resume / discard / reveal.
    fn resume_window(&mut self, ctx: &egui::Context) {
        let Some(idx) = self.resume_dialog else {
            return;
        };
        if idx >= self.resume_orphans.len() {
            self.resume_dialog = None;
            return;
        }
        let (id, source, work, phase) = self.resume_orphans[idx].clone();
        let mut resume = false;
        let mut discard = false;
        let mut reveal = false;
        let mut skip = false;
        egui::Window::new("Resume Blindfolder?")
            .order(egui::Order::Foreground)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(480.0);
                ui.label(format!(
                    "A previous Blindfolder session ({id}, phase={phase:?}) was left open."
                ));
                ui.add_space(crate::theme::SPACE_S);
                ui.monospace(format!("sync: {}", source.display()));
                ui.monospace(format!("work: {}", work.display()));
                ui.add_space(crate::theme::SPACE_M);
                ui.horizontal(|ui| {
                    if crate::theme::primary_button(ui, "Resume checkin", 140.0).clicked() {
                        resume = true;
                    }
                    if crate::theme::secondary_button(ui, "Discard", 100.0).clicked() {
                        discard = true;
                    }
                    if crate::theme::quiet_button(ui, "Reveal work", 110.0).clicked() {
                        reveal = true;
                    }
                    if crate::theme::quiet_button(ui, "Later", 80.0).clicked() {
                        skip = true;
                    }
                });
            });
        if reveal {
            reveal_in_file_manager(&work);
        }
        if resume {
            self.blindfolder = Some((id.clone(), source.clone()));
            match WorkingCopySession::resume(&id) {
                Ok(session) => {
                    let opts = CheckinOpts {
                        coordinated: cfg!(target_os = "macos"),
                    };
                    match session.checkin_with(opts) {
                        Ok(()) => {
                            self.status =
                                Some(format!("Resumed checkin — sealed to {}.", source.display()));
                            self.resume_orphans.remove(idx);
                        }
                        Err(Error::WorkingCopyRemoteChanged) => {
                            self.error = Some(format!(
                                "Sync-folder brick changed; refusing overwrite.\n\
                                 sync: {}\nwork: {}",
                                source.display(),
                                work.display()
                            ));
                        }
                        Err(e) => self.error = Some(e.to_string()),
                    }
                }
                Err(e) => self.error = Some(e.to_string()),
            }
            self.resume_dialog = if self.resume_orphans.is_empty() {
                None
            } else {
                Some(idx.min(self.resume_orphans.len().saturating_sub(1)))
            };
        } else if discard {
            if let Ok(s) = WorkingCopySession::resume(&id) {
                let _ = s.discard();
            }
            self.resume_orphans.remove(idx);
            self.resume_dialog = if self.resume_orphans.is_empty() {
                None
            } else {
                Some(0)
            };
            self.status = Some("Discarded orphan Blindfolder session.".into());
        } else if skip {
            self.resume_dialog = None;
        }
    }

    /// Once-per-session residual-risk banner (C72 / SC10). Acknowledging proceeds to the mount
    /// dialog; it is not shown again this session.
    fn residual_banner_window(&mut self, ctx: &egui::Context) {
        if !self.banner_pending() {
            return;
        }
        let mut acknowledged = false;
        let mut cancel = false;
        egui::Window::new("⚠  Mounted volumes are cleartext to the OS")
            .order(egui::Order::Foreground)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.label(RESIDUAL_RISK_BANNER);
                ui.add_space(crate::theme::SPACE_S);
                crate::theme::muted_label(ui, LOCK_ON_SLEEP_NOTE);
                ui.add_space(crate::theme::SPACE_M);
                ui.horizontal(|ui| {
                    if crate::theme::escape_pressed(ui)
                        || crate::theme::quiet_button(ui, "Cancel", crate::theme::DIALOG_BTN_WIDTH)
                            .clicked()
                    {
                        cancel = true;
                    }
                    if crate::theme::primary_button(
                        ui,
                        "I understand — continue",
                        200.0,
                    )
                    .clicked()
                    {
                        acknowledged = true;
                    }
                });
            });
        if acknowledged {
            self.banner_acknowledged = true;
            if let Some(path) = self.pending_mount.take() {
                self.mount_dialog = Some(MountDialog::new(path));
            }
        } else if cancel {
            self.pending_mount = None;
        }
    }

    fn create_window(&mut self, ctx: &egui::Context) {
        let Some(dlg) = self.create_dialog.as_mut() else {
            return;
        };
        let mut start = false;
        let mut cancel = false;
        let sync_warning = sync_root_seal_cta(Path::new(&dlg.output_path));
        egui::Window::new("Create encrypted volume")
            .collapsible(false)
            .resizable(true)
            .default_width(crate::theme::FORM_WIDTH)
            .show(ctx, |ui| {
                ui.label("Workspace = edit as a folder. Seal = encrypt files for Dropbox/USB.");
                ui.add_space(crate::theme::SPACE_S);
                ui.horizontal(|ui| {
                    ui.label("Volume file");
                    ui.add(
                        egui::TextEdit::singleline(&mut dlg.output_path)
                            .desired_width(240.0)
                            .hint_text("~/Documents/blindkey-workspace.vltd"),
                    );
                    if ui
                        .add_sized(
                            [72.0, crate::theme::PRIMARY_BTN_HEIGHT],
                            egui::Button::new("Save as…"),
                        )
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_title("Create Blindkey volume")
                            .add_filter("Blindkey volume", &["vltd"])
                            .set_file_name("blindkey-workspace.vltd")
                            .save_file()
                        {
                            dlg.output_path = p.display().to_string();
                        }
                    }
                });
                ui.add_space(crate::theme::SPACE_S);
                let pw = crate::theme::labeled_secret_row(
                    ui,
                    "Passphrase",
                    &mut dlg.password,
                    &mut dlg.show_password,
                    &mut dlg.focus_password,
                );
                let cf = crate::theme::labeled_secret_confirm(
                    ui,
                    "Confirm passphrase",
                    &mut dlg.confirm,
                    dlg.show_password,
                );
                if crate::theme::submit_on_enter(&pw, ui) || crate::theme::submit_on_enter(&cf, ui)
                {
                    start = true;
                }
                ui.add_space(crate::theme::SPACE_XS);
                crate::theme::muted_label(
                    ui,
                    "Size padding: on (Padmé default — hides exact volume size).",
                );
                crate::theme::muted_label(ui, LOCK_ON_SLEEP_NOTE);
                ui.collapsing("Advanced…", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Initial size (MiB)");
                        ui.add(egui::DragValue::new(&mut dlg.size_mib).range(1..=1_048_576));
                        ui.label("Max size (MiB)");
                        ui.add(egui::DragValue::new(&mut dlg.max_size_mib).range(1..=1_048_576));
                    });
                });
                if let Some(cta) = &sync_warning {
                    ui.add_space(crate::theme::SPACE_XS);
                    ui.colored_label(crate::theme::WARN, cta);
                    if crate::theme::quiet_button(ui, "Seal files…", 160.0).clicked()
                    {
                        self.seal_request = true;
                        cancel = true;
                    }
                }
                if let Some(e) = &dlg.error {
                    ui.add_space(crate::theme::SPACE_XS);
                    ui.colored_label(crate::theme::DANGER, e);
                }
                ui.add_space(crate::theme::SPACE_S);
                let (c, a) = crate::theme::dialog_cancel_affirm(ui, "Create");
                if c {
                    cancel = true;
                }
                if a {
                    start = true;
                }
            });
        if cancel {
            self.create_dialog = None;
        } else if start {
            self.try_start_create();
        }
    }

    fn mount_window(&mut self, ctx: &egui::Context) {
        let Some(dlg) = self.mount_dialog.as_mut() else {
            return;
        };
        let mut unlock = false;
        let mut cancel = false;
        egui::Window::new("Unlock volume")
            .collapsible(false)
            .resizable(true)
            .default_width(crate::theme::FORM_WIDTH)
            .show(ctx, |ui| {
                ui.label(format!("Volume: {}", dlg.volume_path.display()));
                ui.add_space(crate::theme::SPACE_S);
                let pw = crate::theme::labeled_secret_row(
                    ui,
                    "Passphrase",
                    &mut dlg.password,
                    &mut dlg.show_password,
                    &mut dlg.focus_password,
                );
                if crate::theme::submit_on_enter(&pw, ui) {
                    unlock = true;
                }
                ui.collapsing("Advanced…", |ui| {
                    ui.label("Keyfile path (optional)");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut dlg.keyfile_path)
                                .desired_width(220.0)
                                .hint_text("/path/to/keyfile"),
                        );
                        if crate::theme::text_button(ui, "Choose…").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .set_title("Choose keyfile")
                                .pick_file()
                            {
                                dlg.keyfile_path = p.display().to_string();
                            }
                        }
                    });
                });
                ui.add_space(crate::theme::SPACE_XS);
                crate::theme::muted_label(ui, LOCK_ON_SLEEP_NOTE);
                if let Some(e) = &dlg.error {
                    ui.add_space(crate::theme::SPACE_XS);
                    ui.colored_label(crate::theme::DANGER, e);
                }
                ui.add_space(crate::theme::SPACE_S);
                // C79: Unlock — not Mount — when this dialog only validates credentials.
                let (c, a) = crate::theme::dialog_cancel_affirm(ui, "Unlock");
                if c {
                    cancel = true;
                }
                if a {
                    unlock = true;
                }
            });
        if cancel {
            self.mount_dialog = None;
        } else if unlock {
            self.try_start_mount();
        }
    }

    fn progress_window(&mut self, ctx: &egui::Context) {
        let Some(worker) = self.worker.as_ref() else {
            return;
        };
        let done = worker.done;
        let total = worker.total;
        let label = worker.label.clone();
        let elapsed = worker.elapsed_secs();
        let mut cancel = false;
        egui::Window::new(&label)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let frac = (done as f32 / total as f32).clamp(0.0, 1.0);
                ui.add(egui::ProgressBar::new(frac).show_percentage());
                ui.label(format!("Phase {done}/{total} ({elapsed:.1}s)"));
                if crate::theme::escape_pressed(ui)
                    || crate::theme::quiet_button(ui, "Cancel", crate::theme::DIALOG_BTN_WIDTH)
                        .clicked()
                {
                    cancel = true;
                }
            });
        if cancel {
            if let Some(w) = &self.worker {
                w.cancel();
            }
        }
    }
}


fn reveal_in_file_manager(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer").arg(path).spawn();
    }
    let _ = path;
}

// ─── background jobs (all crypto in blindkey-core) ───────────────────────────────

fn run_create_job(
    cancel: Arc<AtomicBool>,
    tx: Sender<JobUpdate>,
    output: PathBuf,
    password: Zeroizing<String>,
    size_bytes: u64,
    max_bytes: u64,
) {
    let finish = |r: Result<String, String>| {
        let _ = tx.send(JobUpdate::Finished(r));
    };
    let progress = |done: u64, total: u64| {
        let _ = tx.send(JobUpdate::Progress { done, total });
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(VOLUME_OPEN_ERROR.into()));
        return;
    }
    progress(0, 1);
    let opts = VolumeCreateOpts {
        size_bytes,
        max_bytes,
        pad_mode: PadMode::Padme,
        ..VolumeCreateOpts::default()
    };
    let unlock = VolumeUnlock::password_only(password.as_bytes());
    let vol = match Volume::create(&output, &unlock, &opts) {
        Ok(v) => v,
        Err(e) => {
            finish(Err(map_volume_err(e)));
            return;
        }
    };
    // Pin the local freshness anchor for this fresh volume (C70) so the first mount is clean.
    let _ = vol.trust_anchor();
    match vol.close() {
        Ok(()) => finish(Ok(format!(
            "Volume created: {}. Padmé size-padding on (C71).",
            output.display()
        ))),
        Err(e) => finish(Err(map_volume_err(e))),
    }
}

fn run_mount_job(
    cancel: Arc<AtomicBool>,
    tx: Sender<JobUpdate>,
    path: PathBuf,
    password: Zeroizing<String>,
    keyfile_path: String,
    handoff: Arc<Mutex<Option<LiveMount>>>,
) {
    let finish = |r: Result<String, String>| {
        let _ = tx.send(JobUpdate::Finished(r));
    };
    let progress = |done: u64, total: u64| {
        let _ = tx.send(JobUpdate::Progress { done, total });
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(VOLUME_OPEN_ERROR.into()));
        return;
    }
    progress(0, 1);

    let mut keyfile_store: Option<Zeroizing<Vec<u8>>> = None;
    if !keyfile_path.trim().is_empty() {
        match std::fs::read(keyfile_path.trim()) {
            Ok(b) => keyfile_store = Some(Zeroizing::new(b)),
            Err(e) => {
                finish(Err(format!("cannot read keyfile: {e}")));
                return;
            }
        }
    }
    let unlock = VolumeUnlock {
        password: password.as_bytes(),
        keyfile: keyfile_store.as_ref().map(|v| v.as_slice()),
    };
    // Open validates credentials, key commitment (C69), Merkle root + local freshness (C70).
    let vol = match Volume::open(&path, &unlock) {
        Ok(v) => v,
        Err(e) => {
            finish(Err(map_volume_err(e)));
            return;
        }
    };
    let count = vol.list("").map(|v| v.len()).unwrap_or(0);
    let mnt_root = path
        .parent()
        .map(|p| p.join("mnt"))
        .unwrap_or_else(|| PathBuf::from("mnt"));

    // Prefer FUSE when this build can (Linux `volume-mount`; macOS `macos-fuse` + macFUSE).
    #[cfg(any(
        all(feature = "volume-mount", target_os = "linux"),
        all(feature = "macos-fuse", target_os = "macos")
    ))]
    {
        // Leftover cleartext from a prior MaterializedMount session: adopt that, don't FUSE-over it.
        if mnt_root.is_dir()
            && std::fs::read_dir(&mnt_root)
                .ok()
                .and_then(|mut d| d.next())
                .is_some()
        {
            match MaterializedMount::adopt(vol, &mnt_root) {
                Ok(mat) => {
                    return handoff_live(finish, handoff, LiveMount::Materialized(mat), count);
                }
                Err(e) => {
                    finish(Ok(format!(
                        "{} (folder recover failed: {e})",
                        unlock_success_message(count)
                    )));
                    return;
                }
            }
        }
        let _ = std::fs::create_dir_all(&mnt_root);
        match blindkey_fuse::mount_volume(vol, &mnt_root) {
            Ok(guard) => {
                return handoff_live(finish, handoff, LiveMount::Fuse(guard), count);
            }
            Err(_e) => {
                // Fall through: reopen volume for MaterializedMount (fuse consumed/closed on err).
                let vol = match Volume::open(&path, &unlock) {
                    Ok(v) => v,
                    Err(e) => {
                        finish(Err(map_volume_err(e)));
                        return;
                    }
                };
                match MaterializedMount::open_or_adopt(vol, &mnt_root) {
                    Ok(mat) => {
                        return handoff_live(finish, handoff, LiveMount::Materialized(mat), count);
                    }
                    Err(e) => {
                        finish(Ok(format!(
                            "{} (folder open failed: {e})",
                            unlock_success_message(count)
                        )));
                        return;
                    }
                }
            }
        }
    }

    #[cfg(not(any(
        all(feature = "volume-mount", target_os = "linux"),
        all(feature = "macos-fuse", target_os = "macos")
    )))]
    {
        match MaterializedMount::open_or_adopt(vol, &mnt_root) {
            Ok(mat) => handoff_live(finish, handoff, LiveMount::Materialized(mat), count),
            Err(e) => {
                // C79 fallback: credentials were valid; folder materialize failed.
                finish(Ok(format!(
                    "{} (folder open failed: {e})",
                    unlock_success_message(count)
                )));
            }
        }
    }
}

fn handoff_live(
    finish: impl FnOnce(Result<String, String>),
    handoff: Arc<Mutex<Option<LiveMount>>>,
    live: LiveMount,
    count: usize,
) {
    let mp = live.mountpoint().to_path_buf();
    if let Ok(mut slot) = handoff.lock() {
        *slot = Some(live);
    } else {
        drop(live);
        finish(Err("Could not hand off open folder.".into()));
        return;
    }
    finish(Ok(format!(
        "MOUNTED\t{}\t{}",
        mp.display(),
        mount_folder_success_message(&mp, count)
    )));
}

/// Honest unlock closure (UC-26 C79) — validated open, not a live folder.
pub fn unlock_success_message(top_level_count: usize) -> String {
    #[cfg(all(feature = "macos-fuse", target_os = "macos"))]
    {
        if blindkey_sys::macfuse_available() {
            format!(
                "Volume unlocked (validated, {top_level_count} top-level item(s)). \
                 Live FUSE mount failed; opened a cleartext working folder instead."
            )
        } else {
            format!(
                "Volume unlocked (validated, {top_level_count} top-level item(s)). \
                 Install macFUSE from https://macfuse.io for live Finder mounts, or use the \
                 cleartext working folder Blindfolder already opens."
            )
        }
    }
    #[cfg(all(not(feature = "macos-fuse"), target_os = "macos"))]
    {
        let fuse_hint = if blindkey_sys::macfuse_available() {
            "macFUSE is installed — rebuild Blindkey with `--features macos-fuse` for live Finder mounts."
        } else {
            "For live Finder mounts, install macFUSE (https://macfuse.io) and rebuild with \
             `--features macos-fuse`. Blindkey does not bundle macFUSE/Fuse-T."
        };
        format!(
            "Volume unlocked (validated, {top_level_count} top-level item(s)). {fuse_hint}"
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!(
            "Volume unlocked (validated, {top_level_count} top-level item(s)). \
             Live folder mount runs through `blindkey volume mount` / blindkey-fuse."
        )
    }
}

/// Success when a cleartext working folder is open (MaterializedMount / degraded ADR-0010).
pub fn mount_folder_success_message(mount_path: &Path, top_level_count: usize) -> String {
    format!(
        "Folder open at {} ({top_level_count} top-level item(s)). \
         Files are cleartext until Eject (C72).",
        mount_path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_root_detected_and_cta_present() {
        assert!(is_under_sync_root(Path::new(
            "/Users/x/Dropbox/vaults/work.vltd"
        )));
        assert!(is_under_sync_root(Path::new(
            "/Users/x/Library/Mobile Documents/work.vltd"
        )));
        assert!(!is_under_sync_root(Path::new(
            "/Users/x/Documents/work.vltd"
        )));
        let cta = sync_root_seal_cta(Path::new("/Users/x/Google Drive/w.vltd")).unwrap();
        assert!(cta.contains("Seal files") || cta.contains("Seal"));
        assert!(sync_root_seal_cta(Path::new("/tmp/local.vltd")).is_none());
    }

    #[test]
    fn banner_shown_once_per_session() {
        let mut gui = VolumeGui::new();
        assert!(!gui.banner_pending());
        gui.request_mount(PathBuf::from("/tmp/a.vltd"));
        assert!(gui.banner_pending(), "first mount must show the banner");
        // Acknowledge.
        gui.banner_acknowledged = true;
        gui.pending_mount = None;
        // A second mount this session must not re-arm the banner.
        gui.request_mount(PathBuf::from("/tmp/b.vltd"));
        assert!(!gui.banner_pending(), "banner is once per session");
    }

    #[test]
    fn mount_under_sync_root_refused_with_cta() {
        let mut gui = VolumeGui::new();
        gui.request_mount(PathBuf::from("/Users/x/Dropbox/w.vltd"));
        assert!(
            !gui.banner_pending(),
            "cloud-sync mount must be refused, not queued"
        );
        assert!(
            gui.take_error().is_some(),
            "refusal surfaces a Seal CTA error"
        );
    }

    #[test]
    fn vltd_path_by_extension() {
        assert!(is_vltd_path(Path::new("workspace.vltd")));
        assert!(is_vltd_path(Path::new("WORK.VLTD")));
        assert!(!is_vltd_path(Path::new("archive.vltf")));
    }

    #[test]
    fn banner_and_lock_note_are_honest() {
        assert!(RESIDUAL_RISK_BANNER.contains("cleartext"));
        assert!(RESIDUAL_RISK_BANNER.contains("C27"));
        assert!(LOCK_ON_SLEEP_NOTE.contains("best-effort"));
    }

    #[test]
    fn eject_returns_to_locked() {
        let mut gui = VolumeGui::new();
        gui.session = VolumeSessionKind::Unlocked;
        gui.active_path = Some(PathBuf::from("/tmp/a.vltd"));
        gui.mount_path = Some(PathBuf::from("/Volumes/bk"));
        assert_eq!(gui.session_status(), crate::gui_mode::SessionStatus::Mounted);
        gui.eject();
        assert_eq!(gui.session, VolumeSessionKind::Locked);
        assert_eq!(gui.session_status().label(), "Locked");
        assert!(gui.mount_path.is_none());
        let msg = gui.take_status().unwrap();
        assert!(msg.contains("Ejected"));
    }

    #[test]
    fn session_status_unlocked_without_mount() {
        let mut gui = VolumeGui::new();
        gui.session = VolumeSessionKind::Unlocked;
        assert_eq!(
            gui.session_status(),
            crate::gui_mode::SessionStatus::Unlocked
        );
    }

    #[test]
    fn sync_cta_preferred_prefix() {
        let cta = sync_root_seal_cta(Path::new("/Users/x/Dropbox/w.vltd")).unwrap();
        assert!(
            cta.contains("unsupported") && (cta.contains("Seal") || cta.contains("Blindfolder")),
            "CTA={cta}"
        );
    }

    #[test]
    fn unlock_success_never_claims_mounted() {
        let msg = unlock_success_message(3);
        assert!(msg.contains("unlocked (validated"));
        assert!(!msg.contains("Mounted"));
        assert!(!msg.to_lowercase().contains("are cleartext while mounted"));
        #[cfg(target_os = "macos")]
        assert!(
            msg.contains("macfuse.io") || msg.contains("macos-fuse") || msg.contains("macFUSE"),
            "macOS unlock copy must be honest about macFUSE packaging: {msg}"
        );
    }

    #[test]
    fn default_volume_output_is_local_documents() {
        let p = default_volume_output();
        assert!(
            p.contains("blindkey-workspace.vltd"),
            "default path={p}"
        );
        assert!(
            !p.to_lowercase().contains("dropbox"),
            "must not default under Dropbox: {p}"
        );
    }

    #[test]
    fn take_seal_request_is_oneshot() {
        let mut gui = VolumeGui::new();
        assert!(!gui.take_seal_request());
        gui.seal_request = true;
        assert!(gui.take_seal_request());
        assert!(!gui.take_seal_request());
    }

    #[test]
    fn sync_refuse_keeps_cta_for_workspace_recovery() {
        let mut gui = VolumeGui::new();
        gui.request_mount(PathBuf::from("/Users/x/Dropbox/w.vltd"));
        assert!(gui.sync_refuse_cta.is_some());
        assert!(gui.take_error().is_some());
        assert!(
            gui.sync_refuse_cta.is_some(),
            "CTA must survive take_error for Workspace Seal recovery"
        );
    }
}
