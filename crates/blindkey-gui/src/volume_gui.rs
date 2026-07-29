//! UC-25 local encrypted volume GUI — create / mount / eject over `blindkey_core::volume`
//! (Phase C). A thin UC-18 shell: every byte that touches a secret stays in `blindkey-core`;
//! this module only collects paths/passphrases, drives a worker thread, and renders honest copy.
//!
//! Honesty posture (C72 / SC10): while a volume is mounted the OS sees cleartext — same class as
//! an unlocked FileVault. The residual-risk banner states this once per session. Live RW mount of
//! a `.vltd` on a cloud-sync folder is unsupported (C73) — we refuse and point to `blindkey seal`.
//! Live folder mounting itself runs through the userspace FUSE path (`blindkey volume mount` /
//! `blindkey-fuse`); this shell drives Create and Open/validate against the core today.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use blindkey_core::pad::PadMode;
use blindkey_core::{Error, Volume, VolumeCreateOpts, VolumeUnlock, MAGIC_VLTD, VOLUME_OPEN_ERROR};
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
/// Matches the common consumer sync folders; deliberately conservative (name-based, case-insensitive).
pub fn is_under_sync_root(path: &Path) -> bool {
    const SYNC_MARKERS: &[&str] = &[
        "dropbox",
        "google drive",
        "googledrive",
        "onedrive",
        "icloud drive",
        "com~apple~clouddocs", // iCloud Drive on macOS
        "mobile documents",    // ~/Library/Mobile Documents (iCloud)
        "syncthing",
        "pcloud",
        "box sync",
        "mega",
        "nextcloud",
        "owncloud",
    ];
    path.components().any(|c| {
        let seg = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        SYNC_MARKERS.iter().any(|m| seg == *m || seg.contains(m))
    })
}

/// Seal CTA (C73) when `path` is under a sync root — warn + point to the sealed-file path. `None`
/// when the path is local, so the caller can proceed normally.
pub fn sync_root_seal_cta(path: &Path) -> Option<String> {
    if is_under_sync_root(path) {
        Some(
            "Dropbox sync of a live volume is unsupported. Seal files instead. \
             (Live-mounting a .vltd on Dropbox/Drive/iCloud/Syncthing can corrupt the volume.)"
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
    pub error: Option<String>,
}

impl MountDialog {
    fn new(path: PathBuf) -> Self {
        Self {
            volume_path: path,
            password: String::new(),
            keyfile_path: String::new(),
            show_password: false,
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
    /// Credentials validated; Finder mount may still be unavailable (C79).
    Unlocked,
}

/// UC-25 volume GUI controller — Create / Unlock / Eject over `blindkey_core::volume`.
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
    /// Set only when a real OS mount point exists (Reveal in Finder gate).
    mount_path: Option<PathBuf>,
    /// C73 recovery: open Seal files flow (picker) from sync-refuse UI.
    seal_request: bool,
    /// Last sync-root refuse message (survives `take_error` for Workspace CTA).
    sync_refuse_cta: Option<String>,
}

impl Default for VolumeGui {
    fn default() -> Self {
        Self::new()
    }
}

impl VolumeGui {
    pub fn new() -> Self {
        Self {
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
            seal_request: false,
            sync_refuse_cta: None,
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
            return;
        }
        if self.banner_acknowledged {
            self.mount_dialog = Some(MountDialog::new(path));
        } else {
            self.pending_mount = Some(path);
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
                Ok(msg) => {
                    if msg.contains("unlocked (validated") || msg.starts_with("Volume created:") {
                        self.session = VolumeSessionKind::Unlocked;
                        self.mount_path = None; // validate path — no OS mount yet (C79)
                    }
                    self.status = Some(msg);
                }
                Err(e) => self.error = Some(e),
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
        self.start_worker("Unlocking volume…".into(), move |cancel, tx| {
            run_mount_job(cancel, tx, path, password, keyfile_path);
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

    /// Clear validated session (UC-26 IA-01 / IA-12).
    pub fn eject(&mut self) {
        self.session = VolumeSessionKind::Locked;
        self.mount_path = None;
        self.status = Some("Ejected — files locked.".into());
        self.error = None;
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
            ui.weak("Workspace = edit as a folder. Seal = encrypt files for Dropbox/USB.");
            ui.add_space(SPACE_M);

            if !path_label.is_empty() {
                ui.monospace(egui::RichText::new(&path_label).small());
                ui.add_space(SPACE_S);
            }

            let seal_recovery = self.sync_refuse_cta.clone();
            if let Some(cta) = seal_recovery {
                ui.colored_label(theme::WARN, cta);
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
                    ui.label("Volume unlocked (validated).");
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
                        ui.weak("Reveal in Finder appears only when an OS mount path exists.");
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
        self.residual_banner_window(ctx);
        self.create_window(ctx);
        self.mount_window(ctx);
        self.progress_window(ctx);
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
                ui.weak(LOCK_ON_SLEEP_NOTE);
                ui.add_space(crate::theme::SPACE_M);
                ui.horizontal(|ui| {
                    if ui.button("I understand — continue").clicked() {
                        acknowledged = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
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
                let mut focus_pw = false;
                crate::theme::labeled_secret_row(
                    ui,
                    "Passphrase",
                    &mut dlg.password,
                    &mut dlg.show_password,
                    &mut focus_pw,
                );
                crate::theme::labeled_secret_confirm(
                    ui,
                    "Confirm passphrase",
                    &mut dlg.confirm,
                    dlg.show_password,
                );
                ui.add_space(crate::theme::SPACE_XS);
                ui.weak("Size padding: on (Padmé default — hides exact volume size).");
                ui.weak(LOCK_ON_SLEEP_NOTE);
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
                    if crate::theme::secondary_button(ui, "Seal files…", 160.0).clicked()
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
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    if crate::theme::primary_button(ui, "Create", 100.0).clicked() {
                        start = true;
                    }
                });
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
                let mut focus_pw = false;
                crate::theme::labeled_secret_row(
                    ui,
                    "Passphrase",
                    &mut dlg.password,
                    &mut dlg.show_password,
                    &mut focus_pw,
                );
                ui.collapsing("Advanced…", |ui| {
                    ui.label("Keyfile path (optional)");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut dlg.keyfile_path)
                                .desired_width(220.0)
                                .hint_text("/path/to/keyfile"),
                        );
                        if ui.button("Choose…").clicked() {
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
                ui.weak(LOCK_ON_SLEEP_NOTE);
                if let Some(e) = &dlg.error {
                    ui.add_space(crate::theme::SPACE_XS);
                    ui.colored_label(crate::theme::DANGER, e);
                }
                ui.add_space(crate::theme::SPACE_S);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    // C79: Unlock — not Mount — when this dialog only validates credentials.
                    if crate::theme::primary_button(ui, "Unlock", 100.0).clicked() {
                        unlock = true;
                    }
                });
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
                if ui.button("Cancel").clicked() {
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
    // UC-26 C79 / Expected Ability: this GUI path validates unlock only — it does **not**
    // create an OS mount. Never claim "Mounted" here. Live Finder mount needs Fuse packaging
    // (macOS) or `blindkey volume mount` / blindkey-fuse (Linux).
    let _ = vol.close();
    finish(Ok(unlock_success_message(count)));
}

/// Honest unlock closure (UC-26 C79) — validated open, not Finder mount.
pub fn unlock_success_message(top_level_count: usize) -> String {
    #[cfg(target_os = "macos")]
    {
        format!(
            "Volume unlocked (validated, {top_level_count} top-level item(s)). \
             Finder mount needs Fuse packaging on this Mac."
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
            cta.starts_with("Dropbox sync of a live volume is unsupported. Seal files instead."),
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
        assert!(msg.contains("Finder mount needs Fuse packaging on this Mac."));
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
