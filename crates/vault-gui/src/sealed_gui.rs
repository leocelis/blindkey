//! UC-23 sealed-file GUI — seal / open / peek dialogs and background jobs (Phase C).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use eframe::egui;
use vault_core::pad::PadMode;
use vault_core::sealed::{
    ArchiveEntryMeta, SealOptions, SealedContainer, SealedIoOpts, SealedUnlock, SEALED_OPEN_ERROR,
};
use vault_core::{Error, MAGIC_VLTF};
use zeroize::{Zeroize, Zeroizing};

use crate::list_virtualize::{visible_slice_range, ENTRY_ROW_HEIGHT};

use crate::keyfile_gui::{load_or_create_keyfile, recovery_code};

/// Classify a filesystem drop for UC-23 routing.
pub enum SealedDrop {
    OpenContainer(PathBuf),
    SealPaths(Vec<PathBuf>),
}

pub fn is_vltf_path(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("vltf"))
    {
        return true;
    }
    let mut magic = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        if f.read_exact(&mut magic).is_ok() && magic == MAGIC_VLTF {
            return true;
        }
    }
    false
}

pub fn classify_drop(path: &Path) -> Option<SealedDrop> {
    if path.is_file() && is_vltf_path(path) {
        return Some(SealedDrop::OpenContainer(path.to_path_buf()));
    }
    if path.is_file() || path.is_dir() {
        return Some(SealedDrop::SealPaths(vec![path.to_path_buf()]));
    }
    None
}

fn default_output_path(paths: &[PathBuf]) -> Option<PathBuf> {
    let first = paths.first()?;
    let stem = if first.is_dir() {
        first.file_name()
    } else {
        first.file_stem()
    }?;
    Some(PathBuf::from(format!("{}.vltf", stem.to_string_lossy())))
}

fn map_sealed_err(e: Error) -> String {
    match e {
        Error::HeaderAuth => "Incorrect passphrase.".to_string(),
        Error::SealedOpenFailed => SEALED_OPEN_ERROR.to_string(),
        Error::WrongContainerKind => "Wrong container type.".to_string(),
        Error::Io(e) => e.to_string(),
        _ => SEALED_OPEN_ERROR.to_string(),
    }
}

/// Atomic write for `.vltf` (C32 — temp + fsync + rename).
pub fn write_sealed_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
    }
    let tmp = path.with_extension("vltf.tmp");
    {
        let mut oo = std::fs::OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o600);
        }
        let mut f = oo.open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

pub struct SealDialog {
    pub input_paths: Vec<PathBuf>,
    pub output_path: String,
    pub password: String,
    pub confirm: String,
    /// Optional keyfile 2FA at seal time (UC-09 parity with CLI enroll keyfile).
    pub enroll_keyfile: bool,
    pub keyfile_path: String,
    /// Optional YubiKey 2FA at seal time (programs slot 2 — UC-09 / C2).
    pub enroll_yubikey: bool,
    /// Padmé on by default (C66); only toggled via advanced expander.
    pub pad_enabled: bool,
    pub show_advanced: bool,
    pub error: Option<String>,
}

impl SealDialog {
    fn new(paths: Vec<PathBuf>) -> Self {
        let output_path = default_output_path(&paths)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "sealed.vltf".into());
        Self {
            input_paths: paths,
            output_path,
            password: String::new(),
            confirm: String::new(),
            enroll_keyfile: false,
            keyfile_path: String::new(),
            enroll_yubikey: false,
            pad_enabled: true,
            show_advanced: false,
            error: None,
        }
    }
}

impl Drop for SealDialog {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
    }
}

pub struct OpenDialog {
    pub container_path: PathBuf,
    pub dest_path: String,
    pub password: String,
    pub keyfile_path: String,
    pub error: Option<String>,
}

impl OpenDialog {
    fn new(container: PathBuf) -> Self {
        Self {
            container_path: container,
            dest_path: ".".into(),
            password: String::new(),
            keyfile_path: String::new(),
            error: None,
        }
    }
}

impl Drop for OpenDialog {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub struct PeekView {
    pub container_path: PathBuf,
    pub entries: Vec<ArchiveEntryMeta>,
}

enum JobUpdate {
    Progress { done: u64, total: u64 },
    Finished(Result<String, String>),
}

pub struct SealedWorker {
    cancel: Arc<AtomicBool>,
    rx: Receiver<JobUpdate>,
    handle: Option<thread::JoinHandle<()>>,
    pub label: String,
    started: Instant,
    pub done: u64,
    pub total: u64,
}

impl SealedWorker {
    fn poll(&mut self, _ctx: &egui::Context) -> Option<Result<String, String>> {
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

    pub fn running(&self) -> bool {
        self.handle.is_some()
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn throughput_mib_s(&self) -> f64 {
        let elapsed = self.started.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return 0.0;
        }
        // Coarse phase progress — honest label, not byte-accurate until core exposes counters.
        (self.done as f64 / self.total as f64) / elapsed
    }
}

pub struct SealedGui {
    pub seal_dialog: Option<SealDialog>,
    pub open_dialog: Option<OpenDialog>,
    pub peek_view: Option<PeekView>,
    worker: Option<SealedWorker>,
    status: Option<String>,
    error: Option<String>,
}

impl Default for SealedGui {
    fn default() -> Self {
        Self::new()
    }
}

impl SealedGui {
    pub fn new() -> Self {
        Self {
            seal_dialog: None,
            open_dialog: None,
            peek_view: None,
            worker: None,
            status: None,
            error: None,
        }
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

    pub fn open_seal_dialog(&mut self, paths: Vec<PathBuf>) {
        if self.job_running() {
            return;
        }
        self.seal_dialog = Some(SealDialog::new(paths));
    }

    pub fn open_open_dialog(&mut self, container: PathBuf) {
        if self.job_running() {
            return;
        }
        self.open_dialog = Some(OpenDialog::new(container));
    }

    /// Route egui file drops — returns `true` if consumed (caller skips keys.txt import).
    pub fn handle_drops(&mut self, dropped: &[egui::DroppedFile]) -> bool {
        if self.job_running() {
            return true;
        }
        let paths: Vec<PathBuf> = dropped.iter().filter_map(|f| f.path.clone()).collect();
        if paths.is_empty() {
            return false;
        }

        if paths.len() == 1 {
            match classify_drop(&paths[0]) {
                Some(SealedDrop::OpenContainer(p)) => {
                    self.open_open_dialog(p);
                    return true;
                }
                Some(SealedDrop::SealPaths(v)) => {
                    self.open_seal_dialog(v);
                    return true;
                }
                None => return false,
            }
        }

        let seal: Vec<PathBuf> = paths
            .into_iter()
            .filter(|p| (p.is_file() && !is_vltf_path(p)) || p.is_dir())
            .collect();
        if !seal.is_empty() {
            self.open_seal_dialog(seal);
            return true;
        }
        false
    }

    pub fn poll_worker(&mut self, ctx: &egui::Context) {
        let Some(worker) = &mut self.worker else {
            return;
        };
        if let Some(result) = worker.poll(ctx) {
            self.worker = None;
            match result {
                Ok(msg) => self.status = Some(msg),
                Err(e) => self.error = Some(e),
            }
        } else if worker.running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn start_worker(
        &mut self,
        _ctx: &egui::Context,
        label: String,
        spawn: impl FnOnce(Arc<AtomicBool>, Sender<JobUpdate>) + Send + 'static,
    ) {
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let c_cancel = cancel.clone();
        let handle = thread::spawn(move || spawn(c_cancel, tx));
        self.worker = Some(SealedWorker {
            cancel,
            rx,
            handle: Some(handle),
            label,
            started: Instant::now(),
            done: 0,
            total: 1,
        });
    }

    fn try_start_seal(&mut self, ctx: &egui::Context) -> bool {
        let Some(mut dlg) = self.seal_dialog.take() else {
            return false;
        };
        if dlg.password != dlg.confirm {
            dlg.error = Some("Passphrases do not match.".into());
            self.seal_dialog = Some(dlg);
            return true;
        }
        if dlg.password.is_empty() {
            dlg.error = Some("Passphrase required.".into());
            self.seal_dialog = Some(dlg);
            return true;
        }
        if dlg.enroll_keyfile && dlg.enroll_yubikey {
            dlg.error = Some("Choose keyfile OR YubiKey 2FA, not both.".into());
            self.seal_dialog = Some(dlg);
            return true;
        }
        if dlg.enroll_keyfile && dlg.keyfile_path.trim().is_empty() {
            dlg.error = Some("Keyfile path required when keyfile 2FA is enabled.".into());
            self.seal_dialog = Some(dlg);
            return true;
        }
        if dlg.enroll_yubikey && !vault_hardware::yubikey::available() {
            dlg.error = Some(
                "No YubiKey detected — plug it in and install YubiKey Manager (ykman).".into(),
            );
            self.seal_dialog = Some(dlg);
            return true;
        }
        let output = PathBuf::from(&dlg.output_path);
        if output.exists() {
            dlg.error = Some(format!("Refusing to overwrite {}.", output.display()));
            self.seal_dialog = Some(dlg);
            return true;
        }
        let paths = dlg.input_paths.clone();
        let pad_mode = if dlg.pad_enabled {
            PadMode::Padme
        } else {
            PadMode::None
        };
        let seal_2fa = if dlg.enroll_yubikey {
            Seal2faAtCreate::YubiKey
        } else if dlg.enroll_keyfile {
            Seal2faAtCreate::Keyfile(PathBuf::from(dlg.keyfile_path.trim()))
        } else {
            Seal2faAtCreate::None
        };
        let password = Zeroizing::new(dlg.password.clone());
        dlg.password.zeroize();
        dlg.confirm.zeroize();
        drop(dlg);

        self.start_worker(ctx, "Sealing…".into(), move |cancel, tx| {
            run_seal_job(cancel, tx, paths, output, password, pad_mode, seal_2fa);
        });
        true
    }

    fn try_start_open(&mut self, ctx: &egui::Context) -> bool {
        let Some(mut dlg) = self.open_dialog.take() else {
            return false;
        };
        if dlg.password.is_empty() {
            dlg.error = Some("Passphrase required.".into());
            self.open_dialog = Some(dlg);
            return true;
        }
        let container = dlg.container_path.clone();
        let dest = PathBuf::from(&dlg.dest_path);
        let password = Zeroizing::new(dlg.password.clone());
        let keyfile_path = dlg.keyfile_path.clone();
        dlg.password.zeroize();
        drop(dlg);

        self.start_worker(ctx, "Opening…".into(), move |cancel, tx| {
            run_open_job(cancel, tx, container, dest, password, keyfile_path);
        });
        true
    }

    fn try_peek(&mut self) -> bool {
        let Some(dlg) = self.open_dialog.as_ref() else {
            return false;
        };
        if dlg.password.is_empty() {
            return false;
        }
        let container = dlg.container_path.clone();
        let password = Zeroizing::new(dlg.password.clone());
        let keyfile_path = dlg.keyfile_path.clone();
        let bytes = match std::fs::read(&container) {
            Ok(b) => b,
            Err(e) => {
                self.error = Some(e.to_string());
                return true;
            }
        };
        let mut keyfile_store = None;
        let unlock = match build_unlock(
            &bytes,
            password.as_bytes(),
            &keyfile_path,
            &mut keyfile_store,
        ) {
            Ok(u) => u,
            Err(e) => {
                self.open_dialog.as_mut().unwrap().error = Some(e);
                return true;
            }
        };
        match SealedContainer::peek_entries(&bytes, &unlock) {
            Ok(entries) => {
                self.peek_view = Some(PeekView {
                    container_path: container,
                    entries,
                });
                true
            }
            Err(e) => {
                self.open_dialog.as_mut().unwrap().error = Some(map_sealed_err(e));
                true
            }
        }
    }

    pub fn windows(&mut self, ctx: &egui::Context) {
        self.seal_window(ctx);
        self.open_window(ctx);
        self.peek_window(ctx);
        self.progress_window(ctx);
    }
}

fn build_unlock<'a>(
    bytes: &[u8],
    password: &'a [u8],
    keyfile_path: &str,
    keyfile_store: &'a mut Option<Zeroizing<Vec<u8>>>,
) -> Result<SealedUnlock<'a>, String> {
    if SealedContainer::requires_keyfile(bytes) {
        if keyfile_path.trim().is_empty() {
            return Err("This container requires a keyfile.".into());
        }
        let kf = Zeroizing::new(
            std::fs::read(keyfile_path)
                .map_err(|e| format!("cannot read keyfile {keyfile_path}: {e}"))?,
        );
        *keyfile_store = Some(kf);
        Ok(SealedUnlock {
            password,
            keyfile: keyfile_store.as_ref().map(|v| v.as_slice()),
        })
    } else {
        Ok(SealedUnlock::password_only(password))
    }
}

enum Seal2faAtCreate {
    None,
    Keyfile(PathBuf),
    YubiKey,
}

fn run_seal_job(
    cancel: Arc<AtomicBool>,
    tx: Sender<JobUpdate>,
    paths: Vec<PathBuf>,
    output: PathBuf,
    password: Zeroizing<String>,
    pad_mode: PadMode,
    seal_2fa: Seal2faAtCreate,
) {
    let progress = |done: u64, total: u64| {
        let _ = tx.send(JobUpdate::Progress { done, total });
    };
    let finish = |r: Result<String, String>| {
        let _ = tx.send(JobUpdate::Finished(r));
    };

    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    progress(0, 1);
    let opts = SealOptions {
        pad_mode,
        ..SealOptions::default()
    };
    let mut container = match SealedContainer::create(password.as_bytes(), opts) {
        Ok(c) => c,
        Err(e) => {
            finish(Err(e.to_string()));
            return;
        }
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    let refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
    let mut progress_cb = |done: u64, total: u64| {
        let _ = tx.send(JobUpdate::Progress { done, total });
    };
    let mut io = SealedIoOpts {
        cancel: Some(&cancel),
        progress: Some(&mut progress_cb),
    };
    let body_bytes = match container.seal_paths_with(&refs, &mut io) {
        Ok(b) => b,
        Err(e) => {
            finish(Err(e.to_string()));
            return;
        }
    };
    let (final_bytes, recovery_note) = match seal_2fa {
        Seal2faAtCreate::None => (body_bytes, None),
        Seal2faAtCreate::Keyfile(kf_path) => {
            let keyfile = match load_or_create_keyfile(&kf_path) {
                Ok(k) => k,
                Err(e) => {
                    finish(Err(e));
                    return;
                }
            };
            let recovery = match recovery_code() {
                Ok(c) => c,
                Err(e) => {
                    finish(Err(e));
                    return;
                }
            };
            if let Err(e) = container.enroll_keyfile_2fa(
                password.as_bytes(),
                keyfile.as_slice(),
                recovery.as_bytes(),
            ) {
                finish(Err(e.to_string()));
                return;
            }
            let bytes = match container.save_preserving_body(&body_bytes) {
                Ok(b) => b,
                Err(e) => {
                    finish(Err(e.to_string()));
                    return;
                }
            };
            (
                bytes,
                Some(format!(
                    "Sealed with keyfile 2FA. Recovery code (store offline): {recovery}"
                )),
            )
        }
        Seal2faAtCreate::YubiKey => {
            if let Err(e) = vault_hardware::yubikey::program_chalresp_slot2() {
                finish(Err(e));
                return;
            }
            let mut challenge = [0u8; 32];
            if getrandom::getrandom(&mut challenge).is_err() {
                finish(Err("cannot generate YubiKey challenge".into()));
                return;
            }
            let hw_response = match vault_hardware::yubikey::challenge_response(&challenge) {
                Ok(r) => r,
                Err(e) => {
                    finish(Err(e));
                    return;
                }
            };
            let recovery = match recovery_code() {
                Ok(c) => c,
                Err(e) => {
                    finish(Err(e));
                    return;
                }
            };
            if let Err(e) = container.enroll_yubikey_2fa(
                password.as_bytes(),
                hw_response.as_slice(),
                &challenge,
                recovery.as_bytes(),
            ) {
                finish(Err(e.to_string()));
                return;
            }
            let bytes = match container.save_preserving_body(&body_bytes) {
                Ok(b) => b,
                Err(e) => {
                    finish(Err(e.to_string()));
                    return;
                }
            };
            (
                bytes,
                Some(format!(
                    "Sealed with YubiKey 2FA. Recovery code (store offline): {recovery}"
                )),
            )
        }
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    if let Err(e) = write_sealed_atomic(&output, &final_bytes) {
        finish(Err(e));
        return;
    }
    let msg = recovery_note.unwrap_or_else(|| "Sealed container saved.".to_string());
    finish(Ok(msg));
}

fn run_open_job(
    cancel: Arc<AtomicBool>,
    tx: Sender<JobUpdate>,
    container: PathBuf,
    dest: PathBuf,
    password: Zeroizing<String>,
    keyfile_path: String,
) {
    let progress = |done: u64, total: u64| {
        let _ = tx.send(JobUpdate::Progress { done, total });
    };
    let finish = |r: Result<String, String>| {
        let _ = tx.send(JobUpdate::Finished(r));
    };

    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    progress(0, 1);
    let bytes = match std::fs::read(&container) {
        Ok(b) => b,
        Err(e) => {
            finish(Err(e.to_string()));
            return;
        }
    };
    if cancel.load(Ordering::Relaxed) {
        finish(Err(SEALED_OPEN_ERROR.into()));
        return;
    }
    let mut keyfile_store = None;
    let unlock = match build_unlock(
        &bytes,
        password.as_bytes(),
        &keyfile_path,
        &mut keyfile_store,
    ) {
        Ok(u) => u,
        Err(e) => {
            finish(Err(e));
            return;
        }
    };
    let mut progress_cb = |done: u64, total: u64| {
        let _ = tx.send(JobUpdate::Progress { done, total });
    };
    let mut io = SealedIoOpts {
        cancel: Some(&cancel),
        progress: Some(&mut progress_cb),
    };
    if SealedContainer::requires_yubikey(&bytes) {
        let mut respond = |challenge: &[u8; 32]| -> Result<Zeroizing<Vec<u8>>, Error> {
            vault_hardware::yubikey::challenge_response(challenge).map_err(Error::Hardware)
        };
        if let Err(e) =
            SealedContainer::open_to_dir_with(&bytes, &unlock, &dest, &mut io, Some(&mut respond))
        {
            finish(Err(map_sealed_err(e)));
            return;
        }
    } else if let Err(e) = SealedContainer::open_to_dir_with(&bytes, &unlock, &dest, &mut io, None)
    {
        finish(Err(map_sealed_err(e)));
        return;
    }
    finish(Ok("Container extracted.".into()));
}

impl SealedGui {
    fn seal_window(&mut self, ctx: &egui::Context) {
        let Some(dlg) = self.seal_dialog.as_mut() else {
            return;
        };
        let mut start = false;
        let mut cancel = false;
        egui::Window::new("🔐 Seal files")
            .collapsible(false)
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label(format!("{} path(s) selected.", dlg.input_paths.len()));
                ui.horizontal(|ui| {
                    ui.label("Output file");
                    ui.add(
                        egui::TextEdit::singleline(&mut dlg.output_path)
                            .desired_width(240.0)
                            .hint_text("name.vltf"),
                    );
                    if ui.button("Save as…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_title("Save sealed container")
                            .add_filter("Vault sealed file", &["vltf"])
                            .set_file_name("sealed.vltf")
                            .save_file()
                        {
                            dlg.output_path = p.display().to_string();
                        }
                    }
                });
                ui.add_space(6.0);
                ui.label("Passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut dlg.password)
                        .password(true)
                        .desired_width(320.0),
                );
                ui.label("Confirm passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut dlg.confirm)
                        .password(true)
                        .desired_width(320.0),
                );
                ui.add_space(4.0);
                ui.collapsing("Advanced", |ui| {
                    dlg.show_advanced = true;
                    ui.checkbox(&mut dlg.pad_enabled, "Pad size (Padmé — recommended)");
                    ui.checkbox(&mut dlg.enroll_keyfile, "Require keyfile at unlock (2FA)");
                    if dlg.enroll_keyfile {
                        dlg.enroll_yubikey = false;
                        ui.horizontal(|ui| {
                            ui.label("Keyfile");
                            ui.add(
                                egui::TextEdit::singleline(&mut dlg.keyfile_path)
                                    .desired_width(200.0)
                                    .hint_text("path to keyfile"),
                            );
                            if ui.button("Browse…").clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .set_title("Select or create keyfile")
                                    .save_file()
                                {
                                    dlg.keyfile_path = p.display().to_string();
                                }
                            }
                        });
                    }
                    ui.checkbox(
                        &mut dlg.enroll_yubikey,
                        "Require YubiKey at unlock (2FA — overwrites slot 2)",
                    );
                    if dlg.enroll_yubikey {
                        dlg.enroll_keyfile = false;
                        ui.label("Touch the key when prompted during sealing.");
                    }
                });
                if !dlg.pad_enabled && !dlg.show_advanced {
                    ui.label("Size padding: on (Padmé default)");
                }
                if let Some(e) = &dlg.error {
                    ui.colored_label(egui::Color32::RED, e);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    if ui.button("Seal").clicked() {
                        start = true;
                    }
                });
            });
        if cancel {
            self.seal_dialog = None;
        } else if start {
            self.try_start_seal(ctx);
        }
    }

    fn open_window(&mut self, ctx: &egui::Context) {
        let Some(dlg) = self.open_dialog.as_mut() else {
            return;
        };
        let mut extract = false;
        let mut peek = false;
        let mut cancel = false;
        egui::Window::new("📂 Open sealed container")
            .collapsible(false)
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label(format!(
                    "Container: {}",
                    dlg.container_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                ));
                ui.horizontal(|ui| {
                    ui.label("Extract to");
                    ui.add(
                        egui::TextEdit::singleline(&mut dlg.dest_path)
                            .desired_width(220.0)
                            .hint_text("folder"),
                    );
                    if ui.button("Choose…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_title("Extract sealed container")
                            .pick_folder()
                        {
                            dlg.dest_path = p.display().to_string();
                        }
                    }
                });
                ui.add_space(6.0);
                ui.label("Passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut dlg.password)
                        .password(true)
                        .desired_width(320.0),
                );
                if SealedContainer::requires_keyfile(
                    &std::fs::read(&dlg.container_path).unwrap_or_default(),
                ) {
                    ui.horizontal(|ui| {
                        ui.label("Keyfile");
                        ui.add(
                            egui::TextEdit::singleline(&mut dlg.keyfile_path)
                                .desired_width(220.0)
                                .hint_text("path to keyfile"),
                        );
                        if ui.button("Browse…").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .set_title("Select keyfile")
                                .pick_file()
                            {
                                dlg.keyfile_path = p.display().to_string();
                            }
                        }
                    });
                }
                if let Some(e) = &dlg.error {
                    ui.colored_label(egui::Color32::RED, e);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    if ui.button("Peek").clicked() {
                        peek = true;
                    }
                    if ui.button("Extract").clicked() {
                        extract = true;
                    }
                });
            });
        if cancel {
            self.open_dialog = None;
        } else if peek {
            self.try_peek();
        } else if extract {
            self.try_start_open(ctx);
        }
    }

    fn peek_window(&mut self, ctx: &egui::Context) {
        let Some(view) = self.peek_view.as_ref() else {
            return;
        };
        let entries = view.entries.clone();
        let title = format!(
            "Sealed contents — {}",
            view.container_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
        let mut close = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .default_height(360.0)
            .show(ctx, |ui| {
                if entries.is_empty() {
                    ui.label("(empty container)");
                } else {
                    let scroll = egui::ScrollArea::vertical().auto_shrink([false; 2]);
                    scroll.show(ui, |ui| {
                        ui.label(format!(
                            "path ({} files) — sizes only, no contents",
                            entries.len()
                        ));
                        ui.separator();
                        let scroll_off = (-ui.min_rect().top()).max(0.0);
                        let range =
                            visible_slice_range(entries.len(), scroll_off, ui.clip_rect().height());
                        let (lo, hi) = (range.start, range.end);
                        if lo > 0 {
                            ui.allocate_space(egui::vec2(
                                ui.available_width(),
                                lo as f32 * ENTRY_ROW_HEIGHT,
                            ));
                        }
                        for e in &entries[lo..hi] {
                            ui.horizontal(|ui| {
                                ui.label(&e.path);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(format!("{} B", e.size));
                                    },
                                );
                            });
                        }
                        if hi < entries.len() {
                            ui.allocate_space(egui::vec2(
                                ui.available_width(),
                                (entries.len() - hi) as f32 * ENTRY_ROW_HEIGHT,
                            ));
                        }
                    });
                }
                ui.add_space(8.0);
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
        if close {
            self.peek_view = None;
        }
    }

    fn progress_window(&mut self, ctx: &egui::Context) {
        let Some(worker) = self.worker.as_ref() else {
            return;
        };
        let done = worker.done;
        let total = worker.total;
        let label = worker.label.clone();
        let phase_rate = worker.throughput_mib_s();
        let mut cancel = false;
        egui::Window::new(&label)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let frac = (done as f32 / total as f32).clamp(0.0, 1.0);
                ui.add(egui::ProgressBar::new(frac).show_percentage());
                ui.label(format!("Phase {done}/{total} ({phase_rate:.2}/s)"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_stem() {
        let p = default_output_path(&[PathBuf::from("docs/report.pdf")]).unwrap();
        assert_eq!(p, PathBuf::from("report.vltf"));
    }
}
