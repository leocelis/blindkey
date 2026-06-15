//! `vault-gui` — a simple, fast, secure desktop window app over `vault-core` (UC-18 P2).
//!
//! A thin GUI shell: it unlocks (or creates) the vault via `vault_core`, then lets you
//!   • **drop a `keys.txt`** (or pick one) → review masked → import securely,
//!   • **type to search** your entries,
//!   • **copy** a password to the clipboard *model-blind* (the secret is shown shadowed, never
//!     rendered; the clipboard auto-clears — C13/C27),
//!   • **add / edit / change / delete** entries.
//!
//! Every byte that touches a secret stays inside `vault-core`; this binary only renders metadata,
//! orchestrates clipboard delivery, and persists through the core's atomic save path.

#![forbid(unsafe_code)]

mod clip;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui;
use vault_core::format::entry::{CustomValue, Entry, Protected};
use vault_core::gen::{password as gen_password, Charset};
use vault_core::Vault;
use zeroize::{Zeroize, Zeroizing};

/// Seconds before the clipboard auto-clears after a copy (C13).
const CLIPBOARD_TIMEOUT_SECS: u64 = 30;
/// Length of a generated password (alphanumeric, ~119 bits at 20 chars).
const GENERATED_LEN: usize = 20;

fn main() -> eframe::Result<()> {
    vault_core::memory::harden_process(); // C25: disable core dumps before touching secrets

    let path = match default_vault_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vault-gui: {e}");
            std::process::exit(1);
        }
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([640.0, 440.0])
            .with_title("Vault"),
        ..Default::default()
    };

    eframe::run_native(
        "Vault",
        options,
        Box::new(move |_cc| Ok(Box::new(VaultApp::new(path)))),
    )
}

// ─── application state ───────────────────────────────────────────────────────

/// In-progress add/edit form. Its password buffer is zeroized on drop.
struct Editor {
    /// `Some(old_title)` when editing an existing entry; `None` when adding a new one.
    original_title: Option<String>,
    title: String,
    username: String,
    url: String,
    notes: String,
    password: String,
    show_password: bool,
    confirm_delete: bool,
    error: Option<String>,
}

impl Editor {
    fn new_add() -> Self {
        Editor {
            original_title: None,
            title: String::new(),
            username: String::new(),
            url: String::new(),
            notes: String::new(),
            password: String::new(),
            show_password: false,
            confirm_delete: false,
            error: None,
        }
    }
}

impl Drop for Editor {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Parsed import awaiting the user's confirmation.
struct ImportReview {
    entries: Vec<Entry>,
    skipped: usize,
}

/// Actions collected while rendering (so click handlers don't fight the borrow checker over the
/// open vault). Processed once per frame after the panels close.
enum Action {
    Lock,
    Add,
    ChooseImport,
    ToggleReveal,
    CopyPassword(usize),
    CopyUsername(usize),
    Edit(usize),
}

struct VaultApp {
    path: PathBuf,
    vault: Option<Vault>,
    /// Whether a vault file exists on disk (create-new vs. unlock).
    vault_exists: bool,

    // locked screen
    pw_input: String,
    pw_confirm: String,
    focus_password: bool,

    // main screen
    query: String,
    selected: Option<usize>,
    reveal: bool,
    focus_search: bool,

    // overlays
    editor: Option<Editor>,
    import_review: Option<ImportReview>,

    status: String,
    error: Option<String>,
}

impl VaultApp {
    fn new(path: PathBuf) -> Self {
        let vault_exists = path.exists();
        VaultApp {
            path,
            vault: None,
            vault_exists,
            pw_input: String::new(),
            pw_confirm: String::new(),
            focus_password: true,
            query: String::new(),
            selected: None,
            reveal: false,
            focus_search: false,
            editor: None,
            import_review: None,
            status: String::new(),
            error: None,
        }
    }

    // ─── lock / unlock / create ─────────────────────────────────────────────

    fn try_unlock(&mut self) {
        self.error = None;
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(_) => {
                self.error = Some(format!("No vault at {}.", self.path.display()));
                return;
            }
        };
        match Vault::open(&bytes, self.pw_input.as_bytes()) {
            Ok(v) => {
                let weak = matches!(
                    v.kdf_strength(),
                    vault_core::crypto::KdfStrength::BelowFloor
                );
                self.vault = Some(v);
                self.pw_input.zeroize();
                self.pw_confirm.zeroize();
                self.focus_search = true;
                self.status = if weak {
                    "Unlocked — note: this vault's KDF is below the recommended floor.".into()
                } else {
                    "Unlocked.".into()
                };
            }
            Err(e) => {
                self.pw_input.zeroize();
                self.error = Some(match e {
                    vault_core::Error::HeaderAuth => "Incorrect master password.".to_string(),
                    other => other.to_string(),
                });
            }
        }
    }

    fn try_create(&mut self) {
        self.error = None;
        if self.pw_input.is_empty() {
            self.error = Some("Choose a master password.".into());
            return;
        }
        if self.pw_input != self.pw_confirm {
            self.error = Some("Passwords do not match.".into());
            return;
        }
        // Argon2id at the recommended cost runs briefly on this thread (one-time).
        let mut v = match Vault::create_default(self.pw_input.as_bytes()) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        let bytes = match v.save() {
            Ok(b) => b,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        if let Err(e) = write_vault(&self.path, &bytes) {
            self.error = Some(e);
            return;
        }
        self.vault = Some(v);
        self.vault_exists = true;
        self.pw_input.zeroize();
        self.pw_confirm.zeroize();
        self.focus_search = true;
        self.status = "Vault created. Drop a keys.txt or add an entry to get started.".into();
    }

    fn lock(&mut self) {
        self.vault = None;
        self.selected = None;
        self.reveal = false;
        self.query.clear();
        self.editor = None;
        self.import_review = None;
        self.error = None;
        self.status.clear();
        self.focus_password = true;
    }

    /// Save the open vault to disk through the core's body-writing save (atomic, 0600).
    fn persist(&mut self) -> Result<(), String> {
        let vault = self.vault.as_mut().ok_or("vault is locked")?;
        let bytes = vault.save().map_err(|e| e.to_string())?;
        write_vault(&self.path, &bytes)
    }

    // ─── entry actions ──────────────────────────────────────────────────────

    fn copy_password(&mut self, idx: usize) {
        let (title, secret) = {
            let Some(e) = self.vault.as_ref().and_then(|v| v.entries().get(idx)) else {
                return;
            };
            (e.title.clone(), e.password.expose())
        };
        match clip::copy(&secret) {
            Ok(()) => {
                clip::schedule_clear(secret, CLIPBOARD_TIMEOUT_SECS);
                self.status = format!(
                    "Copied {}'s password — clipboard clears in {CLIPBOARD_TIMEOUT_SECS}s.",
                    one_line(&title)
                );
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn copy_username(&mut self, idx: usize) {
        let user = self
            .vault
            .as_ref()
            .and_then(|v| v.entries().get(idx))
            .map(|e| e.username.clone());
        if let Some(user) = user {
            if user.is_empty() {
                self.status = "That entry has no username.".into();
            } else if let Err(e) = clip::copy(user.as_bytes()) {
                self.error = Some(e);
            } else {
                self.status = "Copied username to the clipboard.".into();
            }
        }
    }

    fn begin_edit(&mut self, idx: usize) {
        if let Some(e) = self.vault.as_ref().and_then(|v| v.entries().get(idx)) {
            self.editor = Some(Editor {
                original_title: Some(e.title.clone()),
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.url.clone(),
                notes: e.notes.clone(),
                password: String::new(),
                show_password: false,
                confirm_delete: false,
                error: None,
            });
        }
    }

    fn commit_editor(&mut self) {
        // Snapshot the form first, so we don't hold a borrow of `self.editor` while we mutate the
        // vault (both are fields of `self`).
        let (original, title, username, url, notes, password) = {
            let Some(ed) = self.editor.as_ref() else {
                return;
            };
            (
                ed.original_title.clone(),
                ed.title.trim().to_string(),
                ed.username.trim().to_string(),
                ed.url.trim().to_string(),
                ed.notes.clone(),
                Zeroizing::new(ed.password.clone()),
            )
        };
        if title.is_empty() {
            if let Some(ed) = self.editor.as_mut() {
                ed.error = Some("Title is required.".into());
            }
            return;
        }

        let now = now_unix();
        let result: Result<(), String> = (|| {
            let vault = self.vault.as_mut().ok_or("vault is locked")?;
            match &original {
                None => {
                    if vault.get(&title).is_some() {
                        return Err("An entry with that title already exists.".into());
                    }
                    let secret: Zeroizing<Vec<u8>> = if password.is_empty() {
                        let p = gen_password(Charset::Alnum, GENERATED_LEN)
                            .map_err(|e| e.to_string())?;
                        Zeroizing::new(p.as_bytes().to_vec())
                    } else {
                        Zeroizing::new(password.as_bytes().to_vec())
                    };
                    vault.add_entry(Entry {
                        id: random_id(),
                        title: title.clone(),
                        username,
                        password: Protected::new(secret.to_vec()),
                        url,
                        notes,
                        tags: Vec::new(),
                        otp_secret: None,
                        created_at: now,
                        modified_at: now,
                        expires_at: None,
                        custom_fields: Vec::new(),
                    });
                }
                Some(old) => {
                    let e = vault.entry_mut(old).ok_or("That entry no longer exists.")?;
                    e.title = title.clone();
                    e.username = username;
                    e.url = url;
                    e.notes = notes;
                    if !password.is_empty() {
                        e.password = Protected::new(password.as_bytes().to_vec());
                    }
                    e.modified_at = now;
                }
            }
            Ok(())
        })();

        if let Err(msg) = result {
            if let Some(ed) = self.editor.as_mut() {
                ed.error = Some(msg);
            }
            return;
        }
        if let Err(e) = self.persist() {
            self.error = Some(e);
            return;
        }
        self.status = format!("Saved {}.", one_line(&title));
        self.editor = None;
        self.select_by_title(&title);
    }

    fn delete_from_editor(&mut self) {
        let Some(title) = self.editor.as_ref().and_then(|e| e.original_title.clone()) else {
            return;
        };
        if let Some(v) = self.vault.as_mut() {
            v.remove(&title);
        }
        if let Err(e) = self.persist() {
            self.error = Some(e);
            return;
        }
        self.selected = None;
        self.reveal = false;
        self.editor = None;
        self.status = format!("Deleted {}.", one_line(&title));
    }

    fn select_by_title(&mut self, title: &str) {
        let t = title.to_lowercase();
        self.selected = self
            .vault
            .as_ref()
            .and_then(|v| v.entries().iter().position(|e| e.title.to_lowercase() == t));
        self.reveal = false;
    }

    // ─── import ─────────────────────────────────────────────────────────────

    fn choose_and_load_import(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("text files", &["txt", "text", "env", "csv", "log"])
            .add_filter("all files", &["*"])
            .set_title("Choose a keys.txt to import")
            .pick_file()
        {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let text = Zeroizing::new(text);
                    self.load_import(&text);
                }
                Err(e) => self.error = Some(format!("Cannot read {}: {e}", path.display())),
            }
        }
    }

    fn load_import(&mut self, text: &str) {
        let r = vault_core::import::parse_raw(text);
        if r.entries.is_empty() {
            self.error = Some("No secrets found in that file.".into());
        } else {
            self.error = None;
            self.import_review = Some(ImportReview {
                entries: r.entries,
                skipped: r.blocks_skipped,
            });
        }
    }

    fn commit_import(&mut self) {
        let Some(review) = self.import_review.take() else {
            return;
        };
        let n = review.entries.len();
        if let Some(vault) = self.vault.as_mut() {
            for e in review.entries {
                vault.add_entry(e);
            }
        }
        if let Err(e) = self.persist() {
            self.error = Some(e);
            return;
        }
        self.status = format!("Imported {n} entries — saved.");
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        let Some(file) = dropped
            .into_iter()
            .find(|f| f.path.is_some() || f.bytes.is_some())
        else {
            return;
        };
        let text: Option<Zeroizing<String>> = if let Some(path) = &file.path {
            std::fs::read_to_string(path).ok().map(Zeroizing::new)
        } else {
            file.bytes
                .as_ref()
                .map(|b| Zeroizing::new(String::from_utf8_lossy(b).into_owned()))
        };
        match text {
            Some(text) => self.load_import(&text),
            None => self.error = Some("Couldn't read the dropped file as text.".into()),
        }
    }

    // ─── rendering ──────────────────────────────────────────────────────────

    fn locked_screen(&mut self, ctx: &egui::Context) {
        let creating = !self.vault_exists;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(60.0);
            ui.vertical_centered(|ui| {
                ui.heading("🔒  Vault");
                ui.add_space(4.0);
                ui.label(if creating {
                    "Create your vault — choose a master password you won't forget."
                } else {
                    "Enter your master password to unlock."
                });
                ui.add_space(20.0);

                let mut submit = false;
                let pw = ui.add(
                    egui::TextEdit::singleline(&mut self.pw_input)
                        .password(true)
                        .hint_text("Master password")
                        .desired_width(320.0),
                );
                if self.focus_password {
                    pw.request_focus();
                    self.focus_password = false;
                }
                if pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = true;
                }

                if creating {
                    ui.add_space(6.0);
                    let cf = ui.add(
                        egui::TextEdit::singleline(&mut self.pw_confirm)
                            .password(true)
                            .hint_text("Confirm password")
                            .desired_width(320.0),
                    );
                    if cf.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit = true;
                    }
                }

                ui.add_space(14.0);
                if ui
                    .add_sized(
                        [320.0, 30.0],
                        egui::Button::new(if creating { "Create vault" } else { "Unlock" }),
                    )
                    .clicked()
                {
                    submit = true;
                }

                if let Some(err) = &self.error {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
                }

                if submit {
                    if creating {
                        self.try_create();
                    } else {
                        self.try_unlock();
                    }
                }
            });
        });
    }

    fn unlocked_screen(&mut self, ctx: &egui::Context) {
        let mut action: Option<Action> = None;

        // Precompute the filtered list (owned) so the list closure doesn't borrow the vault.
        let (items, total): (Vec<(usize, String)>, usize) = {
            let vault = self.vault.as_ref().expect("unlocked");
            let q = self.query.to_lowercase();
            let items = vault
                .entries()
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    q.is_empty()
                        || e.title.to_lowercase().contains(&q)
                        || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
                })
                .map(|(i, e)| (i, one_line(&e.title)))
                .collect();
            (items, vault.entries().len())
        };

        // Top bar: search + actions + status.
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("Vault");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Lock").clicked() {
                        action = Some(Action::Lock);
                    }
                    if ui.button("Import keys.txt").clicked() {
                        action = Some(Action::ChooseImport);
                    }
                    if ui.button("➕ Add").clicked() {
                        action = Some(Action::Add);
                    }
                });
            });
            ui.add_space(2.0);
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text("🔎  Type to search by title or tag…")
                    .desired_width(f32::INFINITY),
            );
            if self.focus_search {
                search.request_focus();
                self.focus_search = false;
            }
            ui.add_space(4.0);
        });

        // Bottom status bar.
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(2.0);
            if let Some(err) = &self.error {
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
            } else if !self.status.is_empty() {
                ui.label(&self.status);
            } else {
                ui.label(format!(
                    "{total} entries · drop a keys.txt anywhere to import"
                ));
            }
            ui.add_space(2.0);
        });

        // Left: entry list.
        egui::SidePanel::left("entries")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.label(format!("{} / {} shown", items.len(), total));
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if items.is_empty() {
                            ui.weak("No matching entries.");
                        }
                        for (idx, title) in &items {
                            let selected = self.selected == Some(*idx);
                            if ui.selectable_label(selected, title).clicked() {
                                self.selected = Some(*idx);
                                self.reveal = false;
                            }
                        }
                    });
            });

        // Right: detail of the selected entry.
        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(idx) = self.selected.filter(|&i| i < total) else {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.weak("Select an entry to view it, or drop a keys.txt to import.");
                });
                return;
            };
            // Read the selected entry's display fields (no secret rendered unless `reveal`).
            let vault = self.vault.as_ref().expect("unlocked");
            let e = &vault.entries()[idx];
            let title = one_line(&e.title);
            let username = e.username.clone();
            let url = e.url.clone();
            let notes = e.notes.clone();
            let pw_shadow: String = if self.reveal {
                String::from_utf8_lossy(&e.password.expose()).into_owned()
            } else {
                "•".repeat(10)
            };
            let protected_fields: Vec<String> = e
                .custom_fields
                .iter()
                .filter(|f| matches!(f.value, CustomValue::Protected(_)))
                .map(|f| one_line(&f.name))
                .collect();

            ui.add_space(6.0);
            ui.heading(&title);
            ui.add_space(8.0);

            egui::Grid::new("detail")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Username");
                    ui.horizontal(|ui| {
                        ui.monospace(if username.is_empty() {
                            "—".to_string()
                        } else {
                            one_line(&username)
                        });
                        if !username.is_empty() && ui.small_button("Copy").clicked() {
                            action = Some(Action::CopyUsername(idx));
                        }
                    });
                    ui.end_row();

                    ui.label("URL");
                    ui.monospace(if url.is_empty() {
                        "—".into()
                    } else {
                        one_line(&url)
                    });
                    ui.end_row();

                    ui.label("Password");
                    ui.horizontal(|ui| {
                        ui.monospace(&pw_shadow);
                        if ui.button("📋 Copy").clicked() {
                            action = Some(Action::CopyPassword(idx));
                        }
                        let reveal_label = if self.reveal { "Hide" } else { "Reveal" };
                        if ui.button(reveal_label).clicked() {
                            action = Some(Action::ToggleReveal);
                        }
                    });
                    ui.end_row();
                });

            if !notes.is_empty() {
                ui.add_space(8.0);
                ui.label("Notes");
                ui.group(|ui| {
                    ui.label(&notes);
                });
            }
            if !protected_fields.is_empty() {
                ui.add_space(8.0);
                ui.weak(format!(
                    "Also has protected fields: {}",
                    protected_fields.join(", ")
                ));
            }

            ui.add_space(14.0);
            if ui.button("✏  Edit / change password").clicked() {
                action = Some(Action::Edit(idx));
            }
        });

        if let Some(a) = action {
            match a {
                Action::Lock => self.lock(),
                Action::Add => self.editor = Some(Editor::new_add()),
                Action::ChooseImport => self.choose_and_load_import(),
                Action::ToggleReveal => self.reveal = !self.reveal,
                Action::CopyPassword(i) => self.copy_password(i),
                Action::CopyUsername(i) => self.copy_username(i),
                Action::Edit(i) => self.begin_edit(i),
            }
        }
    }

    fn editor_window(&mut self, ctx: &egui::Context) {
        let mut commit = false;
        let mut cancel = false;
        let mut generate = false;
        let mut delete = false;

        if let Some(ed) = self.editor.as_mut() {
            let editing = ed.original_title.is_some();
            egui::Window::new(if editing { "Edit entry" } else { "Add entry" })
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    egui::Grid::new("editor")
                        .num_columns(2)
                        .spacing([10.0, 8.0])
                        .show(ui, |ui| {
                            ui.label("Title");
                            ui.add(egui::TextEdit::singleline(&mut ed.title).desired_width(280.0));
                            ui.end_row();

                            ui.label("Username");
                            ui.add(
                                egui::TextEdit::singleline(&mut ed.username).desired_width(280.0),
                            );
                            ui.end_row();

                            ui.label("URL");
                            ui.add(egui::TextEdit::singleline(&mut ed.url).desired_width(280.0));
                            ui.end_row();

                            ui.label("Password");
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut ed.password)
                                        .password(!ed.show_password)
                                        .desired_width(190.0)
                                        .hint_text(if editing {
                                            "(unchanged)"
                                        } else {
                                            "(blank = generate)"
                                        }),
                                );
                                ui.checkbox(&mut ed.show_password, "show");
                            });
                            ui.end_row();

                            ui.label("");
                            if ui.button("🎲 Generate strong password").clicked() {
                                generate = true;
                            }
                            ui.end_row();

                            ui.label("Notes");
                            ui.add(
                                egui::TextEdit::multiline(&mut ed.notes)
                                    .desired_width(280.0)
                                    .desired_rows(2),
                            );
                            ui.end_row();
                        });

                    if let Some(err) = &ed.error {
                        ui.add_space(4.0);
                        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            commit = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                        if editing {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if !ed.confirm_delete {
                                        if ui.button("🗑 Delete").clicked() {
                                            ed.confirm_delete = true;
                                        }
                                    } else if ui
                                        .button("Confirm delete — this can't be undone")
                                        .clicked()
                                    {
                                        delete = true;
                                    }
                                },
                            );
                        }
                    });
                });
        }

        if generate {
            if let Some(ed) = self.editor.as_mut() {
                if let Ok(p) = gen_password(Charset::Alnum, GENERATED_LEN) {
                    ed.password.zeroize();
                    ed.password = p.to_string();
                    ed.show_password = true;
                }
            }
        }
        if commit {
            self.commit_editor();
        }
        if cancel {
            self.editor = None;
        }
        if delete {
            self.delete_from_editor();
        }
    }

    fn import_window(&mut self, ctx: &egui::Context) {
        let mut do_import = false;
        let mut cancel = false;

        if let Some(review) = self.import_review.as_ref() {
            let n = review.entries.len();
            egui::Window::new("Import keys.txt")
                .collapsible(false)
                .resizable(true)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .default_width(460.0)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Found {n} entr{} ({} block{} skipped). Secrets are masked:",
                        if n == 1 { "y" } else { "ies" },
                        review.skipped,
                        if review.skipped == 1 { "" } else { "s" },
                    ));
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .max_height(300.0)
                        .show(ui, |ui| {
                            egui::Grid::new("import_grid")
                                .num_columns(2)
                                .striped(true)
                                .spacing([16.0, 4.0])
                                .show(ui, |ui| {
                                    for e in &review.entries {
                                        ui.label(one_line(&e.title));
                                        ui.monospace(mask(&e.password.expose()));
                                        ui.end_row();
                                    }
                                });
                        });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(format!("Import {n} entries")).clicked() {
                            do_import = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
        }

        if do_import {
            self.commit_import();
        }
        if cancel {
            self.import_review = None;
        }
    }
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.vault.is_some() {
            self.handle_dropped_files(ctx);
            self.unlocked_screen(ctx);
            self.editor_window(ctx);
            self.import_window(ctx);
        } else {
            self.locked_screen(ctx);
        }
    }
}

// ─── free helpers ────────────────────────────────────────────────────────────

fn default_vault_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or("cannot determine your home directory")?;
    Ok(PathBuf::from(home).join(".vault").join("vault.vlt"))
}

/// Atomic write: temp file (0600 on Unix) in the same dir → fsync → rename over the target.
fn write_vault(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
    }
    let tmp = path.with_extension("vlt.tmp");
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

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    // Same audited OS CSPRNG vault-core uses; on the (astronomically unlikely) failure path the id
    // stays zero, which only affects entry identity, never secret confidentiality.
    let _ = getrandom::getrandom(&mut id);
    id
}

/// Collapse control characters to spaces for single-line display (defense-in-depth for GUI labels).
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Mask a secret for review: first/last 4 chars + length, never the middle.
fn mask(secret: &[u8]) -> String {
    let s = String::from_utf8_lossy(secret);
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= 8 {
        format!("{} ({n})", "•".repeat(n))
    } else {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[n - 4..].iter().collect();
        format!("{head}…{tail} ({n})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_hides_the_middle() {
        assert_eq!(mask(b"short"), "••••• (5)");
        let m = mask(b"ghp_FAKE0mZ9xQ2vL7nR4tW8");
        assert!(m.starts_with("ghp_"));
        assert!(m.ends_with("(24)"));
        assert!(!m.contains("0mZ9")); // middle never shown
    }

    #[test]
    fn one_line_strips_control_chars() {
        assert_eq!(one_line("a\nb\tc\x1b[31m"), "a b c [31m");
    }

    #[test]
    fn random_id_is_nonzero_and_varies() {
        let a = random_id();
        let b = random_id();
        assert_ne!(a, [0u8; 16]);
        assert_ne!(a, b);
    }
}
