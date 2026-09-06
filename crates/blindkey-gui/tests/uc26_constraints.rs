//! UC-26 constraint tests (C75–C81) + IA-09–IA-14 regression — static + wiring checks.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("blindkey workspace root")
        .to_path_buf()
}

fn read_workspace_file(rel: &str) -> String {
    std::fs::read_to_string(workspace_root().join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn read_gui_src(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn read_gui_sources() -> String {
    let mut out = String::new();
    for name in [
        "main.rs",
        "volume_gui.rs",
        "theme.rs",
        "gui_mode.rs",
        "gui_config.rs",
        "sealed_gui.rs",
    ] {
        out.push_str(&read_gui_src(name));
        out.push('\n');
    }
    out
}

/// T1 / C75 — embedded fonts when default-features = false.
#[test]
fn c75_default_fonts_enabled() {
    let cargo = read_workspace_file("Cargo.toml");
    let eframe_line = cargo
        .lines()
        .find(|l| l.trim_start().starts_with("eframe"))
        .expect("eframe dependency line");
    for feat in ["glow", "default_fonts", "wayland", "x11"] {
        assert!(
            eframe_line.contains(feat),
            "C75: eframe missing feature {feat}: {eframe_line}"
        );
    }
    assert!(
        !eframe_line.contains("persistence"),
        "persistence must stay off"
    );
}

/// T7 / C76 — lock/mount status chrome present.
#[test]
fn c76_status_chrome_wired() {
    let main = read_gui_src("main.rs");
    let vol = read_gui_src("volume_gui.rs");
    assert!(main.contains("SessionStatus::Locked"));
    assert!(main.contains("SessionStatus::Unlocked") || main.contains("Status:"));
    assert!(main.contains("session_status()"));
    assert!(vol.contains("SessionStatus::Mounted"));
    assert!(vol.contains("Ejected — files locked."));
}

/// T2 / C77 — Credentials | Workspace only; Seal is not a mode.
#[test]
fn c77_two_modes_seal_not_mode() {
    let mode = read_gui_src("gui_mode.rs");
    assert!(mode.contains("Credentials"));
    assert!(mode.contains("Workspace"));
    assert!(
        !mode.contains("Seal,"),
        "Seal must not be a GuiMode variant"
    );
    let main = read_gui_src("main.rs");
    assert!(main.contains("GuiMode::Workspace"));
    assert!(main.contains("workspace_home"));
    assert!(main.contains("Seal files"));
    assert!(
        !main.contains("Button::new(\"Create volume\")"),
        "Create volume must not live on Credentials chrome in main.rs"
    );
    assert!(
        !main.contains("button(\"🗄 Volume\")"),
        "Volume must not be a peer Credentials toolbar button"
    );
    assert!(
        !main.contains("button(\"Mount .vltd\")"),
        "Mount .vltd peer button removed from Credentials chrome"
    );
}

/// T8 / C78 — primary chrome uses human labels (no VLTF/VLTD/Kcom as sole button text).
#[test]
fn c78_human_primary_labels() {
    let src = read_gui_sources();
    for bad in [
        "Button::new(\"VLTF\")",
        "Button::new(\"VLTD\")",
        "Button::new(\"Kcom\")",
        "button(\"VLTF\")",
        "button(\"VLTD\")",
    ] {
        assert!(
            !src.contains(bad),
            "primary chrome must not use crypto token alone: {bad}"
        );
    }
    assert!(src.contains("Credentials") && src.contains("Workspace"));
    assert!(src.contains("Seal files"));
    assert!(
        src.contains("Button::new(\"Unlock\")") || src.contains("primary_button(ui, \"Unlock\""),
        "Unlock primary must exist"
    );
    assert!(src.contains("Button::new(\"Eject\")") || src.contains("\"Eject\""));
}

/// T3 / C79 — validate-only fallback stays honest; Reveal gated on mount_path / MaterializedMount.
#[test]
fn c79_mount_honesty_message() {
    let vol = read_gui_src("volume_gui.rs");
    assert!(vol.contains("unlock_success_message"));
    assert!(vol.contains("unlocked (validated"));
    assert!(vol.contains("MaterializedMount"));
    assert!(vol.contains("mount_folder_success_message") || vol.contains("MOUNTED\\t"));
    assert!(
        vol.contains("Button::new(\"Unlock\")") || vol.contains("primary_button(ui, \"Unlock\""),
        "Unlock CTA must exist"
    );
    assert!(
        vol.contains("macfuse.io") || vol.contains("macos-fuse") || vol.contains("macFUSE"),
        "macOS unlock honesty must name macFUSE / macos-fuse"
    );
    assert!(vol.contains("mount_path.is_some()") || vol.contains("can_reveal"));
}

/// T9 / C80 — Advanced disclosure on volume create/unlock.
#[test]
fn c80_progressive_disclosure_advanced() {
    let vol = read_gui_src("volume_gui.rs");
    assert!(vol.contains("collapsing(\"Advanced…\""));
    assert!(vol.contains("size_mib") || vol.contains("Keyfile"));
    // Create / Unlock primaries exist outside Advanced (usable when collapsed).
    assert!(
        vol.contains("Button::new(\"Create\")")
            || vol.contains("Button::new(\"Create volume\")")
            || vol.contains("primary_button(ui, \"Create")
            || vol.contains("primary_button(ui, \"Create volume\"")
    );
    assert!(
        vol.contains("Button::new(\"Unlock\")") || vol.contains("primary_button(ui, \"Unlock\"")
    );
}

/// T10 / C81 — AA theme constants + primary button height ≥ 24.
#[test]
fn c81_aa_theme_documented() {
    let theme = read_gui_src("theme.rs");
    assert!(theme.contains("AA_FG"));
    assert!(theme.contains("AA_BG"));
    assert!(theme.contains("PRIMARY_BTN_HEIGHT"));
    assert!(theme.contains("apply_aa_visuals") || theme.contains("apply_craft_style"));
    assert!(theme.contains(">= 24.0") || theme.contains("24 CSS"));
    let main = read_gui_src("main.rs");
    let vol = read_gui_src("volume_gui.rs");
    assert!(
        main.contains("PRIMARY_BTN_HEIGHT") || main.contains("primary_button"),
        "primary CTAs must use PRIMARY_BTN_HEIGHT / primary_button in credentials"
    );
    assert!(
        vol.contains("PRIMARY_BTN_HEIGHT"),
        "primary CTAs must use PRIMARY_BTN_HEIGHT in workspace"
    );
}

/// T11 / IA-09 — paste enabled + show/hide on vault/volume/seal passphrase fields.
#[test]
fn ia09_show_hide_passphrase() {
    let main = read_gui_src("main.rs");
    let theme = read_gui_src("theme.rs");
    let vol = read_gui_src("volume_gui.rs");
    let sealed = read_gui_src("sealed_gui.rs");
    assert!(
        theme.contains("\"Show\"")
            || theme.contains("checkbox(show, \"Show\")")
            || main.contains("checkbox(&mut self.show_master_pw, \"Show\")"),
        "vault unlock must offer Show"
    );
    assert!(
        vol.contains("labeled_secret_row") && sealed.contains("labeled_secret_row"),
        "volume/seal must use craft passphrase rows (Show via theme helper)"
    );
    assert!(
        !main.contains(".interactive(false)")
            && !vol.contains(".interactive(false)")
            && !sealed.contains(".interactive(false)"),
        "must not disable passphrase TextEdit interactivity (paste)"
    );
}

/// T12 / IA-10–13 — local default path, confirm-match microcopy, cancel worker, closures.
#[test]
fn ia10_13_create_defaults_and_closure() {
    let vol = read_gui_src("volume_gui.rs");
    let main = read_gui_src("main.rs");
    let sealed = read_gui_src("sealed_gui.rs");
    assert!(vol.contains("Documents") || vol.contains("blindkey-workspace.vltd"));
    assert!(vol.contains("Passphrases don't match — retype confirm."));
    assert!(main.contains("Passphrases don't match — retype confirm."));
    assert!(sealed.contains("Passphrases don't match — retype confirm."));
    assert!(vol.contains("fn cancel(") || vol.contains(".cancel()"));
    assert!(vol.contains("Volume created:"));
    assert!(main.contains("Entry saved."));
    assert!(vol.contains("Ejected — files locked."));
    assert!(vol.contains("LOCK_ON_SLEEP_NOTE"));
}

/// First-run + next-beat (§5.7).
#[test]
fn first_run_and_next_beat_wired() {
    let main = read_gui_src("main.rs");
    let cfg = read_gui_src("gui_config.rs");
    assert!(main.contains("Blindkey keeps secrets and encrypted folders on this computer."));
    assert!(main.contains("No account. No cloud."));
    assert!(main.contains("Create vault"));
    assert!(main.contains("Open existing…"));
    assert!(main.contains("Next: Add an API key, or open Workspace to create an encrypted folder."));
    assert!(main.contains("Open Workspace"));
    assert!(main.contains("Not now"));
    assert!(cfg.contains("dismissed_first_run"));
    assert!(cfg.contains("dismissed_next_beat"));
}

/// Phase C trust / microcopy / empty state.
#[test]
fn credentials_microcopy_and_empty_state() {
    let main = read_gui_src("main.rs");
    let theme = read_gui_src("theme.rs");
    assert!(
        main.contains("Stored only on this computer.")
            || theme.contains("Stored only on this computer.")
    );
    assert!(main.contains("Local only. No account. No cloud."));
    assert!(main.contains("Vault could not be unlocked. Check passphrase."));
    assert!(main.contains("Copied. Clipboard clears in"));
    assert!(main.contains("choose a strong passphrase. You cannot recover it if forgotten."));
    assert!(main.contains("Import keys.txt"));
    assert!(main.contains("Add entry"));
    assert!(main.contains("Choose vault file…"));
}

/// Phase D Workspace + C73 Seal recovery CTA.
#[test]
fn workspace_and_seal_recovery_wired() {
    let vol = read_gui_src("volume_gui.rs");
    let main = read_gui_src("main.rs");
    assert!(
        vol.contains("Button::new(\"Create volume\")")
            || vol.contains("primary_button(ui, \"Create volume\"")
    );
    assert!(vol.contains("Workspace = edit as a folder"));
    assert!(vol.contains("Live mount of a .vltd on Dropbox/Drive/iCloud/Syncthing is unsupported"));
    assert!(vol.contains("Open Blindfolder") || vol.contains("Seal files"));
    assert!(vol.contains("take_seal_request") || vol.contains("seal_request"));
    assert!(vol.contains("sync_refuse_cta"));
    assert!(main.contains("take_seal_request"));
}

/// INSTALL documents default_fonts fallback note (Phase A optional).
#[test]
fn install_documents_fonts() {
    let install = read_workspace_file("docs/INSTALL.md");
    assert!(
        install.contains("default_fonts"),
        "INSTALL.md should document default_fonts / blank-glyph note"
    );
}
