//! UC-27 craft constraint tests (C82–C87) — static + wiring checks.

use std::path::PathBuf;

fn read_gui_src(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// T1 / C82 — fixed-width left-aligned unlock card.
#[test]
fn c82_form_width_card() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("FORM_WIDTH: f32 = 420.0") || theme.contains("FORM_WIDTH: f32 = 420"));
    assert!(theme.contains("fn form_card"));
    assert!(main.contains("theme::form_card"));
    assert!(main.contains("set_max_width(FORM_WIDTH)") || theme.contains("set_max_width(FORM_WIDTH)"));
    // Locked form must not nest passphrase horizontal as sole child of vertical_centered without form_card.
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    assert!(
        locked.contains("form_card"),
        "locked_screen must use form_card (CRAFT-01)"
    );
}

/// T2 / C83 — accent-filled Create/Unlock/Add.
#[test]
fn c83_accent_primaries() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    let vol = read_gui_src("volume_gui.rs");
    assert!(theme.contains("fn primary_button"));
    assert!(theme.contains(".fill(ACCENT)") || theme.contains("fill(ACCENT)"));
    assert!(main.contains("theme::primary_button"));
    assert!(
        vol.contains("primary_button"),
        "Workspace Create/Unlock must use primary_button"
    );
}

/// T3 / C84 — craft Spacing at startup.
#[test]
fn c84_craft_spacing_startup() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn apply_craft_style"));
    assert!(theme.contains("text_edit_width = FORM_WIDTH"));
    assert!(theme.contains("interact_size.y = PRIMARY_BTN_HEIGHT"));
    assert!(theme.contains("item_spacing"));
    assert!(main.contains("apply_craft_style"));
}

/// T4 / C85 — non-redundant trust copy; hint ≠ label.
#[test]
fn c85_trust_copy_and_hints() {
    let main = read_gui_src("main.rs");
    let theme = read_gui_src("theme.rs");
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    let trust_hits = locked.matches("No account. No cloud.").count();
    assert!(
        trust_hits <= 1,
        "locked screen must not duplicate 'No account. No cloud.' (got {trust_hits})"
    );
    assert!(
        !theme.contains("hint_text(\"Master password\")"),
        "hint must not echo Master password label"
    );
    assert!(
        !main.contains("hint_text(\"Master password\")"),
        "hint must not echo Master password label"
    );
    assert!(theme.contains("hint_text(\"••••••••\")") || theme.contains("hint_text(\"••••"));
}

/// CRAFT-06 — first-run strip does not compete with form Create primary.
#[test]
fn craft06_first_run_or_form_primary() {
    let main = read_gui_src("main.rs");
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    assert!(
        locked.contains("if first_run") && locked.contains("} else {"),
        "first_run must gate the form primary (CRAFT-06)"
    );
    // Form primary lives in the else branch only.
    let else_idx = locked.find("} else {").expect("else after first_run");
    let after_else = &locked[else_idx..];
    assert!(
        after_else.contains("primary_button"),
        "accent Create/Unlock must be in the non-first_run branch"
    );
}

/// T5 / C86 — TextEdit chrome contrasts panel.
#[test]
fn c86_field_chrome_contrasts() {
    let theme = read_gui_src("theme.rs");
    assert!(theme.contains("AA_FIELD_BG"));
    assert!(theme.contains("AA_FIELD_STROKE") || theme.contains("bg_stroke"));
    assert!(theme.contains("extreme_bg_color = AA_FIELD_BG"));
    assert!(
        !theme.lines().any(|l| {
            let t = l.trim();
            t.starts_with("v.") && t.contains("text_edit_bg_color")
        }),
        "must not set Visuals.text_edit_bg_color (not on egui 0.29.1)"
    );
    assert!(
        !theme.lines().any(|l| {
            let t = l.trim();
            t.starts_with("v.") && t.contains("weak_text_alpha")
        }),
        "must not set Visuals.weak_text_alpha (not on egui 0.29.1)"
    );
}

/// CRAFT-08 — volume/seal dialogs share unlock passphrase helpers.
#[test]
fn craft08_dialog_passphrase_helpers() {
    let vol = read_gui_src("volume_gui.rs");
    let sealed = read_gui_src("sealed_gui.rs");
    assert!(vol.contains("labeled_secret_row"));
    assert!(vol.contains("labeled_secret_confirm") || vol.contains("Unlock"));
    assert!(sealed.contains("labeled_secret_row"));
    assert!(sealed.contains("labeled_secret_confirm"));
    assert!(
        vol.contains("primary_button") && sealed.contains("primary_button"),
        "dialog primaries must use theme::primary_button"
    );
}

/// CRAFT-12 — Workspace home uses SPACE_* + accent Create/Unlock.
#[test]
fn craft12_workspace_home_tokens() {
    let vol = read_gui_src("volume_gui.rs");
    let home = vol
        .split("fn workspace_home")
        .nth(1)
        .and_then(|s| s.split("pub fn windows").next())
        .expect("workspace_home");
    assert!(home.contains("SPACE_"));
    assert!(home.contains("primary_button"));
    assert!(home.contains("Create volume") && home.contains("Unlock"));
}

/// Confirm field width matches master TextEdit column (CRAFT-02).
#[test]
fn craft02_confirm_matches_secret_field_width() {
    let theme = read_gui_src("theme.rs");
    assert!(
        theme.contains("desired_width(secret_field_width())"),
        "labeled_secret_confirm must use secret_field_width (CRAFT-02)"
    );
}

/// CRAFT-16 — Danger on Delete; Accent on editor Save (§4.3).
#[test]
fn craft16_accent_danger_roles() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn danger_button") && theme.contains("fill(DANGER)"));
    assert!(main.contains("danger_button") && main.contains("Confirm delete"));
    assert!(
        main.contains("fill(theme::ACCENT)") || main.contains(".fill(theme::ACCENT)"),
        "editor Save must use accent fill"
    );
}

/// T6 / C87 — Settings progressive disclosure.
#[test]
fn c87_settings_overflow() {
    let main = read_gui_src("main.rs");
    assert!(main.contains("settings_open") || main.contains("Settings…"));
    assert!(main.contains("fn settings_window"));
    assert!(main.contains("SETTINGS_CONTENT_MAX") || main.contains("theme::SETTINGS_CONTENT_MAX"));
    // Settings hosts the former always-visible toggles.
    let settings = main
        .split("fn settings_window")
        .nth(1)
        .and_then(|s| s.split("fn set_padding").next())
        .expect("settings_window");
    assert!(settings.contains("Pad size"));
    assert!(settings.contains("Auto-lock"));
    assert!(settings.contains("Clipboard"));
    assert!(settings.contains("Lock on blur"));
    // Primary Credentials toolbar must not keep Pad size always visible.
    let unlocked_top = main
        .split("fn unlocked_screen")
        .nth(1)
        .and_then(|s| s.split("fn settings_window").next())
        .expect("unlocked_screen");
    assert!(
        !unlocked_top.contains("checkbox(&mut pad_on, \"Pad size\")"),
        "Pad size must not stay on primary Credentials toolbar"
    );
}
