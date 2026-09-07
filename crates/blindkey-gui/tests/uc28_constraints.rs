//! UC-28 component-kit constraint tests (C88–C93) — static + wiring checks.

use std::path::PathBuf;

fn read_gui_src(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// T1 / C88 — locked unlock/create wrapped in `surface_card` with distinct card fill.
#[test]
fn c88_surface_card_locked() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("AA_CARD_BG"));
    assert!(theme.contains("AA_CARD_STROKE"));
    assert!(theme.contains("fn surface_card"));
    assert!(
        theme.contains("AA_CARD_BG: Color32") || theme.contains("AA_CARD_BG ="),
        "AA_CARD_BG token required"
    );
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    assert!(
        locked.contains("surface_card"),
        "locked_screen must wrap form in surface_card (C88)"
    );
    assert!(
        locked.contains("form_card"),
        "form_card width clamp preserved inside surface"
    );
}

/// T2 / C89 — quiet/text role kit for Cancel, first-run strip, Choose vault file.
#[test]
fn c89_quiet_text_button_kit() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    let vol = read_gui_src("volume_gui.rs");
    let sealed = read_gui_src("sealed_gui.rs");
    assert!(theme.contains("fn quiet_button"));
    assert!(theme.contains("fn text_button"));
    assert!(theme.contains("fill(AA_QUIET_FILL)") || theme.contains(".fill(AA_QUIET_FILL)"));
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    assert!(
        locked.contains("quiet_button") && locked.contains("text_button"),
        "first-run / Choose vault file must use quiet/text (C89)"
    );
    assert!(
        locked.contains("Choose vault file"),
        "tertiary choose path still present"
    );
    assert!(
        vol.contains("quiet_button") && sealed.contains("quiet_button"),
        "volume/seal dialog Cancel must use quiet_button"
    );
}

/// T3 / C90 — Settings boxed-list rows inside card chrome.
#[test]
fn c90_settings_boxed_rows() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn settings_switch_row"));
    assert!(theme.contains("fn settings_value_row"));
    let settings = main
        .split("fn settings_window")
        .nth(1)
        .and_then(|s| s.split("fn set_padding").next())
        .expect("settings_window");
    assert!(settings.contains("surface_card"));
    assert!(settings.contains("settings_switch_row"));
    assert!(settings.contains("settings_value_row"));
    assert!(settings.contains("Pad size"));
    assert!(settings.contains("Auto-lock"));
    assert!(settings.contains("Clipboard"));
    assert!(settings.contains("Lock on blur"));
}

/// T4 / C91 — optical vertical balance on locked CentralPanel.
#[test]
fn c91_locked_vertical_balance() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn locked_vertical_balance_spacer"));
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    assert!(
        locked.contains("locked_vertical_balance_spacer"),
        "locked screen must apply optical balance (C91)"
    );
}

/// T5 / C92 — full-row list hit at medium ROW_HEIGHT_LIST.
#[test]
fn c92_full_row_list_hit() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    let virt = read_gui_src("list_virtualize.rs");
    assert!(theme.contains("ROW_HEIGHT_LIST"));
    assert!(theme.contains("fn list_select_row"));
    assert!(
        main.contains("list_select_row"),
        "credential list must use list_select_row (C92)"
    );
    assert!(
        virt.contains("ENTRY_ROW_HEIGHT: f32 = 28.0")
            || virt.contains("ENTRY_ROW_HEIGHT: f32 = 28"),
        "virtualize row height must match medium density"
    );
}

/// T6 / C93 — Search focus via Cmd/Ctrl+F and `focus_search` helper.
#[test]
fn c93_search_focus_contract() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn focus_search"));
    assert!(main.contains("focus_search"));
    assert!(
        main.contains("Key::F") && main.contains("Key::K"),
        "Cmd/Ctrl+F and Cmd/Ctrl+K must focus Search (C93)"
    );
}

/// CRAFT-S05 — Cancel before Affirm + Escape + dialog_cancel_affirm helper.
#[test]
fn craft_s05_dialog_cancel_before_affirm() {
    let theme = read_gui_src("theme.rs");
    let vol = read_gui_src("volume_gui.rs");
    let sealed = read_gui_src("sealed_gui.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn dialog_cancel_affirm"));
    assert!(theme.contains("fn submit_on_enter"));
    assert!(theme.contains("fn enter_pressed"));
    assert!(vol.contains("escape_pressed") || vol.contains("dialog_cancel_affirm"));
    assert!(sealed.contains("dialog_cancel_affirm") || sealed.contains("escape_pressed"));
    assert!(
        vol.contains("focus_password: true") && sealed.contains("focus_password: true"),
        "volume/seal dialogs must request initial passphrase focus"
    );
    assert!(
        main.contains("focus_title: true") || main.contains("focus_title"),
        "editor must request initial title focus"
    );
    // Editor: Cancel appears before Save in source order within the footer horizontal.
    let editor_footer = main
        .split("CRAFT-S05: Cancel before Affirm")
        .nth(1)
        .and_then(|s| s.split("if editing").next())
        .expect("editor CRAFT-S05 footer");
    let cancel_pos = editor_footer.find("quiet_button").expect("Cancel quiet");
    let save_pos = editor_footer.find("Save").expect("Save");
    assert!(
        cancel_pos < save_pos,
        "Cancel must precede Save in editor footer"
    );
    // Import review: Cancel before Import.
    let import = main
        .split("Found {n} entr")
        .nth(1)
        .and_then(|s| s.split("fn audit_modal").next())
        .expect("import modal");
    let cancel_i = import.find("Cancel").expect("import Cancel");
    let import_i = import
        .find("Import {n}")
        .or_else(|| import.find("Import "))
        .expect("import affirm");
    assert!(cancel_i < import_i, "import Cancel must precede Affirm");
    // Enroll: Cancel before Enroll via dialog_cancel_affirm.
    assert!(
        main.contains("dialog_cancel_affirm(ui, \"Enroll\")"),
        "keyfile enroll must use dialog_cancel_affirm"
    );
}

/// SHADOW_CARD token present and default-off (stroke-first).
#[test]
fn craft_shadow_card_default_off() {
    let theme = read_gui_src("theme.rs");
    assert!(
        theme.contains("SHADOW_CARD_ENABLED: bool = false")
            || theme.contains("SHADOW_CARD_ENABLED = false")
    );
}

/// Dialog primary verbs prefer ≥120 px width.
#[test]
fn craft_s03_dialog_btn_min_width() {
    let theme = read_gui_src("theme.rs");
    assert!(
        theme.contains("PRIMARY_BTN_MIN_WIDTH: f32 = 120.0")
            || theme.contains("PRIMARY_BTN_MIN_WIDTH: f32 = 120")
    );
    assert!(theme.contains("DIALOG_BTN_WIDTH"));
}

/// Forbidden Visuals fields (UC-27/28 pin).
#[test]
fn no_forbidden_visuals_fields() {
    let theme = read_gui_src("theme.rs");
    assert!(!theme.lines().any(|l| {
        let t = l.trim();
        t.starts_with("v.") && t.contains("text_edit_bg_color")
    }));
    assert!(!theme.lines().any(|l| {
        let t = l.trim();
        t.starts_with("v.") && t.contains("weak_text_alpha")
    }));
}

/// ROW_HEIGHT_LIST sync with virtualize constant.
#[test]
fn row_height_tokens_aligned() {
    let theme = read_gui_src("theme.rs");
    let virt = read_gui_src("list_virtualize.rs");
    assert!(
        theme.contains("ROW_HEIGHT_LIST: f32 = 28.0")
            || theme.contains("ROW_HEIGHT_LIST: f32 = 28")
    );
    assert!(
        virt.contains("ENTRY_ROW_HEIGHT: f32 = 28.0")
            || virt.contains("ENTRY_ROW_HEIGHT: f32 = 28")
    );
}
