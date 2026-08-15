//! Brand mark + form-column alignment (logo / CRAFT-02 outer edge).

use std::path::PathBuf;

fn read_gui_src(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn brand_mark_and_chrome_wired() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn brand_mark"));
    assert!(theme.contains("fn brand_hero"));
    assert!(theme.contains("BRAND_MARK_SIZE"));
    assert!(theme.contains("BRAND_MARK_HERO"));
    assert!(
        main.contains("brand_hero"),
        "locked screen must use centered brand_hero"
    );
    assert!(
        main.contains("brand_mark"),
        "unlocked header must show brand_mark"
    );
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    assert!(
        !locked.contains("brand_chrome"),
        "locked must not use left-aligned brand_chrome"
    );
    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/blindkey-mark.png");
    assert!(
        assets.is_file(),
        "assets/blindkey-mark.png must exist for docs/icon reuse"
    );
}

#[test]
fn form_column_aligns_cta_and_fields() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("fn form_column_width"));
    let locked = main
        .split("fn locked_screen")
        .nth(1)
        .and_then(|s| s.split("fn ensure_search_cache").next())
        .expect("locked_screen");
    assert!(
        locked.contains("form_column_width"),
        "Create/Unlock CTA must use form_column_width"
    );
    let confirm = theme
        .split("fn labeled_secret_confirm(")
        .nth(1)
        .and_then(|s| s.split("fn caption(").next())
        .expect("confirm");
    assert!(confirm.contains("form_column_width"));
}

#[test]
fn locked_viewport_fits_form() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(theme.contains("LOCKED_WINDOW_W"));
    assert!(theme.contains("fn sync_viewport_to_shell"));
    assert!(theme.contains("fn fit_locked_viewport_to_content"));
    assert!(main.contains("sync_viewport_to_shell"));
    assert!(main.contains("fit_locked_viewport_to_content"));
    assert!(main.contains("LOCKED_WINDOW_W") || main.contains("theme::LOCKED_WINDOW"));
    assert!(
        !main.contains("with_inner_size([900.0, 620.0])"),
        "boot size must be locked fit, not unlocked 900×620"
    );
}
