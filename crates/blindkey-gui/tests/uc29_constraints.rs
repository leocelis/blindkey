//! UC-29 contrast / typography / polarity constraint tests (C94–C98).

use std::path::PathBuf;

fn read_gui_src(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// T1 / C94 — force Dark theme preference; apply visuals via `set_visuals_of(Theme::Dark, …)`.
#[test]
fn c94_force_dark_theme() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    assert!(
        theme.contains("ThemePreference::Dark"),
        "must force ThemePreference::Dark (C94)"
    );
    assert!(
        theme.contains("set_theme(ThemePreference::Dark)"),
        "apply_craft_style must call set_theme(Dark)"
    );
    assert!(
        theme.contains("set_visuals_of(Theme::Dark"),
        "must use set_visuals_of(Theme::Dark, …) not only set_visuals"
    );
    assert!(
        theme.contains("style_mut_of(Theme::Dark"),
        "spacing/text_styles must land on Dark style"
    );
    assert!(
        theme.contains("fn ensure_dark_polarity"),
        "must re-assert Dark if preference drifts (research §4)"
    );
    assert!(
        main.contains("ensure_dark_polarity"),
        "App::update must call ensure_dark_polarity"
    );
    assert!(
        !theme.contains("set_theme(ThemePreference::System)")
            && !theme.contains("ThemePreference::System)"),
        "must not call set_theme with System (Light polarity collision)"
    );
}

/// T2 / C95 — NIST-aligned type scale constants wired into Dark text_styles.
#[test]
fn c95_type_scale_nist() {
    let theme = read_gui_src("theme.rs");
    assert!(theme.contains("FONT_SMALL: f32 = 13.0") || theme.contains("FONT_SMALL = 13.0"));
    assert!(theme.contains("FONT_BODY: f32 = 16.0") || theme.contains("FONT_BODY = 16.0"));
    assert!(theme.contains("FONT_BUTTON: f32 = 16.0") || theme.contains("FONT_BUTTON = 16.0"));
    assert!(theme.contains("FONT_HEADING: f32 = 24.0") || theme.contains("FONT_HEADING = 24.0"));
    assert!(theme.contains("FONT_MONO: f32 = 14.0") || theme.contains("FONT_MONO = 14.0"));
    assert!(theme.contains("TextStyle::Small"));
    assert!(theme.contains("TextStyle::Button"));
    assert!(theme.contains("TextStyle::Monospace"));
    assert!(theme.contains("FONT_SMALL"));
    assert!(theme.contains("FONT_BODY"));
    assert!(theme.contains("FONT_HEADING"));
    assert!(
        theme.contains("item_spacing = Vec2::new(SPACE_S, SPACE_M)")
            || theme.contains("Vec2::new(SPACE_S, SPACE_M)"),
        "widget item_spacing must stay modest (BK-UI-011: line-height ≠ widget gap)"
    );
    assert!(
        theme.contains("BODY_LINE_HEIGHT") && theme.contains("fn body_copy"),
        "wrapped body copy must use explicit line-height, not item_spacing"
    );
    assert!(
        theme.contains("item_spacing.y = SPACE_XS") || theme.contains("item_spacing.y = SPACE_XS;"),
        "label→field in passphrase helpers must be tight (SPACE_XS)"
    );
}

/// T3 / C96 — muted caption token + helpers use AA_MUTED; no shell `ui.weak()`.
#[test]
fn c96_muted_contrast() {
    let theme = read_gui_src("theme.rs");
    let main = read_gui_src("main.rs");
    let vol = read_gui_src("volume_gui.rs");
    assert!(theme.contains("AA_MUTED"), "AA_MUTED token required (C96)");
    assert!(
        theme.contains("from_rgb(140, 140, 148)") || theme.contains("from_rgb(140,140,148)"),
        "AA_MUTED seed RGB(140,140,148)"
    );
    assert!(theme.contains("fn muted_label"));
    let caption_fn = theme
        .split("pub fn caption(")
        .nth(1)
        .and_then(|s| s.split("pub fn muted_label").next())
        .expect("caption");
    assert!(
        caption_fn.contains("AA_MUTED"),
        "caption() must paint AA_MUTED"
    );
    let caption_code: String = caption_fn
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !caption_code.contains(".weak()"),
        "caption() body must not call .weak()"
    );
    let path_fn = theme
        .split("fn vault_path_caption(")
        .nth(1)
        .and_then(|s| s.split("fn escape_pressed").next())
        .expect("vault_path_caption");
    assert!(
        path_fn.contains("AA_MUTED"),
        "vault_path_caption must use AA_MUTED"
    );
    assert!(
        !main.contains("ui.weak("),
        "main.rs must not use ui.weak (fails ~4.0:1 on AA panels)"
    );
    assert!(
        !vol.contains("ui.weak("),
        "volume_gui.rs must not use ui.weak"
    );
}

/// T4 / C97 — primary button white ink on darkened ACCENT; danger uses dark label.
#[test]
fn c97_primary_white_on_accent() {
    let theme = read_gui_src("theme.rs");
    assert!(
        theme.contains("from_rgb(45, 120, 190)") || theme.contains("from_rgb(45,120,190)"),
        "ACCENT must be darkened for white ≥4.5:1"
    );
    assert!(theme.contains("PRIMARY_LABEL"));
    assert!(theme.contains("DANGER_LABEL"));
    let primary = theme
        .split("fn primary_button(")
        .nth(1)
        .and_then(|s| s.split("fn quiet_button").next())
        .expect("primary_button");
    assert!(
        primary.contains("PRIMARY_LABEL") || primary.contains("Color32::WHITE"),
        "primary_button must set white/PRIMARY_LABEL ink"
    );
    assert!(primary.contains("fill(ACCENT)") || primary.contains(".fill(ACCENT)"));
    let danger = theme
        .split("fn danger_button(")
        .nth(1)
        .and_then(|s| s.split("fn focus_search").next())
        .expect("danger_button");
    assert!(
        danger.contains("DANGER_LABEL"),
        "danger_button must use DANGER_LABEL (white on DANGER fails AA)"
    );
}

/// T5 / C98 — non-text stroke tokens + panel fill AA_BG.
#[test]
fn c98_nontext_strokes() {
    let theme = read_gui_src("theme.rs");
    assert!(
        theme.contains("from_rgb(130, 130, 140)") || theme.contains("from_rgb(130,130,140)"),
        "field/card stroke seed RGB(130,130,140)"
    );
    assert!(theme.contains("AA_FIELD_STROKE"));
    assert!(theme.contains("AA_CARD_STROKE"));
    assert!(
        theme.contains("panel_fill = AA_BG") || theme.contains("panel_fill=AA_BG"),
        "panel_fill must remain AA_BG"
    );
    assert!(
        theme.contains("window_fill = AA_BG") || theme.contains("window_fill=AA_BG"),
        "window_fill must remain AA_BG"
    );
    assert!(
        theme.contains("fn contrast_ratio") || theme.contains("uc29_nontext_stroke_contrast"),
        "contrast helper or unit assert must exist"
    );
}

/// Joint G21 — all C94–C98 wiring present on the same theme surface.
#[test]
fn joint_g21_contrast_kit() {
    c94_force_dark_theme();
    c95_type_scale_nist();
    c96_muted_contrast();
    c97_primary_white_on_accent();
    c98_nontext_strokes();
}
