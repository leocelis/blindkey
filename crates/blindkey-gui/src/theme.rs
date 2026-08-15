//! UC-26 AA visuals + UC-27 craft tokens + UC-28 component kit + UC-29 contrast/type polarity
//! for `blindkey-gui`.
//!
//! Contrast targets (C81 / C94–C98): primary text ≈ RGB(230,230,230) on panel RGB(28,28,32) —
//! WCAG 2.2 AA 4.5:1. Captions use [`AA_MUTED`]. Primary CTAs use **white** on darkened
//! [`ACCENT`]. Non-text strokes aim for ≥3:1 (C86 / C98 / WCAG 1.4.11). Status never relies on
//! color alone (UC-26 IA-01).
//!
//! **Polarity (UC-29 / C94):** egui 0.29 defaults to following the OS appearance. Applying visuals
//! with `set_visuals` alone can land on the wrong style Arc when macOS Light activates — force
//! `ThemePreference::Dark` and write via `set_visuals_of` / `style_mut_of` on `Theme::Dark`.
//!
//! Craft tokens (UC-27 / C82–C87): `FORM_WIDTH`, `SPACE_*`, Spacing overrides, accent primaries.
//! Surfaces (UC-28 / C88–C93): `AA_CARD_*`, `surface_card`, quiet/text buttons, Settings rows.
//! Type scale (UC-29 / C95): Small ≥12, Body/Button ≥14, Heading ≥20 (NIST SP 800-63B CX).
//! egui **0.29.1** only — TextEdit fill is `extreme_bg_color` (not `text_edit_bg_color`).

use eframe::egui::{
    self, pos2, Color32, FontFamily, FontId, Layout, Response, RichText, Sense, TextStyle, Theme,
    ThemePreference, Ui, Vec2, WidgetText,
};

/// Documented foreground for primary labels (WCAG 1.4.3 AA).
pub const AA_FG: Color32 = Color32::from_rgb(230, 230, 230);
/// Documented panel / window background (WCAG 1.4.3 AA pair with [`AA_FG`]).
pub const AA_BG: Color32 = Color32::from_rgb(28, 28, 32);
/// Extreme / list background (darker than panel).
pub const AA_BG_EXTREME: Color32 = Color32::from_rgb(18, 18, 22);
/// TextEdit / input fill — lighter than panel for Norman signifier (UC-27 C86 / UC-29 retune).
pub const AA_FIELD_BG: Color32 = Color32::from_rgb(52, 52, 60);
/// Stroke on inactive field chrome (≥3:1 vs [`AA_FIELD_BG`] — UC-29 C98).
pub const AA_FIELD_STROKE: Color32 = Color32::from_rgb(130, 130, 140);
/// Card fill — distinct from panel for figure–ground (UC-28 C88).
pub const AA_CARD_BG: Color32 = Color32::from_rgb(34, 34, 40);
/// Card edge stroke (≥3:1 vs [`AA_CARD_BG`] — UC-29 C98).
pub const AA_CARD_STROKE: Color32 = Color32::from_rgb(130, 130, 140);
/// Quiet / inactive control fill (Cancel, header Lock).
pub const AA_QUIET_FILL: Color32 = Color32::from_rgb(48, 48, 54);
/// Quiet control hover wash.
pub const AA_QUIET_HOVER: Color32 = Color32::from_rgb(58, 58, 66);
/// Muted caption / tertiary ink (≥4.5:1 on card and panel — UC-29 C96).
pub const AA_MUTED: Color32 = Color32::from_rgb(140, 140, 148);
/// Primary action accent — darkened so white label hits ≥4.5:1 (UC-29 C97).
pub const ACCENT: Color32 = Color32::from_rgb(45, 120, 190);
/// Primary button label color (white on [`ACCENT`]).
pub const PRIMARY_LABEL: Color32 = Color32::WHITE;
/// Warning / residual / sync CTA (amber) — text on dark panel ≥4.5:1.
pub const WARN: Color32 = Color32::from_rgb(210, 160, 60);
/// Destructive / error ink on dark panel (≥4.5:1) and danger-button fill.
pub const DANGER: Color32 = Color32::from_rgb(225, 95, 95);
/// Label ink on [`DANGER`] fill (near-black ≥4.5:1 — white on DANGER fails AA).
pub const DANGER_LABEL: Color32 = Color32::from_rgb(20, 20, 24);

/// Preferred minimum height for primary buttons (WCAG 2.5.8 ≈ 24 CSS px; we use 32 logical).
pub const PRIMARY_BTN_HEIGHT: f32 = 32.0;
/// Field height family (UC-27 §8.1).
pub const FIELD_HEIGHT: f32 = 32.0;
/// WinUI short-label minimum width guidance (UC-28 CRAFT-S03) — dialog verbs use this.
pub const PRIMARY_BTN_MIN_WIDTH: f32 = 120.0;
/// Alias for dialog primary/cancel column width (CRAFT-S03 / S05).
pub const DIALOG_BTN_WIDTH: f32 = PRIMARY_BTN_MIN_WIDTH;

pub const SPACE_XS: f32 = 6.0;
pub const SPACE_S: f32 = 10.0;
pub const SPACE_M: f32 = 16.0;
pub const SPACE_L: f32 = 20.0;
pub const SPACE_XL: f32 = 28.0;
/// Edge → unlock card (UC-27 CRAFT-10) — unlocked chrome / oversized windows.
pub const WINDOW_GUTTER: f32 = 16.0;
/// Locked default viewport — bootstrap size; runtime grows to measured content.
pub const LOCKED_WINDOW_W: f32 = 540.0;
pub const LOCKED_WINDOW_H: f32 = 760.0;
pub const LOCKED_WINDOW_MIN_W: f32 = 500.0;
/// Floor only — actual height comes from [`fit_locked_viewport_to_content`].
pub const LOCKED_WINDOW_MIN_H: f32 = 480.0;
/// Cap so a huge error string cannot explode the OS window.
pub const LOCKED_WINDOW_MAX_H: f32 = 1200.0;
/// Unlocked Credentials / Workspace working size.
pub const UNLOCKED_WINDOW_W: f32 = 900.0;
pub const UNLOCKED_WINDOW_H: f32 = 620.0;
pub const UNLOCKED_WINDOW_MIN_W: f32 = 640.0;
pub const UNLOCKED_WINDOW_MIN_H: f32 = 440.0;
/// Unlock / create card width (Fluent 400–480 band).
pub const FORM_WIDTH: f32 = 420.0;
/// Settings scroll column max (Fluent settings pattern).
pub const SETTINGS_CONTENT_MAX: f32 = 1000.0;
/// Approximate width reserved for the Show control on passphrase rows (label + box at 16px).
pub const SHOW_ROW_CHECK_WIDTH: f32 = 80.0;
/// Brand mark size in unlocked chrome headers (logical px).
pub const BRAND_MARK_SIZE: f32 = 24.0;
/// Locked-screen hero mark — larger, centered above the form card.
pub const BRAND_MARK_HERO: f32 = 64.0;

/// Control corner radius (buttons / fields).
pub const RADIUS_CONTROL: f32 = 4.0;
/// Card corner radius.
pub const RADIUS_CARD: f32 = 8.0;
/// Credential list row height — medium density (UC-28 CRAFT-S08); keep in sync with
/// [`crate::list_virtualize::ENTRY_ROW_HEIGHT`].
pub const ROW_HEIGHT_LIST: f32 = 28.0;
/// Unlocked header band target (UC-28 CRAFT-S11).
pub const HEADER_HEIGHT: f32 = 44.0;
/// Estimated locked stack height (hero + card) for oversized-window inset only.
pub const LOCKED_CARD_EST_HEIGHT: f32 = 680.0;
/// Soft ambient card shadow — **default off** (Fluent stroke-first on dark; UC-28 §5.2).
pub const SHADOW_CARD_ENABLED: bool = false;

/// Type scale (logical px) — NIST SP 800-63B CX ≥12 pt; roomy auth UI (BK-UI-007).
pub const FONT_SMALL: f32 = 13.0;
pub const FONT_BODY: f32 = 16.0;
pub const FONT_BUTTON: f32 = 16.0;
pub const FONT_HEADING: f32 = 24.0;
pub const FONT_MONO: f32 = 14.0;
/// Inter-line height for wrapped body copy only — not widget gaps (BK-UI-011).
pub const BODY_LINE_HEIGHT: f32 = 24.0;

/// Apply AA visuals + UC-27 Spacing / UC-28 quiet washes / UC-29 Dark polarity + type scale.
pub fn apply_craft_style(ctx: &egui::Context) {
    // C94: never follow OS Light — tokens only live on the Dark style Arc.
    ctx.set_theme(ThemePreference::Dark);
    apply_aa_visuals(ctx);
    ctx.style_mut_of(Theme::Dark, |s| {
        // Widget gaps: modest vertical > horizontal. Do NOT use this for text line-height.
        s.spacing.item_spacing = Vec2::new(SPACE_S, SPACE_M);
        s.spacing.interact_size.y = PRIMARY_BTN_HEIGHT;
        s.spacing.text_edit_width = FORM_WIDTH;
        s.spacing.button_padding = Vec2::new(12.0, 6.0);
        s.spacing.window_margin = egui::Margin::same(SPACE_M);
        s.text_styles.insert(
            TextStyle::Small,
            FontId::new(FONT_SMALL, FontFamily::Proportional),
        );
        s.text_styles.insert(
            TextStyle::Body,
            FontId::new(FONT_BODY, FontFamily::Proportional),
        );
        s.text_styles.insert(
            TextStyle::Button,
            FontId::new(FONT_BUTTON, FontFamily::Proportional),
        );
        s.text_styles.insert(
            TextStyle::Heading,
            FontId::new(FONT_HEADING, FontFamily::Proportional),
        );
        s.text_styles.insert(
            TextStyle::Monospace,
            FontId::new(FONT_MONO, FontFamily::Monospace),
        );
    });
}

/// Re-assert Dark polarity if preference drifted (research §4 / UC-29 C94).
pub fn ensure_dark_polarity(ctx: &egui::Context) {
    let pref = ctx.options(|o| o.theme_preference);
    if pref != ThemePreference::Dark {
        apply_craft_style(ctx);
    }
}

/// Apply high-contrast dark visuals onto the Dark theme style (UC-26 / UC-28 / UC-29 C94).
pub fn apply_aa_visuals(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.override_text_color = Some(AA_FG);
    v.window_fill = AA_BG;
    v.panel_fill = AA_BG;
    // egui 0.29.1: TextEdit background uses extreme_bg_color.
    v.extreme_bg_color = AA_FIELD_BG;
    v.code_bg_color = AA_BG_EXTREME;
    v.faint_bg_color = Color32::from_rgb(36, 36, 42);
    v.widgets.noninteractive.fg_stroke.color = AA_FG;
    v.widgets.inactive.fg_stroke.color = AA_FG;
    v.widgets.inactive.bg_fill = AA_QUIET_FILL;
    v.widgets.inactive.weak_bg_fill = AA_QUIET_FILL;
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, AA_FIELD_STROKE);
    v.widgets.inactive.rounding = egui::Rounding::same(RADIUS_CONTROL);
    v.widgets.hovered.fg_stroke.color = Color32::from_rgb(245, 245, 245);
    v.widgets.hovered.bg_fill = AA_QUIET_HOVER;
    v.widgets.hovered.weak_bg_fill = AA_QUIET_HOVER;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    v.widgets.hovered.rounding = egui::Rounding::same(RADIUS_CONTROL);
    // Keyboard focus maps to `active` on egui 0.29.1 (UC-28 CRAFT-S07).
    v.widgets.active.fg_stroke.color = Color32::WHITE;
    v.widgets.active.bg_fill = Color32::from_rgb(60, 70, 90);
    v.widgets.active.rounding = egui::Rounding::same(RADIUS_CONTROL);
    v.widgets.open.fg_stroke.color = AA_FG;
    v.selection.bg_fill = Color32::from_rgb(50, 90, 130);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = WARN;
    v.error_fg_color = DANGER;
    ctx.set_visuals_of(Theme::Dark, v);
}

/// Centered unlock/create card: clamp + left-justified inner stack (UC-27 CRAFT-01 / §13.4).
pub fn form_card(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    ui.set_max_width(FORM_WIDTH);
    ui.vertical(add_contents);
}

/// Outlined surface card — figure–ground for unlock/create and Settings (UC-28 CRAFT-S01 / C88).
pub fn surface_card(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    // Stroke-first: SHADOW_CARD_ENABLED stays false unless smoke requires ambient elevation.
    let _ = SHADOW_CARD_ENABLED;
    egui::Frame::none()
        .fill(AA_CARD_BG)
        .stroke(egui::Stroke::new(1.0, AA_CARD_STROKE))
        .rounding(egui::Rounding::same(RADIUS_CARD))
        .inner_margin(egui::Margin::same(SPACE_L))
        .show(ui, |ui| {
            add_contents(ui);
        });
}

/// Top inset on the locked screen (UC-28 CRAFT-S02 / C91).
///
/// Default is snug (`SPACE_S`) so the hero sits near the top. When the user has
/// stretched the window far taller than the fitted locked viewport, add a small
/// extra inset — never the old 35%-of-spare push that floated content mid-void.
pub fn locked_vertical_balance_spacer(ui: &mut Ui) {
    let spare = (ui.available_height() - LOCKED_CARD_EST_HEIGHT).max(0.0);
    let top = if spare > 120.0 { WINDOW_GUTTER } else { SPACE_S };
    ui.add_space(top);
}

/// Resize the OS window to the locked or unlocked shell size (once per transition).
///
/// Locked height is a bootstrap only — [`fit_locked_viewport_to_content`] owns the
/// snug size after the first layout measure. Clears `locked_fit_h` so the next
/// locked frame remeasures (create vs unlock, strength meter, errors).
pub fn sync_viewport_to_shell(
    ctx: &egui::Context,
    locked: bool,
    last: &mut Option<bool>,
    locked_fit_h: &mut Option<f32>,
) {
    if *last == Some(locked) {
        return;
    }
    *last = Some(locked);
    *locked_fit_h = None;
    if locked {
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            LOCKED_WINDOW_W,
            LOCKED_WINDOW_H,
        )));
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
            LOCKED_WINDOW_MIN_W,
            LOCKED_WINDOW_MIN_H,
        )));
    } else {
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            UNLOCKED_WINDOW_W,
            UNLOCKED_WINDOW_H,
        )));
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
            UNLOCKED_WINDOW_MIN_W,
            UNLOCKED_WINDOW_MIN_H,
        )));
    }
}

/// Grow (or snug-shrink when we own the size) the locked window to `needed_h`.
///
/// Call after the locked frame layouts so footer + form are never clipped.
/// Does not fight a user who stretched the window taller than content.
pub fn fit_locked_viewport_to_content(
    ctx: &egui::Context,
    needed_h: f32,
    last_auto_h: &mut Option<f32>,
) {
    let needed = needed_h
        .clamp(LOCKED_WINDOW_MIN_H, LOCKED_WINDOW_MAX_H)
        .ceil();
    let current = ctx.input(|i| {
        i.viewport()
            .inner_rect
            .map(|r| r.height())
            .unwrap_or(needed)
    });
    let owned = last_auto_h
        .map(|h| (h - current).abs() < 10.0)
        .unwrap_or(false);
    let clipped = current + 2.0 < needed;
    let grew = last_auto_h.map(|h| needed > h + 4.0).unwrap_or(true);
    let shrank = owned && last_auto_h.map(|h| needed + 4.0 < h).unwrap_or(false);
    if !(clipped || grew || shrank) {
        return;
    }
    if last_auto_h
        .map(|h| (h - needed).abs() < 2.0)
        .unwrap_or(false)
        && !clipped
    {
        return;
    }
    *last_auto_h = Some(needed);
    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
        LOCKED_WINDOW_W,
        needed,
    )));
    ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
        LOCKED_WINDOW_MIN_W,
        LOCKED_WINDOW_MIN_H,
    )));
}

/// Painted Blindkey mark — keyhole in rounded square (matches `assets/blindkey-mark.png`).
pub fn brand_mark(ui: &mut Ui, size: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter_at(rect);
        let rounding = egui::Rounding::same(size * 0.22);
        let stroke_w = (size * 0.09).clamp(1.5, 3.0);
        painter.rect_filled(rect, rounding, AA_BG_EXTREME);
        painter.rect_stroke(rect, rounding, egui::Stroke::new(stroke_w, ACCENT));
        let c = rect.center();
        let hole_r = size * 0.13;
        let circle_c = pos2(c.x, c.y - size * 0.07);
        painter.circle_filled(circle_c, hole_r, ACCENT);
        let top_w = size * 0.09;
        let bot_w = size * 0.20;
        let top_y = circle_c.y + hole_r * 0.45;
        let bot_y = c.y + size * 0.30;
        painter.add(egui::Shape::convex_polygon(
            vec![
                pos2(c.x - top_w * 0.5, top_y),
                pos2(c.x + top_w * 0.5, top_y),
                pos2(c.x + bot_w * 0.5, bot_y),
                pos2(c.x - bot_w * 0.5, bot_y),
            ],
            ACCENT,
            egui::Stroke::NONE,
        ));
    }
    response
}

/// Locked-screen brand hero — large centered mark + wordmark (+ optional status).
pub fn brand_hero(ui: &mut Ui, status: Option<&str>) {
    ui.vertical_centered(|ui| {
        brand_mark(ui, BRAND_MARK_HERO);
        ui.add_space(SPACE_S);
        ui.heading("Blindkey");
        if let Some(status) = status {
            ui.label(RichText::new(status).color(AA_MUTED));
        }
    });
}

/// Outer form column width — fields and primary CTA share this right edge.
pub fn form_column_width(ui: &Ui) -> f32 {
    ui.available_width().min(FORM_WIDTH)
}

/// Accent-filled primary CTA with white label (UC-27 CRAFT-04 / C83 · UC-29 C97).
///
/// Callers should pass ≥ [`PRIMARY_BTN_MIN_WIDTH`] for short dialog verbs (WinUI guidance);
/// toolbar chips (e.g. Add 72) may stay denser.
pub fn primary_button(ui: &mut Ui, label: impl Into<WidgetText>, width: f32) -> Response {
    let text: WidgetText = label.into();
    ui.add_sized(
        [width, PRIMARY_BTN_HEIGHT],
        egui::Button::new(text.color(PRIMARY_LABEL)).fill(ACCENT),
    )
}

/// Quiet / flat secondary (Cancel, header Lock, first-run strip) — UC-28 CRAFT-S03 / C89.
pub fn quiet_button(ui: &mut Ui, label: impl Into<WidgetText>, width: f32) -> Response {
    ui.add_sized(
        [width, PRIMARY_BTN_HEIGHT],
        egui::Button::new(label).fill(AA_QUIET_FILL),
    )
}

/// Alias: UC-27 `secondary_button` retargeted to quiet visuals (UC-28 migration).
pub fn secondary_button(ui: &mut Ui, label: impl Into<WidgetText>, width: f32) -> Response {
    quiet_button(ui, label, width)
}

/// Frame-less tertiary / HyperlinkButton-class (UC-28 CRAFT-S04 / UC-29 readable accent).
pub fn text_button(ui: &mut Ui, label: impl Into<WidgetText>) -> Response {
    let text: WidgetText = label.into();
    ui.add(egui::Button::new(text.color(ACCENT)).frame(false))
}

/// Destructive CTA (Delete / confirm delete) — dark label on DANGER fill (UC-29 cross-check).
pub fn danger_button(ui: &mut Ui, label: impl Into<WidgetText>, width: f32) -> Response {
    let text: WidgetText = label.into();
    ui.add_sized(
        [width, PRIMARY_BTN_HEIGHT],
        egui::Button::new(text.color(DANGER_LABEL)).fill(DANGER),
    )
}

/// Request Credentials Search focus next frame (UC-28 CRAFT-S09 / C93).
pub fn focus_search(flag: &mut bool) {
    *flag = true;
}

/// Soft one-line status host (UC-28 CRAFT-S10 — optional; prefer footer when enough).
pub fn status_strip(ui: &mut Ui, text: impl AsRef<str>) {
    caption(ui, text);
}

/// GNOME-style Settings switch row: label (+ muted subtitle) \| checkbox (UC-28 CRAFT-S06).
pub fn settings_switch_row(
    ui: &mut Ui,
    title: &str,
    subtitle: Option<&str>,
    value: &mut bool,
) -> Response {
    let mut out = None;
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new((ui.available_width() - 40.0).max(120.0), 0.0),
            Layout::top_down(egui::Align::LEFT),
            |ui| {
                ui.label(title);
                if let Some(sub) = subtitle {
                    ui.label(RichText::new(sub).small().color(AA_MUTED));
                }
            },
        );
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            out = Some(ui.checkbox(value, ""));
        });
    });
    out.expect("checkbox always allocated")
}

/// Settings value row: label (+ muted subtitle) \| custom control (UC-28 CRAFT-S06).
pub fn settings_value_row(
    ui: &mut Ui,
    title: &str,
    subtitle: Option<&str>,
    add_control: impl FnOnce(&mut Ui),
) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new((ui.available_width() * 0.45).max(100.0), 0.0),
            Layout::top_down(egui::Align::LEFT),
            |ui| {
                ui.label(title);
                if let Some(sub) = subtitle {
                    ui.label(RichText::new(sub).small().color(AA_MUTED));
                }
            },
        );
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            add_control(ui);
        });
    });
}

/// Full-width selectable list row (UC-28 CRAFT-S08 / C92) — hit target spans the row.
pub fn list_select_row(
    ui: &mut Ui,
    selected: bool,
    label: impl Into<WidgetText>,
) -> Response {
    ui.add_sized(
        [ui.available_width(), ROW_HEIGHT_LIST],
        egui::SelectableLabel::new(selected, label),
    )
}

/// Width of the secret TextEdit when paired with a Show checkbox on the same row.
///
/// Master+Show row and confirm field share the same **outer** column ([`FORM_WIDTH`] /
/// [`form_column_width`]); only the master TextEdit is narrowed for Show.
pub fn secret_field_width() -> f32 {
    (FORM_WIDTH - SPACE_S - SHOW_ROW_CHECK_WIDTH).max(160.0)
}

/// Label above + secret field + Show (CRAFT-02 / CRAFT-05). Returns the TextEdit response.
pub fn labeled_secret_row(
    ui: &mut Ui,
    label: &str,
    value: &mut String,
    show: &mut bool,
    request_focus: &mut bool,
) -> Response {
    let _ = FIELD_HEIGHT; // documents field family vs PRIMARY_BTN_HEIGHT
    // Label sits close to its field — not the global section gap (BK-UI-011).
    let restore_y = ui.spacing().item_spacing.y;
    ui.spacing_mut().item_spacing.y = SPACE_XS;
    ui.label(label);
    let col = form_column_width(ui);
    let edit = ui
        .horizontal(|ui| {
            ui.set_width(col);
            // Prefer the documented FORM_WIDTH math when the column is the design width.
            let field_w = if (col - FORM_WIDTH).abs() < 0.5 {
                secret_field_width()
            } else {
                (ui.available_width() - ui.spacing().item_spacing.x - SHOW_ROW_CHECK_WIDTH).max(160.0)
            };
            // No bullet hint — "••••••••" reads as a prefilled password when empty (BK-UI-008).
            let edit = ui.add(
                egui::TextEdit::singleline(value)
                    .password(!*show)
                    .desired_width(field_w),
            );
            if *request_focus {
                edit.request_focus();
                *request_focus = false;
            }
            // Fixed slot wide enough for checkbox + “Show” at body size (was clipped at 56px).
            ui.allocate_ui_with_layout(
                Vec2::new(SHOW_ROW_CHECK_WIDTH, PRIMARY_BTN_HEIGHT),
                Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.checkbox(show, if *show { "Hide" } else { "Show" });
                },
            );
            edit
        })
        .inner;
    ui.spacing_mut().item_spacing.y = restore_y;
    edit
}

/// Confirm / secondary secret field (no Show).
///
/// Spans the full form column ([`form_column_width`]) so its right edge matches the primary
/// button — CRAFT-02 outer alignment (Show only on the master row).
pub fn labeled_secret_confirm(
    ui: &mut Ui,
    label: &str,
    value: &mut String,
    show: bool,
) -> Response {
    let restore_y = ui.spacing().item_spacing.y;
    ui.spacing_mut().item_spacing.y = SPACE_XS;
    ui.label(label);
    let w = form_column_width(ui);
    let edit = ui.add(
        egui::TextEdit::singleline(value)
            .password(!show)
            .desired_width(w),
    );
    ui.spacing_mut().item_spacing.y = restore_y;
    edit
}

/// Wrapped body copy with open line-height (not widget spacing).
pub fn body_copy(ui: &mut Ui, text: impl AsRef<str>) -> Response {
    ui.label(
        RichText::new(text.as_ref())
            .size(FONT_BODY)
            .line_height(Some(BODY_LINE_HEIGHT)),
    )
}

/// Caption line at Small + muted ink (CRAFT-09 / UC-29 C96).
pub fn caption(ui: &mut Ui, text: impl AsRef<str>) {
    ui.label(RichText::new(text.as_ref()).small().color(AA_MUTED));
}

/// Body-size muted label — prefer over `ui.weak()` (egui gray-out fails ~4.0:1 on AA panels).
pub fn muted_label(ui: &mut Ui, text: impl AsRef<str>) -> Response {
    ui.label(RichText::new(text.as_ref()).color(AA_MUTED))
}

/// Path caption: monospace path + muted “Stored only…” (CRAFT-13 / UC-29 C96).
pub fn vault_path_caption(ui: &mut Ui, path: &std::path::Path) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Vault:").small().color(AA_MUTED));
        ui.monospace(RichText::new(path.display().to_string()).small().color(AA_MUTED));
        ui.label(RichText::new(" · Stored only on this computer.").small().color(AA_MUTED));
    });
}

/// True when Escape was pressed this frame (dialog Cancel — UC-28 CRAFT-S05).
pub fn escape_pressed(ui: &Ui) -> bool {
    ui.input(|i| i.key_pressed(egui::Key::Escape))
}

/// True when Enter/Return was pressed this frame (dialog Affirm when safe — CRAFT-S05).
pub fn enter_pressed(ui: &Ui) -> bool {
    ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// Affirm when Enter was pressed after a field lost focus (safe Return path — CRAFT-S05).
pub fn submit_on_enter(field: &Response, ui: &Ui) -> bool {
    field.lost_focus() && enter_pressed(ui)
}

/// Dialog footer: Cancel (`quiet_button`) then Affirm (`primary_button`) at ≥120 px (CRAFT-S05).
///
/// Also treats Escape as Cancel. Does **not** auto-Affirm on Enter — callers use
/// [`submit_on_enter`] on passphrase fields so Return does not fire while typing mid-field.
pub fn dialog_cancel_affirm(ui: &mut Ui, affirm_label: &str) -> (bool, bool) {
    let mut cancel = escape_pressed(ui);
    let mut affirm = false;
    ui.horizontal(|ui| {
        if quiet_button(ui, "Cancel", DIALOG_BTN_WIDTH).clicked() {
            cancel = true;
        }
        if primary_button(ui, affirm_label, DIALOG_BTN_WIDTH).clicked() {
            affirm = true;
        }
    });
    (cancel, affirm)
}

/// WCAG 2.2 relative luminance for sRGB [`Color32`] (UC-29 contrast asserts).
#[cfg(test)]
pub fn relative_luminance(c: Color32) -> f32 {
    fn channel(u: u8) -> f32 {
        let s = f32::from(u) / 255.0;
        if s <= 0.03928 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
}

/// WCAG contrast ratio between two sRGB colors (≥1.0).
#[cfg(test)]
pub fn contrast_ratio(a: Color32, b: Color32) -> f32 {
    let l1 = relative_luminance(a);
    let l2 = relative_luminance(b);
    let (hi, lo) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
    (hi + 0.05) / (lo + 0.05)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aa_constants_are_distinct() {
        assert_ne!(AA_FG, AA_BG);
        assert_ne!(AA_BG, AA_FIELD_BG);
        assert_ne!(AA_FIELD_BG, AA_BG_EXTREME);
        assert_ne!(AA_CARD_BG, AA_BG, "C88: card fill must differ from panel");
        assert_ne!(AA_MUTED, AA_FG);
        const { assert!(PRIMARY_BTN_HEIGHT >= 24.0) };
        const { assert!(FORM_WIDTH == 420.0) };
        const { assert!(FIELD_HEIGHT >= 24.0) };
        const { assert!(ROW_HEIGHT_LIST >= 24.0) };
        const { assert!(RADIUS_CARD >= RADIUS_CONTROL) };
        const { assert!(FONT_SMALL >= 12.0) };
        const { assert!(FONT_BODY >= 14.0) };
        const { assert!(FONT_BUTTON >= 14.0) };
        const { assert!(FONT_HEADING >= 20.0) };
        const { assert!(BRAND_MARK_SIZE >= 16.0) };
        const { assert!(BRAND_MARK_HERO > BRAND_MARK_SIZE) };
        const { assert!(SPACE_M > SPACE_S) };
    }

    #[test]
    fn secret_field_width_matches_form_column_math() {
        assert!(
            (secret_field_width() - (FORM_WIDTH - SPACE_S - SHOW_ROW_CHECK_WIDTH)).abs() < f32::EPSILON
        );
    }

    #[test]
    fn card_tokens_contrast() {
        assert_ne!(AA_CARD_BG, AA_BG);
        assert_ne!(AA_CARD_STROKE, AA_CARD_BG);
    }

    #[test]
    fn uc29_text_contrast_aa() {
        assert!(
            contrast_ratio(AA_FG, AA_BG) >= 4.5,
            "AA_FG on AA_BG must be ≥4.5:1"
        );
        assert!(
            contrast_ratio(AA_FG, AA_CARD_BG) >= 4.5,
            "AA_FG on AA_CARD_BG must be ≥4.5:1"
        );
        assert!(
            contrast_ratio(AA_MUTED, AA_CARD_BG) >= 4.5,
            "AA_MUTED on card must be ≥4.5:1 (C96)"
        );
        assert!(
            contrast_ratio(AA_MUTED, AA_BG) >= 4.5,
            "AA_MUTED on panel must be ≥4.5:1 (C96)"
        );
        assert!(
            contrast_ratio(PRIMARY_LABEL, ACCENT) >= 4.5,
            "white on ACCENT must be ≥4.5:1 (C97)"
        );
        assert!(
            contrast_ratio(DANGER, AA_BG) >= 4.5,
            "DANGER error text on panel must be ≥4.5:1"
        );
        assert!(
            contrast_ratio(DANGER_LABEL, DANGER) >= 4.5,
            "DANGER_LABEL on DANGER fill must be ≥4.5:1"
        );
        assert!(
            contrast_ratio(WARN, AA_BG) >= 4.5,
            "WARN text on panel must be ≥4.5:1"
        );
    }

    #[test]
    fn uc29_nontext_stroke_contrast() {
        assert!(
            contrast_ratio(AA_FIELD_STROKE, AA_FIELD_BG) >= 3.0,
            "field stroke ≥3:1 vs field fill (C98)"
        );
        assert!(
            contrast_ratio(AA_CARD_STROKE, AA_CARD_BG) >= 3.0,
            "card stroke ≥3:1 vs card fill (C98)"
        );
    }
}
