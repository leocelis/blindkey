//! UC-26 AA visuals + UC-27 craft tokens for `blindkey-gui`.
//!
//! Contrast targets (C81): primary text ≈ RGB(230,230,230) on panel RGB(28,28,32) — WCAG 2.2
//! AA 4.5:1. Non-text strokes aim for ≥3:1 (C86 / WCAG 1.4.11). Status never relies on color
//! alone (UC-26 IA-01).
//!
//! Craft tokens (UC-27 / C82–C87): `FORM_WIDTH`, `SPACE_*`, Spacing overrides, accent primaries.
//! egui **0.29.1** only — TextEdit fill is `extreme_bg_color` (not `text_edit_bg_color`).

use eframe::egui::{self, Color32, Response, Ui, Vec2};

/// Documented foreground for primary labels (WCAG 1.4.3 AA).
pub const AA_FG: Color32 = Color32::from_rgb(230, 230, 230);
/// Documented panel / window background (WCAG 1.4.3 AA pair with [`AA_FG`]).
pub const AA_BG: Color32 = Color32::from_rgb(28, 28, 32);
/// Extreme / list background (darker than panel).
pub const AA_BG_EXTREME: Color32 = Color32::from_rgb(18, 18, 22);
/// TextEdit / input fill — lighter than panel for Norman signifier (UC-27 C86).
pub const AA_FIELD_BG: Color32 = Color32::from_rgb(42, 42, 48);
/// Stroke on inactive field chrome (≥3:1 intent vs [`AA_FIELD_BG`]).
pub const AA_FIELD_STROKE: Color32 = Color32::from_rgb(110, 110, 120);
/// Primary action accent (Create / Unlock / Add).
pub const ACCENT: Color32 = Color32::from_rgb(80, 160, 220);
/// Warning / residual / sync CTA (amber).
pub const WARN: Color32 = Color32::from_rgb(210, 160, 60);
/// Destructive confirm (red).
pub const DANGER: Color32 = Color32::from_rgb(220, 80, 80);

/// Preferred minimum height for primary buttons (WCAG 2.5.8 ≈ 24 CSS px; we use 28 logical).
pub const PRIMARY_BTN_HEIGHT: f32 = 28.0;
/// Field height family (UC-27 §8.1).
pub const FIELD_HEIGHT: f32 = 28.0;

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_S: f32 = 8.0;
pub const SPACE_M: f32 = 12.0;
pub const SPACE_L: f32 = 16.0;
pub const SPACE_XL: f32 = 24.0;
/// Edge → unlock card (UC-27 CRAFT-10).
pub const WINDOW_GUTTER: f32 = 16.0;
/// Unlock / create card width (Fluent 400–480 band).
pub const FORM_WIDTH: f32 = 420.0;
/// Settings scroll column max (Fluent settings pattern).
pub const SETTINGS_CONTENT_MAX: f32 = 1000.0;
/// Approximate width reserved for the Show checkbox on passphrase rows.
pub const SHOW_ROW_CHECK_WIDTH: f32 = 56.0;

/// Apply AA visuals + UC-27 Spacing / field chrome once at startup.
pub fn apply_craft_style(ctx: &egui::Context) {
    apply_aa_visuals(ctx);
    ctx.style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(SPACE_S, SPACE_S);
        s.spacing.interact_size.y = PRIMARY_BTN_HEIGHT;
        s.spacing.text_edit_width = FORM_WIDTH;
        s.spacing.button_padding = Vec2::new(10.0, 4.0);
        s.spacing.window_margin = egui::Margin::same(12.0);
    });
}

/// Apply high-contrast dark visuals (UC-26 Phase A / C81).
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
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, AA_FIELD_STROKE);
    v.widgets.hovered.fg_stroke.color = Color32::from_rgb(245, 245, 245);
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    v.widgets.active.fg_stroke.color = Color32::WHITE;
    v.widgets.open.fg_stroke.color = AA_FG;
    v.selection.bg_fill = Color32::from_rgb(50, 90, 130);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = WARN;
    v.error_fg_color = DANGER;
    ctx.set_visuals(v);
}

/// Centered unlock/create card: clamp + left-justified inner stack (UC-27 CRAFT-01 / §13.4).
pub fn form_card(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    ui.set_max_width(FORM_WIDTH);
    ui.vertical(add_contents);
}

/// Accent-filled primary CTA (UC-27 CRAFT-04 / C83).
pub fn primary_button(ui: &mut Ui, label: impl Into<egui::WidgetText>, width: f32) -> Response {
    ui.add_sized(
        [width, PRIMARY_BTN_HEIGHT],
        egui::Button::new(label).fill(ACCENT),
    )
}

/// Quiet secondary button at primary height.
pub fn secondary_button(ui: &mut Ui, label: impl Into<egui::WidgetText>, width: f32) -> Response {
    ui.add_sized([width, PRIMARY_BTN_HEIGHT], egui::Button::new(label))
}

/// Destructive CTA (Delete / confirm delete) — research §4.3 Danger role.
pub fn danger_button(ui: &mut Ui, label: impl Into<egui::WidgetText>, width: f32) -> Response {
    ui.add_sized(
        [width, PRIMARY_BTN_HEIGHT],
        egui::Button::new(label).fill(DANGER),
    )
}

/// Width of the secret TextEdit when paired with a Show checkbox on the same row.
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
    ui.label(label);
    let field_w = secret_field_width();
    ui.horizontal(|ui| {
        let edit = ui.add(
            egui::TextEdit::singleline(value)
                .password(!*show)
                .desired_width(field_w)
                .hint_text("••••••••"),
        );
        if *request_focus {
            edit.request_focus();
            *request_focus = false;
        }
        ui.checkbox(show, "Show");
        edit
    })
    .inner
}

/// Confirm / secondary secret field (no Show).
///
/// Width matches the master TextEdit column (`secret_field_width`) so both fields share one
/// left edge — CRAFT-02 (± Show on the master row only).
pub fn labeled_secret_confirm(
    ui: &mut Ui,
    label: &str,
    value: &mut String,
    show: bool,
) -> Response {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(!show)
            .desired_width(secret_field_width())
            .hint_text("••••••••"),
    )
}

/// Caption line at Small + weak weight (CRAFT-09).
pub fn caption(ui: &mut Ui, text: impl AsRef<str>) {
    ui.label(egui::RichText::new(text.as_ref()).small().weak());
}

/// Path caption: monospace path + weak “Stored only…” (CRAFT-13).
pub fn vault_path_caption(ui: &mut Ui, path: &std::path::Path) {
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new("Vault:").small().weak());
        ui.monospace(egui::RichText::new(path.display().to_string()).small());
        ui.label(egui::RichText::new(" · Stored only on this computer.").small().weak());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aa_constants_are_distinct() {
        assert_ne!(AA_FG, AA_BG);
        assert_ne!(AA_BG, AA_FIELD_BG);
        assert_ne!(AA_FIELD_BG, AA_BG_EXTREME);
        const { assert!(PRIMARY_BTN_HEIGHT >= 24.0) };
        const { assert!(FORM_WIDTH == 420.0) };
        const { assert!(FIELD_HEIGHT >= 24.0) };
    }

    #[test]
    fn field_fill_contrasts_panel() {
        assert_ne!(
            AA_FIELD_BG, AA_BG,
            "C86: TextEdit fill must differ from panel"
        );
    }
}
