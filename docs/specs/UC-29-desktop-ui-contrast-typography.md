# UC-29 — Desktop UI Contrast, Typography & Theme Polarity (`blindkey-gui`)

> **Tech spec** · **Implemented v1.0** · July 2026 · **Status:** shipped — polarity + WCAG/NIST type/contrast
> after UC-28 smoke failure (light canvas / dark card / illegible captions).  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-29 · **Constraints:** **C94–C98** (G21) PASS;
> must not regress C20, C27, C40–C54, C75–C81, C82–C87, C88–C93  
> **Extends:** [UC-28](UC-28-desktop-ui-component-kit.md), [UC-27](UC-27-desktop-ui-visual-craft.md),
> [UC-26](UC-26-desktop-ui-information-architecture.md)  
> **Research (binding SoT):** [desktop_ui_contrast_typography_research.md](../../research/desktop_ui_contrast_typography_research.md)
> · companions: [desktop_ui_components_styling_research.md](../../research/desktop_ui_components_styling_research.md),
> [desktop_app_ui_ux_research.md](../../research/desktop_app_ui_ux_research.md)  
> **ROADMAP:** **S-28** ✅ · Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml)
> disagree, the **intent wins**.

This document is the **implementation contract** for fixing Blindkey’s locked-shell
**theme polarity**, **WCAG 2.2 AA contrast**, and **NIST-aligned type scale** after the
2026-07-30 smoke screenshot (light window + dark `surface_card` → dark-on-dark labels).

---

## 1. Scope & goals

| # | Goal |
|---|------|
| 1 | **Force Dark theme** — `ThemePreference::Dark`; never follow macOS Light for the AA shell |
| 2 | **Apply tokens to Dark style** — `set_visuals_of(Theme::Dark, …)` + `style_mut_of(Dark, …)` |
| 3 | **Retune tokens** — accent / muted / field / strokes meet measured WCAG ratios |
| 4 | **Type scale** — Small ≥12, Body/Button ≥14, Heading ≥20 (NIST ≥12 pt intent) |
| 5 | **Primary ink** — white label on darkened `ACCENT` (≥4.5:1) |
| 6 | **Captions** — `AA_MUTED` (not Light-theme `.weak()` gray-out of black) |
| 7 | **Thin shell** — presentation only; preserve C20 / C88–C93 |

**Non-goals:** Light theme mode toggle; AccessKit ON; toolkit swap; Liquid Glass; density pref.

---

## 2. Standards

| Source | Use |
|--------|-----|
| WCAG 2.2 **1.4.3** | Text ≥4.5:1 (body, captions, button labels) |
| WCAG 2.2 **1.4.11** | UI boundaries ≥3:1 (field stroke vs fill; card stroke vs card) |
| NIST SP 800-63B CX | High contrast; sans-serif; **≥12 pt** user-facing auth text |
| APCA | Informative sanity only — **not** a conformance claim |
| Baymard / WCAG 1.4.8 | Keep `FORM_WIDTH` ~420 (50–75 char band) |

---

## 3. Root cause (binding)

egui **0.29.1** defaults to `ThemePreference::System`. `Context::set_visuals` mutates only
the **currently selected** style. At `CreationContext`, system theme may still be unset
(writes hit Dark), then macOS Light activates → **untouched Light style** + dark
`surface_card` Frame → polarity collision (research §0).

**Fix:** `ctx.set_theme(ThemePreference::Dark)` then `set_visuals_of` / `style_mut_of` on
`Theme::Dark`.

---

## 4. Token retune (seed → shipped)

| Token | Before | After | Intent |
|-------|--------|-------|--------|
| `ACCENT` | (80,160,220) | **(45,120,190)** | White ≥4.5:1 |
| `AA_MUTED` | (n/a / `.weak()`) | **(140,140,148)** | Captions ≥4.5:1 on card/panel |
| `AA_FIELD_BG` | (42,42,48) | **(52,52,60)** | Stronger field figure |
| `AA_FIELD_STROKE` | (110,110,120) | **(130,130,140)** | ≥3:1 vs field |
| `AA_CARD_STROKE` | (90,90,100) | **(130,130,140)** | ≥3:1 vs card |
| Primary label | default / black | **WHITE** | 1.4.3 on accent |
| `DANGER` | (220,80,80) | **(225,95,95)** | Error text ≥4.5:1 on panel |
| Danger label | white (fail) | **DANGER_LABEL (20,20,24)** | ≥4.5:1 on DANGER fill |

Type styles (logical px): Small **12**, Body **14**, Button **14**, Heading **20**, Monospace **13**.

---

## 5. Implementation map

| Module | Change |
|--------|--------|
| `theme.rs` | Tokens; `apply_craft_style` forces Dark + `_of(Dark)`; text_styles; `AA_MUTED`; white `primary_button`; `DANGER_LABEL` on danger; muted `caption` / `muted_label` / path / settings subtitles; accent `text_button`; `ensure_dark_polarity` |
| `main.rs` | `apply_craft_style` at boot; `ensure_dark_polarity` each frame; locked + unlocked trust/empty via caption/muted |
| `volume_gui.rs` | Workspace notes via `muted_label` (no `ui.weak`) |
| Tests | `uc29_constraints.rs` C94–C98 + contrast unit asserts in `theme.rs` |
| Intent | G21 C94–C98 · v1.9.6 |

---

## 6. Constraints (G21 — PASS)

| ID | Statement | Test |
|----|-----------|------|
| **C94** | GUI forces `ThemePreference::Dark`, applies via `set_visuals_of(Theme::Dark, …)`, and re-asserts with `ensure_dark_polarity` each frame | `c94_force_dark_theme` |
| **C95** | Text styles: Small ≥12, Body ≥14, Button ≥14, Heading ≥20 | `c95_type_scale_nist` |
| **C96** | `AA_MUTED` on card/panel ≥4.5:1; captions/path/`muted_label`; no shell `ui.weak` | `c96_muted_contrast` |
| **C97** | White primary on `ACCENT` ≥4.5:1; danger uses `DANGER_LABEL` | `c97_primary_white_on_accent` |
| **C98** | Field stroke ≥3:1 vs field fill; card stroke ≥3:1 vs card fill; panel fill token remains `AA_BG` | `c98_nontext_strokes` |

**Joint:** all five pass on the same `theme.rs` + `apply_craft_style` surface (`joint_g21_contrast_kit`).

---

## 7. Segments (shipped)

| Seg | Work | Status |
|-----|------|--------|
| D0 | Research + measured ratios | ✅ |
| D1 | Force Dark + `*_of(Dark)` + type scale | ✅ |
| D2 | Token retune + white primary + muted captions | ✅ |
| D3 | `uc29_constraints.rs` + intent G21 | ✅ |
| D4 | Docs ROADMAP/PRD/CONSTRAINT_INDEX/CHANGELOG | ✅ |

---

## 8. Acceptance (manual smoke)

- [ ] Full dark window (no light void around card)
- [ ] Labels, instructions, path, footer readable
- [ ] “Choose vault file…” readable (accent tertiary)
- [ ] Create vault: white text on blue, not black-on-sky
- [ ] Fields visibly inset (stroke + fill)
- [ ] Delete/danger: dark label on red (not white-on-red)

---

## 9. Research ↔ spec map

| Research locus | Spec section |
|----------------|--------------|
| §0 incident / polarity | §3 root cause |
| §1 WCAG / NIST / Baymard | §2 standards |
| §2 measured + retune seeds | §4 tokens |
| §3 type scale | §4 type + C95 |
| §4 polarity rules (incl. re-assert) | C94 + `ensure_dark_polarity` |
| §5 anti-patterns | §10 deferred / tests |
| §6 UC-29 proposal | this UC (shipped) |

---

## 10. Implementation ↔ spec cross-check (post-ship)

Closed 2026-07-30 against Implemented v1.0 + gap pass.

| ID | Spec / research requirement | Gap found | Fix |
|----|-----------------------------|-----------|-----|
| X1 | Captions use `AA_MUTED`, not `ui.weak` | Unlocked/Workspace still called `ui.weak` (~4.0:1 fail) | `muted_label` + migrate main/volume |
| X2 | Research §4 re-assert theme | Only set at CreationContext | `ensure_dark_polarity` each `App::update` |
| X3 | Button labels ≥4.5:1 on fill | `danger_button` used white on DANGER (~3.96:1) | `DANGER_LABEL` near-black; DANGER text retuned (225,95,95) |
| X4 | Spec §5 said main.rs unchanged | Locked trust already used `caption` | Doc corrected; unlocked trust → muted |
| X5 | Research retune omitted `AA_CARD_STROKE` | Spec had it; research table lag | Research post-retune table updated |
| X6 | C96 only helpers, not shell | Empty states / OTP still weak | Ban `ui.weak(` in main/volume tests |
| X7 | Research §8 still “Implement” | UC shipped | Research §8 → shipped + ONE rec smoke |
| X8 | FONT_MONO / Button style asserts | C95 incomplete | Test asserts Monospace + Button inserts |
| X9 | DANGER as error text on panel | (220,80,80) ~4.29:1 | DANGER (225,95,95) ≥4.5:1 |

**Joint:** C94–C98 + `joint_g21_contrast_kit` + `theme::tests::uc29_*` green after gap pass.

---

## 11. Changelog

| Date | Change |
|------|--------|
| 2026-07-30 | **Implemented v1.0** — force Dark polarity; WCAG/NIST tokens + type; C94–C98; ROADMAP S-28 |
| 2026-07-30 | **Cross-check gap pass** — `muted_label` / no `ui.weak`; `ensure_dark_polarity`; danger label AA; §10 table |
