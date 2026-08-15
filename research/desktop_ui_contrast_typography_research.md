# Desktop UI contrast, typography & layout polarity — research

> **Task:** Ground Blindkey’s locked-shell color/type/layout failures (2026-07-30 smoke)
> in **primary standards and institute guidance**, diagnose the egui theme bug, and propose
> a shippable fix UC.
>
> Research date: **2026-07-30**. Markers: ✓ verified · ~ corroborated · ? assumed.
>
> **Trigger:** Live screenshot after UC-28 — light window chrome + dark `surface_card`,
> illegible labels/captions, harsh white fields, “horrible” color/type/contrast.
>
> **Where this sits:**
>
> | Doc | Owns |
> |-----|------|
> | [`desktop_ui_components_styling_research.md`](desktop_ui_components_styling_research.md) | Component kit / surfaces (UC-28) |
> | [`desktop_app_ui_ux_research.md`](desktop_app_ui_ux_research.md) | H1–H7 craft (UC-27) |
> | **This file** | **Polarity, contrast math, type scale, layout canvas** |
> | Spec | **[UC-29](../docs/specs/UC-29-desktop-ui-contrast-typography.md)** |

**Stack pin:** egui / eframe **0.29** → **0.29.1**; AccessKit OFF.

---

## 0. Incident (2026-07-30 smoke) — what failed

Observed create-vault window:

| Symptom | Likely cause |
|---------|----------------|
| Large **light gray** canvas; dark card floating | egui `ThemePreference::System` → macOS **Light** style active; `set_visuals` wrote into the *active* style at boot (often Dark before system theme arrives), then Light style took over |
| Labels / instructions / path **dark-on-dark** inside card | Light-theme foreground (near-black) on `AA_CARD_BG` Frame fill |
| Footer caption **light-on-light** | `.weak()` gray on Light panel fill |
| Bright **white** TextEdit | Light-theme field chrome, not `AA_FIELD_BG` |
| Blue primary with black label | Default egui fill button ink; white-on-ACCENT(80,160,220) is only **~2.8:1** (fails WCAG 1.4.3) |

**Root cause (✓ egui 0.29.1 sources):** `Options::theme_preference` defaults to
`ThemePreference::System`. `Context::set_visuals` mutates **only the currently selected**
dark/light style. After `system_theme` resolves to Light, Blindkey’s AA tokens are ignored
while `surface_card` still paints a dark Frame → **polarity collision**.

---

## 1. Standards & institute sources (binding)

### 1.1 W3C WCAG 2.2 (Recommendation)

| SC | Requirement | Blindkey use |
|----|-------------|--------------|
| [1.4.3 Contrast (Minimum)](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html) ✓ | Normal text ≥ **4.5:1**; large text ≥ 3:1 | Body, labels, button labels, captions that are “normal” size |
| [1.4.11 Non-text Contrast](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast) ✓ | UI component boundaries / states ≥ **3:1** vs adjacent | Field stroke vs field fill; card edge vs panel |
| [1.4.12 Text Spacing](https://www.w3.org/WAI/WCAG22/Understanding/text-spacing.html) ✓ | Content survives user spacing overrides (line 1.5×, etc.) — research basis McLeish / Wayne E. Dick | Don’t clip captions; keep Spacing tokens roomy |
| [1.4.8 Visual Presentation](https://www.w3.org/WAI/WCAG22/Understanding/visual-presentation.html) (AAA) ~ | ≤80 characters/line; leading ≥1.5 | Keep `FORM_WIDTH` ~420; body not full-bleed |

W3C Understanding 1.4.3 notes the **4.5:1** floor accounts for aging / low acuity beyond the older
**ISO 9241-3 / ANSI-HFES-100** **3:1** recommendation for standard text.

### 1.2 NIST SP 800-63B — Customer Experience (usable security)

✓ [NIST pages.nist.gov 800-63-4 / SP 800-63B customer experience](https://pages.nist.gov/800-63-4/sp800-63b/customer/):

- Prefer **high contrast** for user-facing text
- **Sans-serif** on electronic displays
- Fonts that distinguish confusable characters (O/0)
- **Minimum font size of 12 points** when text fits the device
- Larger touch/hit targets on constrained UIs

Directly applies to Blindkey’s passphrase / create / unlock surfaces.

### 1.3 ISO 9241 family

- ISO 9241-11 usability definition (cited by NIST) — effectiveness / efficiency / satisfaction
- ISO 9241-3 historical **3:1** text contrast (cited by W3C Understanding 1.4.3) — WCAG AA is stricter

### 1.4 APCA / WCAG 3 candidate (informative only)

~ [Myndex APCA](https://www.myndex.com/APCA/) / [SAPC-APCA](https://github.com/Myndex/SAPC-APCA):
perceptual contrast for self-illuminated displays; dark-mode WCAG 2 ratios can
**overstate** readability. **Not** a conformance claim until WCAG 3 is Recommendation.
Blindkey **ships WCAG 2.2 AA math**; use APCA as a design sanity check for dark AA.

### 1.5 Layout / line length (industry research + W3C)

~ [Baymard Institute — optimal line length](https://baymard.com/blog/line-length-readability):
body **50–75** characters; WCAG 1.4.8 AAA ≤80. Blindkey unlock card width already in band.

---

## 2. Measured pairs (this pass)

Relative luminance WCAG formula (sRGB), sample:

| Pair | Ratio | Verdict |
|------|-------|---------|
| AA_FG (230) on AA_BG (28,28,32) | ~13.6:1 | ✓ AA |
| AA_FG on AA_CARD (34,34,40) | ~12.7:1 | ✓ AA |
| White on ACCENT (80,160,220) | ~2.8:1 | ✗ fails 1.4.3 |
| Black on ACCENT | ~7.4:1 | ✓ but looks “toy” on security UI |
| Dark gray ~80 on CARD (light-theme ink on Frame) | ~2.0:1 | ✗ incident |
| Weak gray on light window | ~1.8:1 | ✗ footer incident |
| AA_FIELD (42) on CARD (34) | ~1.1:1 | ✗ field figure–ground weak |
| AA_FIELD_STROKE (110) on FIELD (42) | ~2.8:1 | ✗ fails 1.4.11 (≥3:1) |

**Retune targets (seed for UC-29):**

| Token | Seed | Intent |
|-------|------|--------|
| `ACCENT` | RGB(45, 120, 190) | White label ≥4.5:1 |
| `AA_MUTED` | RGB(140, 140, 148) | Captions ≥4.5:1 on card/panel |
| `AA_FIELD_BG` | RGB(52, 52, 60) | Stronger field vs card |
| `AA_FIELD_STROKE` | RGB(130, 130, 140) | ≥3:1 vs field fill |
| `AA_CARD_STROKE` | RGB(130, 130, 140) | ≥3:1 vs card fill |
| `DANGER` | RGB(225, 95, 95) | Error text ≥4.5:1 on panel; dark label on fill |
| `DANGER_LABEL` | RGB(20, 20, 24) | ≥4.5:1 on DANGER (white fails) |

**Post-ship measured (shipped tokens, WCAG formula):**

| Pair | Ratio | Verdict |
|------|-------|---------|
| White on ACCENT (45,120,190) | ~4.62:1 | ✓ AA |
| AA_MUTED on CARD / panel | ~4.74 / ~5.09 | ✓ AA |
| AA_FIELD_STROKE on FIELD | ~3.24:1 | ✓ 1.4.11 |
| AA_CARD_STROKE on CARD | ~4.16:1 | ✓ 1.4.11 |
| DANGER on panel | ~4.86:1 | ✓ AA |
| DANGER_LABEL on DANGER | ~5.25:1 | ✓ AA |
| egui `weak()` gray-out of AA_FG on panel | ~4.0–4.3:1 | ✗ — banned; use `AA_MUTED` |

---

## 3. Typography scale (NIST + egui)

egui 0.29.1 defaults (`default_text_styles`): Small **9**, Body/Button **12.5**, Heading **18**.

NIST usable-security guidance: **≥12 pt** for user-facing auth text. Small=9 fails that intent
for captions that carry path / trust / recoverability warnings.

| Role | egui TextStyle | Proposed size (logical) |
|------|---------------|-------------------------|
| Caption / path | Small | **12.0** (was 9) |
| Body / labels | Body | **14.0** |
| Button | Button | **14.0** |
| Title | Heading | **20.0** |

Do not invent a fourth marketing display size on lock (UC-27 CRAFT-15).

---

## 4. Layout / polarity rules

1. **One polarity per window** — dark AA panel fill everywhere; no light canvas with dark card.
2. **Force `ThemePreference::Dark`** — do not follow macOS Light for the security shell
   (C20 egui stays; appearance is product-owned).
3. Apply visuals with `set_visuals_of(Theme::Dark, …)` + spacing/text_styles on Dark style.
4. Re-assert theme preference at startup (and optionally each update if ThemeChanged fires).
5. Captions use explicit `AA_MUTED` (not Light-theme `weak()` gray-out of black).
6. Primary buttons: **white** ink on darkened `ACCENT`.
7. Optical card balance (UC-28) remains; empty light void must disappear once panel is dark.

---

## 5. Anti-patterns

| ❌ | Why |
|----|-----|
| Dark Frame on Light Style | Polarity collision (this incident) |
| `set_visuals` only, System theme | Tokens land on wrong style Arc |
| White on bright sky-blue primary | Fails 1.4.3 |
| Small=9 for recoverability / path captions | Below NIST 12pt intent |
| Relying on `.weak()` without verifying muted ratio | Gray-out of wrong base color |

---

## 6. UC-29 status (shipped)

**[UC-29](../docs/specs/UC-29-desktop-ui-contrast-typography.md)** / ROADMAP **S-28** is **Implemented v1.0**
with intent **G21 C94–C98**. Post-ship gap pass closed: `muted_label` (no `ui.weak`),
`ensure_dark_polarity`, danger-label AA (see UC-29 §10).

---

## 7. Sources

### Official / institute

- W3C — [WCAG 2.2](https://www.w3.org/TR/WCAG22/); Understanding [1.4.3](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html), [1.4.11](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast), [1.4.12](https://www.w3.org/WAI/WCAG22/Understanding/text-spacing.html), [1.4.8](https://www.w3.org/WAI/WCAG22/Understanding/visual-presentation.html)
- NIST — [SP 800-63B Customer Experience](https://pages.nist.gov/800-63-4/sp800-63b/customer/) (legibility / ≥12 pt / high contrast)
- ISO 9241-3 / ANSI-HFES-100 — historical 3:1 text (via W3C Understanding 1.4.3)

### Research / candidate algorithms

- Myndex — [APCA](https://www.myndex.com/APCA/), [SAPC-APCA](https://github.com/Myndex/SAPC-APCA) (informative)
- Baymard Institute — [line length readability](https://baymard.com/blog/line-length-readability)
- McLeish / Wayne E. Dick — cited in W3C Understanding 1.4.12

### Code

- egui 0.29.1 — `ThemePreference::System` default; `set_visuals` / `set_visuals_of`; `default_text_styles`; `weak()` = gray-out via `tint_color_towards`

---

## 8. ONE recommendation

> Smoke **UC-29** with `cargo run -p blindkey-gui` on macOS Light appearance — confirm full dark
> window, readable captions/path, white Create vault, no light canvas. Then commit when happy.

---

## 9. Changelog

| Date | Change |
|------|--------|
| 2026-07-30 | Initial contrast/typography/polarity research from WCAG/NIST/APCA/Baymard + egui System-theme root cause; UC-29 proposal |
| 2026-07-30 | **Post-ship** — measured shipped ratios; ban `ui.weak`; `AA_CARD_STROKE` / DANGER tokens; UC-29 shipped pointer |
