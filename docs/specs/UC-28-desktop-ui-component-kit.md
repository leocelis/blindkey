# UC-28 — Desktop UI Component Kit & Surfaces (`blindkey-gui`)

> **Tech spec** · **Implemented v1.0** · July 2026 · **Status:** shipped — component kit + surface polish
> after UC-27 craft; research cross-check closed (§14).  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-28 · **Constraints:** **C88–C93** (G20) PASS;
> must not regress C20, C27, C40–C54, C75–C81, C82–C87, C72–C74  
> **Extends:** [UC-27](UC-27-desktop-ui-visual-craft.md) (craft shipped), [UC-26](UC-26-desktop-ui-information-architecture.md),
> [UC-18](UC-18-native-ui.md), [UC-20](UC-20-desktop-gui-hardening.md), [UC-21](UC-21-desktop-gaps-closure.md)  
> **Research (binding SoT):** [desktop_ui_components_styling_research.md](../../research/desktop_ui_components_styling_research.md)
> §0–§2 layers · §3 platforms · §4 catalog · §5–§5b peers · §6–§6f egui map · §7 gaps · §8 kit ·
> §9 tokens · §15 cookbook · §16 source audit  
> **Companions:** [desktop_app_ui_ux_research.md](../../research/desktop_app_ui_ux_research.md) (H1–H7 / UC-27),
> [desktop_security_ui_research.md](../../research/desktop_security_ui_research.md) (IA),
> [ui_architecture.md](../../research/ui_architecture.md) (C20 / toolkit)  
> **Sibling (not this UC):** SwiftUI / Liquid Glass / native menus = UC-18 P3; multi-volume list =
> UC-26 DF-7; Argon2 cancel UI = UC-26 DF-6; AccessKit enable = research G4; third-party egui kits =
> optional later only after dep review  
> **ROADMAP:** **S-27** ✅ · Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml)
> disagree, the **intent wins**.

This document is the **implementation contract** for a reusable **component kit and surface
language** in `blindkey-gui` — cards, button roles, Settings rows, vertical balance, hover
states, and search keyboard contracts — so the shell reads as a finished desktop product
**without** inventing locked-state navigation rails or swapping toolkits. UC-27 fixed form
alignment and accent; UC-28 fixes the remaining “floating on void / no chrome components”
gap from live smoke (2026-07-30).

---

## 1. Scope & goals

UC-27 (Implemented v1.0) delivered `FORM_WIDTH` discipline, Spacing tokens, accent primaries,
trust-copy hygiene, and Settings overflow. Live create/unlock still fails **component polish**:
form lacks a distinct card surface, secondary CTAs look like debug chrome, Settings is a free
checkbox pile, locked content sits high in empty canvas, quiet-control hover states are
under-specified, and search keyboard contracts are incomplete (research §1 / §7).

| # | Goal |
|---|------|
| 1 | **Surfaces** — unlock/create (and Settings sections) sit in an outlined `surface_card` (`AA_CARD_*`) |
| 2 | **Button roles** — accent / quiet / text / danger helpers used consistently; tertiary actions do not compete with primary |
| 3 | **Dialog order & keys** — Cancel **before** Affirm; Esc→Cancel; Return→Affirm when safe; initial focus on first field (research §6f) |
| 4 | **Settings rows** — GNOME boxed-list style: label (+ optional weak subtitle) \| control inside a card |
| 5 | **Optical balance** — locked card vertically balanced (not glued to top); footer band remains |
| 6 | **State chrome** — quiet buttons + list rows respect egui `Widgets` hover/inactive (focus uses `active`) |
| 7 | **List hit targets + density** — credential rows full-row selectable; medium `ROW_HEIGHT_LIST` (no Bitwarden-style padding bloat) |
| 8 | **Search contract** — Cmd/Ctrl+F focuses Search when unlocked Credentials; Enter/Tab → first result when query non-empty (best-effort); optional post-unlock focus |
| 9 | **Type / field non-regression** — preserve UC-27 CRAFT-05/09/13/15 + NIST paste/show + C54 visible labels |
| 10 | **Thin shell** — presentation only; preserve C20 / C27 / C75–C87 |

**Feel goals** (research §0 / §8): figure–ground, calm role hierarchy, KeePassXC Welcome-class
locked create (chrome-light), Cryptomator-class Workspace later (DF-7 — **out of scope here**).

**Non-goals (this UC):**

- Locked-state sidebar / Material navigation rail (M3 = 3–7 destinations; Blindkey has 2 modes)
- Calling Credentials \| Workspace a “GNOME view switcher” (HIG rule of thumb is 3–5 views)
- Multi-volume vault list / Cryptomator main-window clone (UC-26 DF-7)
- Native menu bar / Liquid Glass / AppKit glass (UC-18 P3)
- Vendoring Armas / egui-elegance / egui_styled wholesale (steal ideas; in-repo helpers first)
- Electron / Tauri webview for “polish” (breaks C20)
- Fake dashboard stats, purple AI aesthetic, marketing gradients (UC-27 §5.9 / research §10)
- Changing UC-26 IA, mount honesty, Seal-as-secondary
- AccessKit enable by default (still OFF with `default-features = false`)
- Density preference UI (compact/comfortable) — P3 / deferred
- Soft toast / info-bar system beyond a thin `status_strip` helper — P2 optional in this UC if cheap; full toast host deferred

---

## 2. Standards & process alignment

| Standard / guidance | How this UC uses it |
|---------------------|---------------------|
| **ISO/IEC/IEEE 29148** | Goals, non-goals, constraints, tests, deferred ledger |
| **ISO 9241-210** | Research → draft → implement → screenshot re-check |
| **ISO 9241-110** | Consistency of controls across locked/unlocked/dialogs (maps research §4 catalog) |
| **WCAG 2.2** AA | Keep 1.4.3 / 1.4.11 / 2.5.8 / 2.4.7 (focus visible via egui `active`); 3.3.8 paste/show preserved |
| **NIST SP 800-63B-4** | Paste + show/hide on passphrases unchanged (research §6c / §6f) |
| **Fluent 2 / WinUI** | Card fill+stroke; elevation stroke-first on dark; button min width ~120 for short labels; max ~26 chars; HyperlinkButton pattern for tertiary; CommandBar primary-vs-overflow already via Settings (UC-27) |
| **GNOME HIG / Adwaita** | `.card` / boxed-list Settings; Cancel before Affirm; flat/quiet header actions; Esc/Return dialog keys |
| **Apple HIG / Liquid Glass** | Hierarchy/layers doctrine only — **do not** implement glass materials in egui |
| **Material 3** | Rail guidance = **out** (3–7 items); do not mis-apply to 2 modes |
| **egui / eframe 0.29** (lock **0.29.1**) | `Frame`, `Widgets`/`WidgetVisuals`, `Button::fill`, `TopBottomPanel` only — no `text_edit_bg_color` / `weak_text_alpha` |

**Dialog button order (research §3.2 — platform conflict):**

| Platform | Order |
|----------|-------|
| GNOME Dialogs | Cancel **before** Affirm |
| WinUI Buttons | Affirmative-first in recommendation list |

**Blindkey:** Cancel then Affirm (LTR) — matches existing volume/seal dialogs and GNOME/macOS common trailing-default pattern.

---

## 3. Prior art & baseline

### 3.1 Peers (research §5)

| Source | Steal | Skip |
|--------|-------|------|
| Cryptomator | List\|detail + unlock **dialog** (for Workspace DF-7 later); info bar | Always-on vault list on Credentials first-run create |
| KeePassXC | Stacked Welcome vs DB chrome; search-in-toolbar; View density toggles (later) | Full Qt menu bar now |
| Bitwarden issues | Full-row hit target; search focus / Cmd+F; medium density | Electron; excess padding fashion |
| Fluent / Adwaita | Card + boxed list + button roles | Native widgets |

### 3.2 This repo (post–UC-27)

| Module | Today | UC-28 change |
|--------|-------|--------------|
| `theme.rs` | `FORM_WIDTH`, `SPACE_*`, `AA_FIELD_*`, `primary_button`, `secondary_button`, `danger_button`, `form_card` (width clamp only) | + `AA_CARD_*`, radii; `surface_card`; `quiet_button` / `text_button`; settings row helpers; optional `status_strip` |
| `main.rs` locked | Aligned form; accent Create; top-heavy | Wrap in `surface_card`; optical vertical balance |
| Settings window | Free checkboxes | Boxed-list rows inside card |
| Credential list | Rows | Full-row hit + hover wash |
| Search | Present | Focus contract |

### 3.3 Alternatives considered

| Option | Verdict |
|--------|---------|
| In-repo `theme.rs` / thin helpers on egui 0.29.1 | ✅ **this UC** |
| Vendor egui-elegance / Armas / egui_styled | ❌ unless tiny MIT/Apache + quiet aesthetic after review |
| SwiftUI now | ❌ UC-18 P3 |
| Add Material rail / locked sidebar | ❌ Fights research §16 X1–X3 |
| Wait for egui upstream per-widget Frame | ❌ `Frame::show` already enough |

---

## 4. Problem statement (normative)

Maps to research §1 / §7:

1. **No figure–ground** — form floats on flat `AA_BG` without card fill/stroke (H7 residual / Gestalt).
2. **Secondary CTAs look primary-adjacent** — “Choose vault file…” / Cancel / Open existing lack quiet/text roles.
3. **Settings soup** — progressive disclosure exists (C87) but interior is not boxed-list craft.
4. **Empty canvas** — sparse ≠ top-glued; needs optical vertical balance.
5. **State under-specification** — egui `Widgets.hovered` / `inactive` not tuned for quiet controls.
6. **List / search keyboard gaps** — full-row hit + Search focus (Bitwarden lessons).

---

## 5. Proposed design

### 5.1 Architecture

```text
theme.rs tokens     → AA_CARD_*, RADIUS_*, ROW_HEIGHT_LIST, HEADER_HEIGHT
theme helpers       → surface_card, quiet_button, text_button, settings_*_row,
                      focus_search, optional status_strip / app_header band
main / volume/seal  → call helpers only (no one-off Frame recipes)
tests               → uc28_constraints.rs (C88–C93) + keep uc26/uc27 green
```

**`secondary_button` migration:** UC-27 `secondary_button` stays as a thin wrapper or is
retargeted to `quiet_button` visuals. All Cancel / first-run strip / header Lock call sites
must use **quiet** styling after this UC — do not leave a parallel “raised secondary” path
that competes with accent.

Prefer **in-repo helpers** over third-party kits (research §6.2).

### 5.2 Tokens (seed — tune on smoke; 4 px grid)

| Token | Intent | Seed (dark) |
|-------|--------|-------------|
| `AA_CARD_BG` | Card fill ≠ `AA_BG` | ~RGB 32–36 |
| `AA_CARD_STROKE` | 1 px edge | ≥3:1 intent vs card fill where practical |
| `RADIUS_CONTROL` | Buttons / fields | 4–6 |
| `RADIUS_CARD` | Cards | 8–12 |
| `SHADOW_CARD` | Optional | **Default off** — stroke-first (Fluent Windows distinction); enable only if smoke still flat |
| `ROW_HEIGHT_LIST` | Credential row | ~28–32 |
| `HEADER_HEIGHT` | Unlocked header band | ~40–48 |

### 5.3 `surface_card` (CRAFT-S01)

Normative pattern (egui 0.29.1):

```rust
egui::Frame::none()
    .fill(AA_CARD_BG)
    .stroke(egui::Stroke::new(1.0, AA_CARD_STROKE))
    .rounding(egui::Rounding::same(RADIUS_CARD))
    .inner_margin(egui::Margin::same(SPACE_L))
    .show(ui, |ui| { /* existing form_card / settings body */ });
```

- Locked unlock/create: wrap the existing `form_card` stack (trust + fields + CTAs + path caption).
- Settings: one or more cards / boxed sections — not bare checkboxes on window chrome.
- Do **not** require ambient shadow for exit; stroke-first.

### 5.4 Optical vertical balance (CRAFT-S02)

```text
CentralPanel height H
top_spacer = max(WINDOW_GUTTER, (H - card_h) * 0.35)
surface_card
footer band (drop caption) near bottom — CRAFT-10 preserved
```

Card optically centered, slightly high (research §6.3). Do not fill void with dashboard widgets.

### 5.5 Button role kit (CRAFT-S03…S05)

| Helper | Role | Use |
|--------|------|-----|
| `primary_button` | Accent | Create / Unlock / Add / Save / Enroll (existing); short labels prefer ≥120 px width (WinUI) |
| `quiet_button` | Low-contrast / flat-ish | Cancel; header Lock / Settings; first-run Create/Open strip; dialog secondary |
| `text_button` | No fill (HyperlinkButton-class) | “Choose vault file…” and similar tertiary |
| `danger_button` | Destructive | Delete / confirm delete (existing) |

Rules:

- Exactly **one** accent CTA per focus task (UC-27 CRAFT-04 preserved).
- First-run strip remains XOR form primary (CRAFT-06); strip buttons are **quiet**, not accent.
- Dialog footers (Credentials, volume create/unlock, seal/extract): **Cancel (`quiet_button`) then Affirm (`primary_button`)** — CRAFT-S05.
- Dialog keys (research §6f): **Esc** → Cancel; **Return** → Affirm when action is reversible/safe; initial focus on first passphrase/field.
- Verb labels; avoid >~26 characters on primary buttons (WinUI) — wrap/resize if localized long.

### 5.5b Header band (CRAFT-S11 — P2, in-scope light)

Unlocked chrome uses `HEADER_HEIGHT` and **quiet** Lock/Settings (GNOME flat header lesson).
Full `app_header` refactor is optional; minimum is quiet trailing actions + existing mode switch
(UC-26). Do not add a Material rail.

### 5.6 Settings boxed lists (CRAFT-S06)

| Helper | Layout |
|--------|--------|
| `settings_switch_row(ui, title, subtitle_opt, &mut bool)` | Label column \| Switch/checkbox |
| `settings_value_row(ui, title, subtitle_opt, add_control)` | Label \| DragValue / combo |

Host Pad size, Auto-lock, Clipboard, Lock on blur, and similar toggles as rows inside
`surface_card` (or stacked cards). Preserve C87 (Settings overflow) — this UC restyles the
**interior**, not the disclosure model.

### 5.7 State chrome (CRAFT-S07)

Tune or document `apply_craft_style` so quiet controls get distinct `Widgets.inactive` vs
`hovered` washes without breaking accent fills. Remember: egui maps keyboard **focus →
`Widgets.active`** (research §6b / §16 X7) — do not invent a nonexistent focus Visuals field.

### 5.8 List rows + Search (CRAFT-S08, S09)

- **CRAFT-S08:** Credential list rows — full-row click/select hit target; hover wash on the row;
  target height ≈ `ROW_HEIGHT_LIST` (medium density — research §10 anti-pattern: no huge padding).
- **CRAFT-S09:** `focus_search()` helper — when unlocked Credentials: Cmd/Ctrl+F focuses Search;
  optional focus Search once after unlock; when query non-empty, Enter or Tab moves focus toward
  the first matching row (best-effort in egui; document limits in open Q #3).

### 5.8b Field / type non-regression (CRAFT-S12)

Do not regress UC-27 / research §6c / §9.1:

- Label above fields; hint ≠ label (CRAFT-05).
- Path / drop / trust captions = Small + weak (CRAFT-09/13); title once (CRAFT-15).
- NIST paste + Show on passphrases; C54 visible labels (AccessKit OFF).

### 5.9 Optional thin status strip (CRAFT-S10 — P2)

`status_strip(ui, text)` — weak one-line host for soft status (research §8 kit). Not a full
toast stack. **Default for this UC:** implement if ≤ small helper; else DF-4. Footer caption
already covers drop hints.

### 5.10 Explicit anti-patterns

| ❌ Forbidden |
|-------------|
| Locked-state Material rail / fake destinations |
| Liquid Glass blur stacks |
| Shadcn/Armas purple “AI” look |
| Dashboard metric cards |
| egui APIs newer than pin (`text_edit_bg_color`, `weak_text_alpha`, …) |
| Affirm-before-Cancel as Blindkey default (WinUI order) without documenting exception |
| Hover highlight without clickable row |
| Excess list padding that collapses visible rows (Bitwarden lesson) |

### 5.11 Deferred (ledger)

| ID | Item | Where |
|----|------|-------|
| DF-1 | Multi-volume Workspace list \| detail | UC-26 DF-7 |
| DF-2 | Native menus / Liquid Glass | UC-18 P3 |
| DF-3 | AccessKit ON | research G4 |
| DF-4 | Full toast / info-bar system | follow-up |
| DF-5 | Compact/comfortable density preference | P3 |
| DF-6 | Peer pixel audit R1 | optional PR |
| DF-7 | Third-party egui kit adopt | after dep review |

---

## 6. Constraint compliance map

### 6.1 Constraints (G20 — PASS)

| ID | Statement | Test |
|----|-----------|------|
| **C88** | Locked unlock/create body is wrapped in `surface_card` using `AA_CARD_BG` ≠ `AA_BG` and visible stroke | `uc28_constraints.rs` `c88_*` |
| **C89** | Quiet/text role kit: Cancel + first-run strip + “Choose vault file…” use `quiet_button` / `text_button` — not accent fill | `c89_*` + `craft_s05_*` |
| **C90** | Settings interior presents ≥3 controls as labeled rows (`settings_*_row` or equivalent) inside card chrome | `c90_*` |
| **C91** | Locked CentralPanel applies optical vertical balance (spacer math or equivalent) — card not permanently top-glued with only `WINDOW_GUTTER` | `c91_*` |
| **C92** | Credential list rows expose full-row select hit target at medium `ROW_HEIGHT_LIST` density | `c92_*` |
| **C93** | Unlocked Credentials Search is focusable via Cmd/Ctrl+F through `focus_search` (or equivalent wiring) | `c93_*` |

Preserve: C20, C27, C40–C54, C72–C74, C75–C81, C82–C87.

### 6.2 CRAFT rule IDs (this UC)

| ID | Behavior | Research |
|----|----------|----------|
| CRAFT-S01 | `surface_card` on locked form + Settings sections | §6e, §8 |
| CRAFT-S02 | Optical vertical balance | §6.3, §7 P0 |
| CRAFT-S03 | `quiet_button` for Cancel / quiet chrome / first-run strip / header Lock | §4.1, §7 P1–P2 |
| CRAFT-S04 | `text_button` for tertiary links | §4.1 / WinUI HyperlinkButton |
| CRAFT-S05 | Cancel before Affirm + Esc/Return/initial-focus dialog keys | §3.2, §6f |
| CRAFT-S06 | Settings boxed-list rows | §3.3 / GNOME boxed lists |
| CRAFT-S07 | Hover/inactive quiet-control states (`Widgets`) | §6b |
| CRAFT-S08 | Full-row list hit targets + `ROW_HEIGHT_LIST` medium density | §5.3, §6f, §10 |
| CRAFT-S09 | `focus_search` + Cmd/Ctrl+F (+ best-effort Enter/Tab) | §6f, §8 |
| CRAFT-S10 | Optional `status_strip` | §5.1 / §8 (P2) |
| CRAFT-S11 | Unlocked header quiet density (`HEADER_HEIGHT`) | §7 P2 header flat |
| CRAFT-S12 | Preserve UC-27 type/field/NIST/C54 | §6c, §9.1 |

---

## 7. Test plan

### 7.1 Automated

| Test | Asserts |
|------|---------|
| `uc28_constraints.rs` T1–T6 | C88–C93 static/wiring |
| Existing `uc26_*` / `uc27_*` | No regressions |
| `cargo clippy -p blindkey-gui -- -D warnings` | Clean |
| Theme unit asserts | `AA_CARD_BG != AA_BG`; no forbidden Visuals fields |

### 7.2 Manual smoke

1. Locked create: visible card edge; accent Create; Choose vault file… quiet/text.
2. Vertical balance: resize window — card not stuck to top only.
3. Settings: row layout readable; toggles still work.
4. Unlocked: Search Cmd/Ctrl+F; list row click anywhere on row.
5. H1–H7 still closed (UC-27).

### 7.3 Joint

Single screenshot + checklist: card + quiet tertiary + Settings rows + balance — all on same build.

---

## 8. Implementation segments (IVD)

| Seg | Work | Exit | Research |
|-----|------|------|----------|
| **C0** | Tokens `AA_CARD_*` / radii / `ROW_HEIGHT_LIST` / `HEADER_HEIGHT` (+ SHADOW off) | Compiles; unit asserts | §9 |
| **C1** | `surface_card` + locked wrap + vertical balance | Screenshot: figure–ground + balance | §15 #1–3 |
| **C2** | `quiet_button` / `text_button` + migrate `secondary_button`; dialog Cancel→Affirm + Esc/Return sweep (main + volume + seal) | No competing tertiary; CRAFT-S05 | §15 #4, §6f |
| **C3** | Settings boxed-list rows | ≥3 row controls | §15 #5 |
| **C4** | Hover quiet + full-row list + `focus_search` + header quiet (S11) | Smoke CRAFT-S07…S09, S11 | §15 #6–7 |
| **C5** | `uc28_constraints.rs` + suites + clippy; verify CRAFT-S12 non-regression | Green | §15 #8 |
| **C6** | Intent G20 C88–C93 + CONSTRAINT_INDEX + mark Implemented | Accept → Implemented | promotion |

**Segment rule:** 3+ constraints → implement one segment at a time; re-read intent constraints
from disk per IVD Rule 1.

---

## 9. Open questions

1. Enable `SHADOW_CARD` after stroke-only smoke, or keep stroke-only forever on dark AA?
   → **Shipped:** `SHADOW_CARD_ENABLED = false` (stroke-first). Flip only after smoke.
2. Is CRAFT-S10 (`status_strip`) in-scope for v1 of this UC or deferred DF-4?
   → **Shipped:** thin `status_strip` on unlocked bottom bar; full toast host remains DF-4.
3. Search Enter→first-result: hard-require or best-effort given egui focus limits?
   → **Shipped:** best-effort — Tab/Enter selects first match when query non-empty and no row selected.
4. Full `app_header` helper vs light CRAFT-S11 quiet trailing actions only?
   → **Shipped:** light CRAFT-S11 (`min_height(HEADER_HEIGHT)` + quiet Lock/Settings).

---

## 10. Deferred ledger

See §5.11 DF-1…DF-7.

---

## 11. Changelog

| Date | Change |
|------|--------|
| 2026-07-30 | **Draft v0.1** — Component kit & surfaces from `desktop_ui_components_styling_research.md` (post–§16 audit); candidate C88–C93; segments C0–C6; CRAFT-S01…S10 |
| 2026-07-30 | **Draft v0.2** — Research cross-check (§14): dialog Esc/Return/focus; C89 quiet kit breadth; `focus_search` / `secondary_button` migration; CRAFT-S11–S12; ROW_HEIGHT + header; WinUI 120/26; anti-patterns from §10 |
| 2026-07-30 | **Implemented v1.0** — `surface_card` + quiet/text kit; Settings boxed rows; optical balance; full-row list + Search focus; dialog Esc + Cancel→Affirm; `uc28_constraints.rs` C88–C93; intent G20 / v1.9.5; ROADMAP S-27 |
| 2026-07-30 | **Implementation cross-check (§15)** — closed CRAFT-S05 gaps: `dialog_cancel_affirm` / `submit_on_enter`; dialog `focus_password` / editor `focus_title`; import/enroll Cancel→Affirm; `SHADOW_CARD_ENABLED`; `DIALOG_BTN_WIDTH` ≥120; header `min_height(HEADER_HEIGHT)` |

---

## 12. Acceptance checklist (maintainer)

- [x] C0–C5 merged; tests green  
- [x] Locked form: visible card; optical balance; quiet/text tertiary  
- [x] Settings: boxed-list rows  
- [x] List full-row hit + Search focus smoke  
- [x] Dialogs: Cancel→Affirm + Esc/Return smoke (Credentials + volume + seal)  
- [x] UC-26 / UC-27 suites PASS; CRAFT-S12 fields/type/NIST intact  
- [x] No locked sidebar / no Material rail / no Liquid Glass  
- [x] Intent G20 C88–C93 promoted  
- [x] Spec status → **Implemented v1.0**  
- [x] ROADMAP S-27 ✅  
- [x] §15 implementation gaps closed  

---

## 13. Research ↔ spec map

| Research locus | Spec section |
|----------------|--------------|
| §1 incident / §7 gaps | §4 problem |
| §5.1 Cryptomator list nuance | Non-goals + §3.1 (no fake list on Credentials create) |
| §5.2 KeePassXC Welcome | Locked chrome-light stance |
| §5.3 Bitwarden | CRAFT-S08 / S09 |
| §6 / §6.3 Frame recipe | CRAFT-S01 / S02 |
| §6b Widgets states | CRAFT-S07 |
| §6c TextBox / fields | CRAFT-S12 |
| §6f keyboard / a11y | CRAFT-S05 / S08 / S09 |
| §3.2 dialog order conflict | CRAFT-S05 + §2 |
| §3.4 M3 rail 3–7 | Non-goals |
| §4.1 button roles + WinUI 120/26 | CRAFT-S03…S04 |
| §7 P2 header flat | CRAFT-S11 |
| §8 kit (`focus_search`, `status_strip`) | §5.1 / CRAFT-S09 / S10 |
| §9 tokens / §9.1 type | §5.2 / CRAFT-S12 |
| §10 anti-patterns | §5.10 |
| §15 cookbook | §8 segments |
| §16 audit X1–X11 | Incorporated as normative corrections |

**Intentional deltas from research:**

1. CRAFT-S10 status strip is **thin** (bottom band) — full toast host remains DF-4.
2. Density preference UI stays deferred (P3) — keep medium list density only (`ROW_HEIGHT_LIST`).
3. Cryptomator always-on vault list is **not** copied onto Credentials first-run — Workspace DF-7 owns that pattern.
4. Full `app_header` helper is optional; CRAFT-S11 requires quiet header density, not a full rewrite.
5. Research §8.1 acceptance sketch is a **minimum**; this UC also ships list/search/hover/dialog keys (aligned with §7 / §15).

---

## 14. Research cross-check (Draft v0.2)

Closed against `desktop_ui_components_styling_research.md` §0–§16 (2026-07-30).

| ID | Spec ↔ research issue | Severity | Resolution in v0.2 |
|----|----------------------|----------|-------------------|
| A1 | Spec CRAFT-S05 = order only; research §6f also Esc/Return/initial focus | Med | CRAFT-S05 + goal #3 + segment C2 |
| A2 | Research §8 kit `focus_search` unnamed in spec | Med | Named helper; C93 wording |
| A3 | C89 too narrow (Choose vault file only) vs quiet kit for Cancel/strip | Med | C89 broadened |
| A4 | `secondary_button` fate unspecified | Med | Migration note §5.1 |
| A5 | Dialog sweep missed volume/seal | Med | Explicit in CRAFT-S05 / C2 |
| A6 | `ROW_HEIGHT_LIST` token unused in CRAFT | Low | CRAFT-S08 |
| A7 | Header flat P2 / `HEADER_HEIGHT` / `app_header` missing | Low | CRAFT-S11 |
| A8 | Field/type/NIST non-regression not stated | Med | CRAFT-S12 + goal #9 |
| A9 | WinUI 120px / 26-char not in button rules | Low | CRAFT-S03 |
| A10 | §10 anti-patterns (hover without hit; padding bloat) absent | Low | §5.10 |
| A11 | ISO 9241-110 / forbidden Visuals fields omitted vs UC-27 | Low | §2 |
| A12 | Research §0 still implied Cryptomator nav “post-auth” only | Med | Fixed in research (this pass) |
| A13 | Research §8.1 sketch omitted list/search vs §15 | Low | Spec delta #5 + research §8.1 update |

**Joint:** Draft v0.2 + research §13/§8.1/§0 aligned → ready for Accept.

---

## 15. Implementation ↔ spec cross-check (post-ship)

Closed 2026-07-30 against Implemented v1.0 code (`theme.rs`, `main.rs`, `volume_gui.rs`, `sealed_gui.rs`, `uc28_constraints.rs`).

| ID | Spec requirement | Gap found | Fix |
|----|------------------|-----------|-----|
| I1 | CRAFT-S05 Return→Affirm when safe | Volume/seal dialogs had Esc+Cancel only; no Enter path | `submit_on_enter` on passphrase fields |
| I2 | CRAFT-S05 initial focus on first field | `focus_pw = false` always in dialogs | `focus_password: true` on Create/Mount/Seal/Open/Enroll; `focus_title` on Editor |
| I3 | CRAFT-S05 Cancel→Affirm everywhere | Import Affirm-before-Cancel; Enroll Affirm-before-Cancel | Reordered + `dialog_cancel_affirm` / quiet Cancel |
| I4 | §5.2 `SHADOW_CARD` token | Missing | `SHADOW_CARD_ENABLED = false` |
| I5 | CRAFT-S03 dialog ≥120 px short verbs | Dialogs used width 100 | `DIALOG_BTN_WIDTH` / `PRIMARY_BTN_MIN_WIDTH` = 120 |
| I6 | CRAFT-S11 `HEADER_HEIGHT` | Token unused (`let _ =`) | `TopBottomPanel::min_height(HEADER_HEIGHT)` |
| I7 | CRAFT-S05 helper consistency | Per-dialog hand-rolled footers | `dialog_cancel_affirm` + tests |
| I8 | Open Q #2–#4 unresolved in docs | Spec still open | Closed in §9 with shipped answers |

**Still deferred (not gaps):** DF-1…DF-7; peer pixel audit; AccessKit ON; native menus.

**Joint:** I1–I8 closed · `uc26`/`uc27`/`uc28` PASS · clippy `-D warnings` clean.
