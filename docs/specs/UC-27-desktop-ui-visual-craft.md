# UC-27 — Desktop UI Visual Craft Polish (`blindkey-gui`)

> **Tech spec** · **Implemented v1.0** · July 2026 · **Status:** implemented — presentation craft
> (`FORM_WIDTH` card, Spacing, accent primaries, Settings overflow, field chrome); **C82–C87 PASS**
> (`uc27_constraints.rs`).  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-27 · **Constraints:** **C82–C87** (G19, intent **v1.9.4**);
> must not regress C20, C27, C40–C54, C75–C81, C72–C74  
> **Extends:** [UC-26](UC-26-desktop-ui-information-architecture.md) (IA shipped), [UC-18](UC-18-native-ui.md),
> [UC-20](UC-20-desktop-gui-hardening.md), [UC-21](UC-21-desktop-gaps-closure.md)  
> **Research (binding craft SoT):** [desktop_app_ui_ux_research.md](../../research/desktop_app_ui_ux_research.md)
> §1 incident · §4 systems · §8 playbook · §13 egui 0.29.1 API map · §16 H1–H7 · §17 checklist · §19 audit  
> **Companions:** [desktop_security_ui_research.md](../../research/desktop_security_ui_research.md) (IA/honesty),
> [ui_architecture.md](../../research/ui_architecture.md) (toolkit),
> [desktop_ui_components_styling_research.md](../../research/desktop_ui_components_styling_research.md) +
> [UC-28](UC-28-desktop-ui-component-kit.md) (component kit / surfaces — Implemented v1.0)  
> **Sibling (not this UC):** SwiftUI / Liquid Glass = UC-18 P3; vault Argon2 cancel = UC-26 DF-6;
> multi-volume list = UC-26 DF-7; AccessKit enable = research G4 / R4  
> **Cross-check:** research ↔ Draft **v0.2**; **Implemented 2026-07-29** (ROADMAP S-26);
> three-way code↔spec↔research audit same day (§14)  
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the **intent wins**.

This document is the **implementation contract** for making the shipped `blindkey-gui` look and
feel like a finished desktop product — **layout, hierarchy, spacing, primary accent, density,
and copy discipline** — without changing crypto, format, modes, or delivery logic. UC-26 made
Blindkey *usable and honest*; UC-27 makes it *crafted*.

---

## 1. Scope & goals

UC-26 (Implemented v1.0) delivered fonts, Credentials | Workspace modes, mount honesty, and
AA text contrast. Live macOS smoke (2026-07-29) still fails **visual craft**: mixed
center/left form alignment, duplicate trust copy, competing Create CTAs, primary buttons
indistinguishable from secondary, and low-affordance dark inputs (research §1 / §16).

| # | Goal |
|---|------|
| 1 | **Form discipline** — unlock/create uses one clamped card (`FORM_WIDTH = 420`); fields left-aligned inside it |
| 2 | **Hierarchy** — one primary accent CTA per focus task; secondary actions quiet |
| 3 | **Spacing system** — egui `Spacing` + `SPACE_*` tokens replace ad-hoc `add_space` |
| 4 | **Signifiers** — TextEdit fill/stroke contrast vs panel (WCAG 1.4.11; egui 0.29.1 `extreme_bg_color`) |
| 5 | **Copy hygiene** — no duplicate trust lines; no label+identical `hint_text` |
| 6 | **Chrome calm** — unlocked credential settings behind progressive disclosure (Settings) without removing capability |
| 7 | **Density / bands** — sparse unlock; medium credential list; Settings scroll column; chrome ≠ body ≠ footer |
| 8 | **Thin shell** — presentation only; preserve C20 / C27 / C75–C81 |

**Feel goals** (research §0 / §8): calm, aligned, trustworthy — competence without theater.
Not Liquid Glass; not a metrics dashboard; not a toolkit swap.

**Non-goals (this UC):**

- Toolkit swap (Electron, Tauri webview secrets, SwiftUI — UC-18 P3)
- Changing Credentials | Workspace IA, Seal-as-secondary, mount honesty (UC-26)
- Changing C27 copy-default, clipboard/reveal timeouts (UC-21)
- New crypto, volume format, FUSE packaging (UC-25)
- Vault unlock Argon2 “Deriving key…” + Cancel (UC-26 DF-6)
- Multi-volume Cryptomator list (UC-26 DF-7)
- Enabling AccessKit by default (research G4 — optional follow-up; pin today is **OFF**)
- Fake Liquid Glass blur, marketing gradients, purple “AI” aesthetic, dashboard stats cards (research §8.5)
- `blindkey-tui` visual parity
- Private `*_patterns.yaml` in this public repo
- Side-by-side KeePassXC/Cryptomator pixel audit as a merge blocker (research R1 — PR optional)

---

## 2. Standards & process alignment

Same certification posture as UC-26 (align, do not claim formal cert):

| Standard / guidance | How this UC uses it |
|---------------------|---------------------|
| **ISO/IEC/IEEE 29148** | Goals, non-goals, constraints, tests, deferred ledger — Blindkey UC template |
| **ISO 9241-210** | Research → draft craft → implement → heuristic re-check on unlock screenshot |
| **ISO 9241-110** | Consistency, error tolerance, suitability — maps to Nielsen/Shneiderman in research §14 |
| **WCAG 2.2** AA | Keep 1.4.3 text; **strengthen 1.4.11** non-text (inputs); keep 2.5.8 targets; keep 3.3.8 paste/show |
| **NIST SP 800-63B-4** | Preserve paste + show/hide on passphrase fields (UC-26/UC-21) — craft must not hide them |
| **Fluent 2 / WinUI** | 4 px spacing ramp; left-aligned forms; unlock focus width **400–480** → pick **420**; Settings ~1000 px content |
| **GNOME HIG** | Simplicity; clamp; suggested vs quiet buttons; Settings overflow |
| **Apple HIG** | Short writing; one clear default action; Hierarchy/Harmony/Consistency (2025 framing); **do not** implement Liquid Glass materials in egui |
| **egui / eframe 0.29.1** | Official `Style` / `Spacing` / `Visuals` / `Ui` / `Button::fill` only — no APIs from newer egui |

**AccessKit reality (research §12.2 / §13.7 / §19 X2):** Blindkey pins `default-features = false`
without re-adding `accesskit` → AccessKit is **OFF**. Visible `ui.label` before every `TextEdit`
remains mandatory (C54) whether or not AccessKit is later enabled.

Trusted-author mapping (implementation checklist, not theater): Nielsen #4/#8, Shneiderman
consistency + STM, Norman signifier/mapping, Tog Fitts/simplicity, Johnson attention, Krug
redundancy — research §14.

---

## 3. Prior art & baseline

### 3.1 Product craft (visual)

| Source | Steal | Skip |
|--------|-------|------|
| Cryptomator | Sparse unlock focus; large primary; Workspace density | Native materials |
| KeePassXC | Aligned forms/toolbars; credential list alignment | Density clone |
| 1Password / Bitwarden desktop | Search-first; polished empty states | Cloud/account chrome |
| Signal Desktop | Calm chrome | Electron stack |
| Finder / Files | Path as secondary caption | Native widgets |
| Fluent / GNOME / Apple HIG | Tokens, clamp, suggested CTA | Platform-native widgets |

### 3.2 This repo (Implemented v1.0 — craft landed)

| Module | Behavior after UC-27 |
|--------|----------------------|
| `theme.rs` | `FORM_WIDTH` / `SPACE_*` / `AA_FIELD_*`; `apply_craft_style`; `form_card` / `primary_button` / secret-row helpers |
| `main.rs` locked | Three bands; first-run strip **or** form primary (CRAFT-06); single trust line; accent Create/Unlock |
| Unlocked chrome | Add accent + Settings…; pad/autolock/clipboard/audit/keyfile/import in Settings |
| `volume_gui` / `sealed_gui` | Accent primaries; passphrase rows via theme helpers (FORM_WIDTH discipline) |
| Tests | `uc27_constraints.rs` C82–C87 + CRAFT-06/08 |

### 3.3 Alternatives considered

| Option | Verdict |
|--------|---------|
| Stay egui + craft tokens/layout | ✅ **this UC** |
| SwiftUI now for “native polish” | ❌ UC-18 P3 — months; wrong sequencing |
| CSS/webview shell | ❌ Violates C20 |
| Wait for eframe bump for newer Visuals fields | ❌ Craft is fixable on **0.29.1** (`extreme_bg_color`, strokes, `Button::fill`) |

---

## 4. Problem statement (normative)

Maps 1:1 to research §1 / §16 (H1–H7):

1. **Alignment axis broken (H3):** nesting `horizontal` passphrase rows inside `vertical_centered`
   without a fixed-width inner `vertical` produces left-drifted fields vs centered siblings
   (research §6, §13.4; egui `Ui` docs).
2. **No spacing system:** ad-hoc `add_space(4/6/8/10/12/14)` fights Fluent proximity and egui
   defaults (`item_spacing` Y=3, `text_edit_width=280`, `interact_size.y=18` — research §13.2 / X7).
3. **Primary not primary (H5):** Create/Unlock/Add look like quiet greys; `theme::ACCENT` exists but
   is unused on buttons (`Button::fill` is available on 0.29.1).
4. **Redundant copy (H1, H4):** “No account. No cloud.” appears with the long trust sentence; label and
   `hint_text` both say “Master password”.
5. **Competing Create CTAs (H2):** first-run strip + form primary without dismiss discipline.
6. **Path competes with passphrase (H6):** path/footer same visual weight as labels.
7. **Weak input signifiers (H7):** `AA_BG_EXTREME` (18,18,22) on panel `AA_BG` (28,28,32) is a dark
   hole; non-text contrast / Norman signifier fail without stroke or lighter field fill.

---

## 5. Proposed design

### 5.1 Architecture (presentation only)

```
theme.rs          → tokens + apply_aa_visuals / apply_craft_style (+ Spacing mutator)
layout helpers    → form_card / passphrase_row (theme.rs or layout.rs) — research §6 / §13.4
main.rs           → locked unlock/create (three bands); unlocked Settings overflow + Add accent
volume_gui.rs     → FORM_WIDTH / accent / SPACE_* on Workspace home CTAs + dialogs
sealed_gui.rs     → same for Seal/Open primaries (consistency)
uc27_constraints  → static/unit craft gates (sibling to uc26)
```

No new crates. No `persistence`. No AccessKit required for exit.

### 5.2 Density & window bands (research §4.1 / §4.4)

| Context | Density | Rule |
|---------|---------|------|
| Unlock / create | **Sparse** | Generous vertical rhythm (`SPACE_M`/`SPACE_L` between groups) |
| Credentials list | **Medium** | Keep UC-20 virtualization; rows/columns share one alignment axis |
| Settings | Scrollable single column | Content max ≈ **1000** px (Fluent settings pattern); not unlock-card width |
| Workspace home | **Sparse** | Cryptomator-class; large accent Create/Unlock (research §8.4) |

**Three bands** on locked screen (research §4.1 / §8.2):

1. **Chrome** — Blindkey · Locked (status never color-alone — UC-26 IA-01)
2. **Body** — form card centered with `WINDOW_GUTTER` (16–24) from window edge
3. **Footer** — drop hint only (`ui.weak` / Small)

### 5.3 Phase A — Design tokens & style (blocker)

**Normative tokens** in `crates/blindkey-gui/src/theme.rs`:

| Token | Value | Notes |
|-------|-------|-------|
| `SPACE_XS` | `4.0` | Fluent 4 px ramp base |
| `SPACE_S` | `8.0` | label→field; gutters inside card |
| `SPACE_M` | `12.0` | related group |
| `SPACE_L` | `16.0` | section; min window gutter |
| `SPACE_XL` | `24.0` | band; max window gutter |
| `WINDOW_GUTTER` | `16.0`..=`24.0` | Edge → card (prefer `SPACE_L` or `SPACE_XL`) |
| `FORM_WIDTH` | `420.0` | unlock/create card; within UC-26 Fluent **400–480** |
| `SETTINGS_CONTENT_MAX` | `1000.0` | Settings scroll column clamp |
| `FIELD_HEIGHT` | `28.0`..=`32.0` | Match `PRIMARY_BTN_HEIGHT` family (research §8.1) |
| `SHOW_ROW_CHECK_WIDTH` | measured / documented | passphrase field = `FORM_WIDTH - item_spacing.x - SHOW_ROW_CHECK_WIDTH` |
| `PRIMARY_BTN_HEIGHT` | `28.0` | keep (C81 / IA-08); Fitts ≥24 |
| `ACCENT` / `WARN` / `DANGER` / `AA_*` | keep | Accent = primary CTAs only; Danger = destructive; Warn = residual/sync refuse (research §4.3) |

**egui 0.29.1 Spacing defaults → intentional overrides** (research §13.2):

| Field | Default | Blindkey craft |
|-------|---------|----------------|
| `item_spacing` | `(8, 3)` | `(SPACE_S, SPACE_S)` — raise Y |
| `interact_size.y` | `18` | `PRIMARY_BTN_HEIGHT` (28) |
| `text_edit_width` | `280` | `FORM_WIDTH` (420) |
| `button_padding` | egui default | Comfortable for primary CTAs (tune once; document) |
| `window_margin` / `menu_margin` | egui default | Dialog breathing room |
| `indent` | egui default | Advanced collapsing (keep UC-26) |

**Normative style mutations** (research §19 X1 — pin-correct APIs only):

```text
ctx.style_mut(|s| {
  s.spacing.item_spacing = vec2(SPACE_S, SPACE_S);
  s.spacing.interact_size.y = PRIMARY_BTN_HEIGHT;
  s.spacing.text_edit_width = FORM_WIDTH;
  // optional: button_padding, window_margin
});
visuals.extreme_bg_color = field fill LIGHTER than panel (preferred) OR keep dark + mandatory stroke;
visuals.widgets.inactive.bg_stroke = visible ≥3:1 vs adjacent fill where feasible;
// optional: faint_bg_color behind unlock card (Gestalt common region — research §13.3)
```

**Forbidden for this pin (do not cite / do not call):**
`text_edit_bg_color`, `weak_text_alpha`, `window_corner_radius` (newer egui; 0.29.1 uses
`window_rounding`). Captions → `ui.weak()` / `TextStyle::Small`, not a missing Visuals alpha field.

**Field fill rule (decided):** lighter fill than `AA_BG` (e.g. RGB ~40–44 on panel 28) **plus**
thin visible `bg_stroke` on inactive text-edit chrome (research open Q → closed here).

Exit: unlock fields visibly “editable”; Spacing defaults overridden once at boot.

### 5.4 Phase B — Locked unlock / create form (CRAFT-01…06, 10, 13, 15)

**Normative layout pattern** (research §13.4 — copy into helper):

```text
vertical_centered {
  ui.set_max_width(FORM_WIDTH);
  ui.vertical(|ui| {                    // left-justify INSIDE centered clamp
    // trust / first-run / labels / fields / primary / secondary / path caption
  });
}
```

Never place a passphrase `horizontal` as a **direct** child of `vertical_centered` without the
inner `vertical` + `FORM_WIDTH` clamp.

Wireframe (research §8.2) is **normative**:

```
Chrome: Blindkey · Locked
Band:   Local only. No account. No cloud.     ← exactly one trust line on this screen
Card:   set_max_width(FORM_WIDTH); inner vertical (left-justified)
        [first-run only, until dismissed]
          [ Create vault ]  [ Open existing… ]   ← co-equal until one chosen; then dismiss strip
        Instruction (one line)
        Master password          ← label above only; hint_text empty or “••••••••”
        [____________] Show
        Confirm (create only)
        [____________]
        [ Create vault | Unlock ]  ← ONE accent primary, width FORM_WIDTH
        Choose vault file…         ← secondary quiet
        path + Stored only…        ← ONE caption block (weak / Small; path monospace OK)
Footer: drop hint (weak)
```

| Rule ID | Behavior | Research |
|---------|----------|----------|
| CRAFT-01 | Unlock/create body centered via clamp; **inner** stack is `ui.vertical` left-justified at `FORM_WIDTH` | §6, §13.4 |
| CRAFT-02 | All passphrase/confirm fields share the same content width (± Show on same row) | §8.2 #3 |
| CRAFT-03 | Exactly **one** occurrence of `Local only. No account. No cloud.` **or** the long first-run sentence — not both stacked as duplicates of “No account. No cloud.” | §4.5, H1 |
| CRAFT-04 | Primary Create/Unlock uses `Button::fill(ACCENT)` + `PRIMARY_BTN_HEIGHT`; sized to `FORM_WIDTH` | §8.1, H5 |
| CRAFT-05 | No `.hint_text` identical to the field’s visible label | H4 / §19 X3 |
| CRAFT-06 | After first-run strip dismissed, form primary alone remains — no peer competing Create | §8.2 #2, H2 |
| CRAFT-10 | Locked window uses chrome / body / footer bands; body card respects `WINDOW_GUTTER` | §4.1 |
| CRAFT-13 | Path + “Stored only…” = **one** caption block under the card; path may use monospace; drop hint is footer-only weak text | §4.2, §8.2 #4, H6 |
| CRAFT-15 | App title / screen heading appears **once** in chrome — do not fight with a second Display-weight “Blindkey” inside the card | §4.2 |

### 5.5 Phase C — Unlocked chrome calm (CRAFT-07, 11, 14)

| Rule ID | Behavior | Research |
|---------|----------|----------|
| CRAFT-07 | Credentials mode: keep Search, **Add** (accent), Lock (quiet), status, mode switch, **Settings…**. Move Pad size / Auto-lock / Clipboard / Lock on blur / Audit / Keyfile 2FA / Import behind Settings. Import may remain as empty-state CTA. **Seal** lives on Workspace (UC-26) — not Credentials toolbar. | §8.3 + UC-26 modes (Settings promoted from §17 #6) |
| CRAFT-11 | Unlocked Credentials **Add** uses accent fill (same primary weight as Create/Unlock — research §8.1) | §8.1 |
| CRAFT-14 | Settings content clamped to `SETTINGS_CONTENT_MAX` (~1000); scrollable single column; density medium | §4.4 |
| CRAFT-16 | Color roles: Accent = primary CTAs (Create/Unlock/Add/Save/Enroll); Danger = Delete / confirm-delete only; Warn = sync residual; errors via `DANGER` text | §4.3 |

Unlocked chrome (Credentials): left = brand + mode + status; right = Settings + Lock.  
Workspace chrome stays sparse; Seal / Create / Unlock there (UC-26 Cryptomator-class).

### 5.6 Phase D — Dialog + Workspace consistency (CRAFT-08, 12)

| Rule ID | Behavior | Research |
|---------|----------|----------|
| CRAFT-08 | Volume create/unlock and Seal dialogs: primary accent-filled; Cancel quiet; passphrase rows use same Show pattern + width discipline as unlock (no new IA). Dialog vertical rhythm uses `SPACE_*`. Preserve NIST paste + show/hide. | §8.1, §4.7, §14.1 #4 |
| CRAFT-12 | Workspace **home** Create/Unlock (or equivalent large CTAs) use accent fill + primary height — Cryptomator sparsity | §8.4 |

### 5.7 Phase E — Type ramp (CRAFT-09)

| Rule ID | Behavior | Research |
|---------|----------|----------|
| CRAFT-09 | Path, drop hint, and secondary captions use `ui.weak` and/or `TextStyle::Small` — not the same visual weight as passphrase labels | §4.2, H6 |

Optional: bump `style.text_styles` for Heading/Body once — do not introduce custom font files unless
`default_fonts` fails (INSTALL path).

### 5.8 Motion (preserve, do not expand)

Keep UC-26 dialog fades in the **150–250 ms** class (research §4.6). No continuous “crypto”
animation. Mode-switch fades remain optional polish (DF-7) — not required for exit.

### 5.9 Explicit anti-patterns (research §8.5 — must not ship)

| ❌ Forbidden in this UC |
|-------------------------|
| Fake Liquid Glass blur stacks |
| Marketing gradients / purple AI aesthetic |
| Dashboard cards with stats |
| Center-aligning **only some** controls in a form |
| Citing / using egui APIs newer than **0.29.1** Visuals fields listed in §5.3 |

### 5.10 Explicitly deferred (do not sneak in)

| Item | Where tracked |
|------|----------------|
| Vault Argon2 progress + Cancel | UC-26 DF-6 |
| Multi-volume list | UC-26 DF-7 |
| Live Mounted/Reveal path | UC-26 DF-8 |
| AccessKit feature enable | research G4 |
| Liquid Glass / SwiftUI | UC-18 P3 |
| eframe version bump | UC-21 DG-3 / UC-26 DF-4 |
| KeePassXC/Cryptomator pixel audit | research R1 |
| egui Window/Panel styling cookbook doc | research R2 |
| High-contrast / increased-contrast macOS smoke | research R4 |

---

## 6. Constraint compliance map

### 6.1 Existing (must not regress)

| Constraint | Note |
|------------|------|
| C20 | egui stays; single binary |
| C27 / C13 | Copy-default; clipboard timeout |
| C40–C54 | Hardening + gaps closure; C54 visible labels before TextEdit |
| C41 | No eframe `persistence` |
| C72–C74 | Residual banner; sync refuse + Seal CTA; uniform volume errors |
| C75–C81 | Fonts, status, modes, human labels, mount honesty, Advanced, AA targets |

### 6.2 Constraints (G19 — promoted intent **v1.9.4**)

| ID | Title | Test |
|----|-------|------|
| **C82** | Unlock/create fixed-width left-aligned card | `uc27_constraints.rs` `c82_*` |
| **C83** | Create/Unlock/Add accent fill | `c83_*` |
| **C84** | Craft Spacing at startup | `c84_*` |
| **C85** | Non-redundant trust copy; hint ≠ label | `c85_*` |
| **C86** | TextEdit chrome contrasts panel | `c86_*` |
| **C87** | Credential settings progressive disclosure | `c87_*` |

---

## 7. Test plan

### 7.1 Automated / in-tree

| ID | Covers | Method |
|----|--------|--------|
| T1 | C82 | `uc27_constraints.rs`: `FORM_WIDTH == 420`; locked path clamp + inner vertical pattern |
| T2 | C83 | Accent fill on Create/Unlock (locked) + Add (unlocked) construction |
| T3 | C84 | Theme apply sets Spacing fields named in §5.3 |
| T4 | C85 | Locked screen: `"No account. No cloud."` count ≤ 1; master password hint ≠ label |
| T5 | C86 | Theme constants / stroke documentation assertion |
| T6 | C87 | Settings overflow: settings controls not all in always-visible toolbar source path |
| T7 | Regression | `cargo test -p blindkey-gui --tests`; `cargo clippy -p blindkey-gui --all-targets -- -D warnings` |
| T8 | UC-26 | All `uc26_constraints` remain green (modes, honesty, fonts, paste/show) |
| T9 | Manual | Screenshot unlock create + unlock existing + Workspace home + Settings — alignment axis + accent + single trust line |

### 7.2 Heuristic gate (ship)

Re-run research §16 **H1–H7** on a fresh screenshot. **Ship gate:** H1–H7 all closed or waived
in PR with maintainer note. Zero “broken alignment” majors.

| Heuristic | Closed by |
|-----------|-----------|
| H1 Duplicate trust | CRAFT-03 / C85 |
| H2 Competing Create | CRAFT-06 |
| H3 Misaligned fields | CRAFT-01–02 / C82 |
| H4 Label + hint echo | CRAFT-05 / C85 |
| H5 Primary not primary | CRAFT-04, 11, 12 / C83 |
| H6 Path weight | CRAFT-09, 13 |
| H7 Low-contrast inputs | CRAFT field fill / C86 |

### 7.3 Maintainer smoke (UC-26 journeys + craft)

1. First-run → Create vault → Add (accent) → Copy → Lock  
2. Unlock existing → Credentials **Settings…** → change clipboard timeout → Lock  
3. Workspace Create → Unlock → Eject  
4. Optional: paste + Show on create passphrase (NIST / C54 regression)

### 7.4 Optional research follow-ups (not merge blockers)

| ID | Item |
|----|------|
| R1 | Side-by-side pixel audit vs KeePassXC / Cryptomator unlock (attach screenshots in PR) |
| R4 | High-contrast / increased-contrast macOS smoke after theme change |

---

## 8. Implementation segments (IVD)

3+ candidate constraints → **segmented** implementation; re-read this file from disk between segments.

| Seg | Work | Exit | Maps §17 |
|-----|------|------|----------|
| **B0** | Tokens + Spacing + field fill/stroke (+ optional faint card) in `theme.rs` | Compiles; visuals smoke | §17 #1 |
| **B1** | Locked unlock/create rewrite + `form_card` / `passphrase_row` (CRAFT-01…06, 10, 13, 15) | Screenshot: aligned card; H1–H7 closed on unlock | §17 #2–5 |
| **B2** | Unlocked Settings overflow + Add accent (CRAFT-07, 11, 14) | Toolbar calm; settings reachable | §17 #6 |
| **B3** | Volume + Seal dialog + Workspace home accent/width (CRAFT-08, 09, 12) | Dialogs + Workspace match | consistency |
| **B4** | `uc27_constraints.rs` T1–T6 + full GUI suites + clippy | Green | §17 #7 |
| **B5** | Intent G19 C82–C87 + CONSTRAINT_INDEX + mark Implemented | Accept → Implemented | promotion |

No ADR unless abandoning egui or changing C20 — craft is reversible presentation.

**Helper preference (OSS hygiene):** `fn form_card(ui, |ui| …)` / `fn passphrase_row` in `theme.rs`
or `layout.rs` — match existing module style (`theme.rs`, `gui_mode.rs`). Avoid copy-paste width math.

**§17 → this UC:** research listed Settings as “optional”; this UC **promotes** it to in-scope
(CRAFT-07 / C87) because unlocked toolbar soup is the second-largest craft defect after unlock
alignment. Unlock form (B0–B1) remains the first ship priority if the PR must split.

---

## 9. Open questions

1. **AccessKit:** enable in a follow-up UC or leave OFF until a11y milestone (research G4)?
2. **Unlock card chrome:** use `faint_bg_color` panel behind the form (Gestalt common region) or flat panel only? — currently flat; optional polish.

**Closed by implementation:** Settings = `egui::Window`; intent G19 promoted with ship; field fill = lighter + thin stroke (§5.3).

---

## 10. Deferred ledger

| ID | Item | Why deferred |
|----|------|--------------|
| DF-1 | SwiftUI / Liquid Glass | UC-18 P3 / research R3 |
| DF-2 | Vault Argon2 cancel UI | UC-26 DF-6 |
| DF-3 | Multi-volume list | UC-26 DF-7 |
| DF-4 | AccessKit default-on | Product/size tradeoff (G4) |
| DF-5 | eframe >0.29 for newer Visuals fields | Not required for craft |
| DF-6 | Custom embedded TTF beyond `default_fonts` | Only if glyph regression returns |
| DF-7 | Animated mode-switch fades | UC-26 motion note; optional polish |
| DF-8 | Peer pixel audit cookbook (R1) + Window styling notes (R2) | Optional PR attachments / docs |
| DF-9 | High-contrast OS smoke (R4) | A11y follow-up after theme change |

---

## 11. Changelog

| Date | Change |
|------|--------|
| 2026-07-29 | **Draft v0.1** — Visual craft contract from research §8/§13/§17/§19; candidate C82–C86; segments B0–B5 |
| 2026-07-29 | **Draft v0.2** — Spec↔research cross-check: H1–H7 map; §4 density/bands/gutters; §8.1 `FIELD_HEIGHT` + Add accent; §8.4 Workspace; §8.5 anti-patterns; §13.2 Spacing defaults table; §13.4 layout pattern normative; NIST + AccessKit OFF; Settings promoted (C87); `SETTINGS_CONTENT_MAX` / `WINDOW_GUTTER` / CRAFT-10…15; R1/R2/R4 deferred; §13 audit table |
| 2026-07-29 | **Implemented v1.0** — `apply_craft_style` + tokens; locked `form_card`; accent Create/Unlock/Add; Settings window; Workspace/Seal dialog accents; `uc27_constraints.rs` C82–C87; intent G19 / v1.9.4; ROADMAP S-26 |
| 2026-07-29 | **Impl↔spec cross-check** — CRAFT-06 first-run XOR form primary; CRAFT-08 dialog passphrase helpers + FORM_WIDTH; CRAFT-09/13 caption + path monospace; empty-state Add accent; §3.2 baseline refreshed |
| 2026-07-29 | **Impl↔spec pass 2** — CRAFT-02 confirm=`secret_field_width`; Workspace SPACE_* + `primary_button`; dialog/next-beat/keyfile enroll craft helpers; Lock=`secondary_button`; sealed DANGER |
| 2026-07-29 | **Three-way audit (code↔UC-27↔research)** — CRAFT-07 Seal→Workspace; CRAFT-16 accent/danger; editor Save accent + `danger_button`; dialog `SPACE_*`; §14 matrix |

---

## 12. Acceptance checklist (maintainer)

- [x] B0–B4 merged; tests green  
- [x] Unlock form: single trust line; aligned fields; accent primary  
- [x] Settings reachable; primary toolbar calm; Add accent  
- [x] Workspace home Create/Unlock accent  
- [x] UC-26 suites still PASS (incl. paste/show)  
- [x] No egui APIs beyond 0.29.1; no forbidden Visuals field names  
- [x] No `persistence` / no secrets in GUI  
- [x] Intent G19 C82–C87 promoted  
- [x] Spec status → **Implemented v1.0**

---

## 13. Research ↔ spec cross-check (Draft v0.2)

Audit of [`desktop_app_ui_ux_research.md`](../../research/desktop_app_ui_ux_research.md) against
Draft v0.1 → **closed in v0.2** unless noted.

| Research locus | Gap in Draft v0.1 | Resolution in v0.2 |
|----------------|-------------------|--------------------|
| §1 / §16 H1–H7 | Heuristics implied, not mapped | §4 problem list + §7.2 table |
| §4.1 gutters / three bands | Missing | CRAFT-10; `WINDOW_GUTTER` |
| §4.2 type ramp / single title | Weak | CRAFT-09, CRAFT-13, CRAFT-15 |
| §4.3 accent/warn/danger roles | Accent only | Token notes + CRAFT-04/11/12 |
| §4.4 density + Settings ~1000 | Missing | §5.2; `SETTINGS_CONTENT_MAX`; CRAFT-14 |
| §4.6 motion | Only deferred fade | §5.8 preserve 150–250 ms; no crypto anim |
| §4.7 NIST paste/show | WCAG only | Standards table + CRAFT-08 + smoke #4 |
| §5 peers (empty state, list align) | Thin | Prior art + list density note |
| §6 / §13.4 layout fix | Described loosely | Normative code pattern §5.4 |
| §8.1 `FIELD_HEIGHT` + **Add** accent | Missing | Tokens + CRAFT-11; C83 expands |
| §8.4 Workspace large CTAs | Dialog-only CRAFT-08 | CRAFT-12 |
| §8.5 anti-patterns | Non-goals partial | §5.9 table |
| §13.2 Spacing defaults / `button_padding` | Partial | §5.3 defaults table |
| §13.3 `faint_bg_color` card | Missing | Optional in B0; open Q #4 |
| §13.7 / §19 X2 AccessKit OFF | Non-goal only | Standards §2 reality note |
| §17 #6 Settings “optional” | CRAFT-07 required without note | §8: intentional promotion + C87 |
| §19 X1 forbidden APIs | Comment only | §5.3 forbidden list |
| §9 R1–R4 | Absent | §5.10 / DF-8/9 / §7.4 |
| §14 author checklist | One line | Kept; H-map carries weight |

**Intentional deltas from research (documented):**

1. Settings overflow is **in scope** (not optional) — C87 / CRAFT-07.  
2. Field fill recipe **decided** (lighter + stroke) — research left it open.  
3. R1 peer pixel audit is **not** a merge blocker.  
4. Research §8.3 “Lock + Seal” on one chrome row is **pre–mode-split**; with UC-26, Seal is Workspace-only (CRAFT-07).

---

## 14. Three-way audit — code ↔ UC-27 ↔ research (2026-07-29)

Sources: `theme.rs` / `main.rs` / `volume_gui.rs` / `sealed_gui.rs` · this spec ·
[`desktop_app_ui_ux_research.md`](../../research/desktop_app_ui_ux_research.md) §4 / §8 / §13 / §16 / §17 / §19.

| Locus | Research | Spec | Code | Verdict |
|-------|----------|------|------|---------|
| H1 / CRAFT-03 / C85 | One trust line | Required | Single `Local only…` in locked card | **PASS** |
| H2 / CRAFT-06 | First-run XOR form primary | Required | `if first_run` strip else accent Create/Unlock | **PASS** |
| H3 / CRAFT-01–02 / C82 | Aligned card + equal field widths | `form_card` + `secret_field_width` | Both helpers; confirm matches master | **PASS** |
| H4 / CRAFT-05 | No label==hint | Required | Hints `••••••••` only | **PASS** |
| H5 / CRAFT-04,11,12 / C83 | Accent Create/Unlock/Add | `primary_button` | Locked + Workspace + Add + dialogs | **PASS** |
| H6 / CRAFT-09,13 | Path caption weight | `vault_path_caption` / Small+weak | Helper + footer drop | **PASS** |
| H7 / CRAFT / C86 | Field chrome | `extreme_bg_color` + stroke | `AA_FIELD_*` | **PASS** |
| §4.1 bands / gutter | Chrome≠body≠footer; 16–24 gutter | CRAFT-10 / `WINDOW_GUTTER` | Locked bands + gutter | **PASS** |
| §4.3 Danger | Delete only | CRAFT-16 | `danger_button` on Delete/confirm | **PASS** |
| §4.3 / §8.1 Save | Primary of editor | CRAFT-16 | Save `fill(ACCENT)` | **PASS** |
| §4.4 Settings ~1000 | Fluent settings | CRAFT-14 / C87 | `SETTINGS_CONTENT_MAX` | **PASS** |
| §8.2 wireframe | FORM 420 card | CRAFT-01…15 | Matches (trust inside card) | **PASS** |
| §8.3 Seal on chrome | Pre-mode Lock+Seal | CRAFT-07 Workspace Seal | Seal on Workspace home | **PASS** (intentional delta) |
| §8.4 Workspace | Sparse large CTAs | CRAFT-12 | `HOME_CTA_W` + accent | **PASS** |
| §8.5 anti-patterns | No glass/dashboard | §5.9 | No violations found | **PASS** |
| §13.2 Spacing | Override defaults | C84 / `apply_craft_style` | item_spacing / interact_size.y / text_edit_width | **PASS** |
| §13.3 / §19 X1 | No forbidden Visuals | Forbidden list | No `text_edit_bg_color` / `weak_text_alpha` | **PASS** |
| §13.7 AccessKit OFF | OFF today | Non-goal | `default-features = false` | **PASS** |
| §17 checklist | 7 craft PR items | B0–B4 | All shipped; Settings in-scope | **PASS** |
| Goal 3 ad-hoc space | Tokens replace literals | CRAFT-08 dialogs | Dialogs + home use `SPACE_*`; dense list still has some literals | **PASS** with residual |
| R1 / G3 pixel audit | Optional | DF-8 | Not done | **Deferred** |
| DF-6 Argon2 cancel | Out of scope | Non-goal | Absent | **Deferred** |
| DF-7 multi-volume | Out of scope | Non-goal | Absent | **Deferred** |
| Faint unlock card | Optional | Open Q #4 | Not painted | **Open** |

**Ship gate:** research H1–H7 closed in code; UC-27 CRAFT-01…16 satisfied or intentionally deferred as above.
