# Desktop app UI/UX craft — full-stack research (classic → modern)

> **Task:** Survey **desktop application visual craft and interaction design** from early
> graphical desktops through 2025–2026 platform systems — layout, hierarchy, typography,
> spacing, density, materials, and peer product craft — so Blindkey’s `blindkey-gui` can look
> and feel like a finished product, not a wireframe.
>
> Research date: **2026-07-29**. Markers: ✓ verified this pass · ~ corroborated · ? assumed.
>
> **Where this sits in Blindkey research:**
> | Doc | Owns |
> |-----|------|
> | [`ui_architecture.md`](ui_architecture.md) | Toolkit / trust boundary (egui vs SwiftUI vs Tauri) |
> | [`desktop_security_ui_research.md`](desktop_security_ui_research.md) | Usable **security** IA, mental models, crypto honesty |
> | **This file** | Desktop craft **history** (§2–§11) + **Blindkey stack craft** (§12–§18): egui 0.29 / eframe / glow, official APIs, trusted authors → concrete widgets |
> | Spec [UC-26](../docs/specs/UC-26-desktop-ui-information-architecture.md) | Binding IA contract (modes, honesty, microcopy) |
> | Spec [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md) | Binding **craft** contract — **Implemented v1.0** / ROADMAP S-26 (C82–C87 PASS) |
>
> **Trigger:** Live `blindkey-gui` unlock/create screen (screenshot 2026-07-29) — readable fonts
> after UC-26, but **layout, hierarchy, and redundancy still look unfinished** (§1).
>
> **Stack pin (✓ workspace `Cargo.toml` + `Cargo.lock` 2026-07-29):** `eframe` / `egui`
> **0.29.1** resolved; features `glow`, `default_fonts`, `wayland`, `x11`; `default-features = false`
> (so upstream defaults like `accesskit` are **not** pulled unless re-enabled); **no** `persistence`.

---

## 0. Do we need this research?

**Short answer:** Yes as a **craft source of truth** for Blindkey desktop polish. No as a
**blocker** before fixing today’s screen.

| Need | Why |
|------|-----|
| **Yes — craft research** | UC-26 + `desktop_security_ui_research.md` fixed *legibility* and *security IA*. They did **not** fully specify *visual craft*: column width, label-field alignment, type ramp, spacing scale, primary vs secondary CTA weight, redundancy rules. The 2026-07-29 screenshot fails those craft rules. |
| **No — wait forever** | The worst defects on that screen are **known layout bugs** (mixed center/left alignment, duplicated trust copy, competing Create CTAs). Fixing them does not require reading Xerox PARC first. |
| **Yes — breadth** | “Best UI/UX for desktop” is not one fashion. Principles repeat from Star/Macintosh → Windows 95 → Aqua → Fluent/Adwaita → 2025 Liquid Glass. Encoding that lineage prevents chasing web trends that fight egui + C20. |

**ONE recommendation after this doc:**

> Implement via **[UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md)** (Draft) / ROADMAP **S-26** —
> the **§17 egui craft PR** (tokens + unlock card layout + one trust line + accent
> primary) using official egui `Style`/`Spacing`/`Visuals` and Nielsen #8 / Norman mapping —
> before any toolkit swap or more historical research.

---

## 1. Incident diagnosis — Blindkey unlock screen (2026-07-29)

Observed on macOS dark window (first-run create vault):

| Defect | Craft rule violated | Era that already solved it |
|--------|---------------------|----------------------------|
| “No account. No cloud.” **twice** + long trust sentence | Redundancy / cognitive load (GNOME “simple”; Apple writing) | Always — HIG writing guides |
| First-run **Create \| Open** *plus* form **Create vault** again | Two primaries for one task (Hick’s law; primary CTA uniqueness) | Macintosh / Windows dialog design |
| “Master password” **label** + same string as **hint_text** inside the field; field row **left-drifted** vs confirm | Duplicate chrome (Nielsen #8); label–control alignment / Fluent left-align | IBM CUA / Windows 95 property sheets |
| Confirm field centered while master field skewed | **Inconsistent alignment axis** — looks “broken,” not “minimal” | Xerox/Apple alignment discipline |
| Flat grey buttons, no primary weight vs secondary | Visual hierarchy (suggested vs default — GNOME/Adwaita; Accent — Fluent) | Aqua / Fluent accent |
| Uniform tiny type; path + footer compete with passphrase | Type ramp missing (Fluent Title/Body/Caption; Apple hierarchy) | Post-2010 systems |
| Dark-on-dark inputs (low non-text contrast) | WCAG 1.4.11 non-text contrast; Fluent stroke tokens | Accessibility era |

**Verdict:** Not “needs Liquid Glass.” Needs **form discipline + hierarchy**. egui can do that.

---

## 2. Timeless principles (older than any OS)

These predate modern HIGs and still judge Blindkey.

### 2.1 Perception (Gestalt)

| Principle | Desktop implication |
|-----------|---------------------|
| **Proximity** | Label sits **next to / immediately above** its field with small gap; group passphrase + confirm; separate trust footer with larger gap |
| **Similarity** | All text fields same width; all secondary buttons same style |
| **Continuity / common region** | One **card / panel** for the unlock form — not free-floating widgets on an infinite dark void |
| **Figure–ground** | Content lighter/stronger than chrome; or chrome clearly separated by stroke/fill |

### 2.2 Motor & choice

| Law | Desktop implication |
|-----|---------------------|
| **Fitts’s law** | Primary button large enough (≥24–28 px height — Blindkey already documents this); place near related fields |
| **Hick’s law** | First-run: **two** choices max at decision point; don’t also show a third competing Create below without clear framing |
| **Working-memory / chunking** | Trust message = **one** short line, not three near-duplicates. Classic Miller “7±2” is cited by Shneiderman; modern estimates are often ~4 chunks (Cowan) — either way, **don’t burn STM on redundant copy** (~) |

### 2.3 Interaction classics (Shneiderman / Nielsen — also in security research)

Consistency, feedback, closure, error prevention, recognition over recall, aesthetic **and**
minimalist design (minimal ≠ empty; means **no redundant chrome**).

✓ These are restated across Apple HIG, Fluent, and GNOME HIG for decades.

---

## 3. Historical eras of desktop UI (oldest → newest)

### Era A — Foundations (1970s–1984)

| Milestone | What entered craft DNA | Confidence |
|-----------|------------------------|------------|
| **Xerox PARC** (Alto, Star) | Windows, icons, menus, overlapping documents; desktop metaphor | ~ historical consensus |
| **Apple Lisa / Macintosh (1984)** | Menu bar, consistent dialogs, **direct manipulation**, Human Interface Guidelines as product doctrine | ✓ product history |
| **Early HIG idea** | User is in control; consistency across apps; see-and-point | ✓ |

**Take for Blindkey:** Consistency and direct manipulation beat clever one-off layouts.

### Era B — Productivity desktops (1985–1999)

| Milestone | Craft contribution | Confidence |
|-----------|-------------------|------------|
| **Windows 3.x / 95** | Dialog units, property sheets, **left-aligned labels + fields**, OK/Cancel order conventions | ✓ |
| **IBM CUA** | Cross-vendor dialog and menu conventions | ~ |
| **Motif / CDE (UNIX)** | Heavy bezels, 3D controls — “industrial” clarity over fashion | ~ |
| **Mac System 7–9** | Platinum appearance; clear default button ring | ✓ |

**Take for Blindkey:** Forms are a **column**: labels and fields share one left edge (or labels in a
narrow left column). Mixing centered headings with left-drifted fields is a 1995-era anti-pattern.

### Era C — Skeuomorphism & polish (2000–2012)

| Milestone | Craft contribution | Confidence |
|-----------|-------------------|------------|
| **Mac OS X Aqua** | Depth, primary button color, generous padding, “lickable” controls | ✓ |
| **Windows XP Luna → Vista Aero** | Themed chrome; glass/blur experiments; denser Office toolbars | ✓ |
| **Early iOS → Mac influence** | Larger hit targets, clearer primary actions | ✓ |

**Take for Blindkey:** Primary action must **look** primary (fill/accent), not identical to
“Choose vault file…”.

### Era D — Flat / Metro / Modern (2012–2017)

| Milestone | Craft contribution | Confidence |
|-----------|-------------------|------------|
| **Windows 8 Metro** | Typography-first, large touch tiles — over-corrected density for desktop | ✓ |
| **iOS 7 / flat Mac** | Reduced chrome; risk of **low contrast** and weak affordances | ✓ |
| **Material Design (Google)** | Elevation, FAB, motion — mobile-first; desktop ports often awkward | ~ |

**Take for Blindkey:** Flat is fine; **affordance** still required (clear field borders, button
states). Dark theme without strokes = “empty void,” not “premium.”

### Era E — Fluent / Big Sur / Adwaita (2017–2024)

| System | Core craft rules | Confidence |
|--------|------------------|------------|
| **Fluent Design → Fluent 2** | **4 px spacing ramp**; Segoe UI Variable type ramp; left-align body; proximity grouping; content basics spacing (8–16 epx common) | ✓ [Fluent layout](https://fluent2.microsoft.design/layout), [WinUI content basics](https://learn.microsoft.com/en-us/windows/apps/design/basics/content-basics) |
| **Apple HIG (pre–2025)** | Classic iOS design themes often summarized as **clarity / deference / depth**; macOS HIG emphasizes platform conventions, clarity of writing, sidebar+content productivity layouts; SF Pro | ~ iOS triad is widely cited; treat as **theme labels**, not a single macOS statute page |
| **GNOME HIG + libadwaita** | Simple, reduce effort, progressive disclosure; **AdwClamp** max content width; suggested/destructive button styles; adaptive breakpoints | ✓ [GNOME principles](https://developer.gnome.org/hig/principles.html), [adaptive](https://developer.gnome.org/hig/guidelines/adaptive.html) |

**Take for Blindkey:**

1. **Spacing scale** (4/8/12/16/24/32) — stop arbitrary `add_space` without a system.
2. **Clamp form width** (~400–480 px for unlock — already noted in UC-26 Fluent section).
3. **Suggested primary** vs quiet secondary.

### Era F — 2025–2026 platform refresh (current)

| System | What’s new | What Blindkey should **not** blindly copy |
|--------|------------|-------------------------------------------|
| **Apple Liquid Glass (WWDC25 / macOS Tahoe era)** | New design pillars often stated as **Hierarchy, Harmony, Consistency**; translucent functional layer for toolbars/sidebars; content canvas vs floating chrome | Full glass materials in **egui** — expensive, off-brand for a local vault, fights C20 thin shell. Steal **hierarchy**, not specular refraction. ✓ Apple newsroom / WWDC25 AppKit sessions (pillars ~ secondary writeups + WWDC) |
| **Fluent 2 maturation** | Tokenized spacing/type; denser productivity apps stay left-aligned | Don’t import web React Fluent into Rust GUI — import **tokens** |
| **GNOME Adwaita** | Clamp, adaptive dialogs, dark/light | Match **simplicity** and clamp; don’t require GTK |

**Take for Blindkey (2026):** On egui, win with **layout + type + accent**, not materials arms race.
Native SwiftUI shell (UC-18 P3) is where Liquid Glass belongs later.

---

## 4. Cross-cutting craft systems (what “modern desktop” actually means)

### 4.1 Layout

| Rule | Practice |
|------|----------|
| One alignment axis per region | Unlock card: **all** controls left-aligned to the same x, or true vertical stack with equal width |
| Max measure | Body text and forms ≈ 40–80 characters; unlock card **`FORM_WIDTH = 420`** (within UC-26 Fluent band **400–480** px) |
| Window regions | Title/status chrome ≠ form body ≠ footer hint — three bands with spacing |
| Gutters | 16–24 px from window edge to card; 8–12 px label→field |

### 4.2 Typography

| Level | Role | Blindkey mapping (egui) |
|-------|------|-------------------------|
| Display / Title | App name or screen title once | `heading("Blindkey")` **or** screen title — not both fighting |
| Body | Instructions | One instruction line |
| Caption / weak | Path, drop hint, trust | `weak()` only in footer band |
| Monospace | Paths only | vault path |

Fluent and Apple both insist: **hierarchy via size/weight**, not by repeating the same sentence.

### 4.3 Color & materials

| Role | Rule |
|------|------|
| Accent | One accent for primary CTA (Blindkey `theme::ACCENT` exists — **use it on Create/Unlock**) |
| Danger | Delete / destructive confirm only |
| Warn | Sync refuse, residual risk |
| Surfaces | Input fill ≠ panel fill (need visible field chrome) |
| Status | Never color alone (UC-26 IA-01) |

### 4.4 Density

| Context | Density |
|---------|---------|
| Unlock / create (focus task) | **Sparse** — generous vertical rhythm |
| Credentials list (mail-like) | **Medium** — virtualized rows (already UC-20) |
| Settings | Scrollable single column (~1000 px max content — Fluent settings pattern) |

### 4.5 Writing (UI copy craft)

Platform writing guides converge:

- Prefer **one** trust claim: “Local only. No account. No cloud.”
- Don’t restate the same fact in the next line.
- Buttons: verbs users do (“Create vault”, “Open existing…”) — already UC-26.
- Errors: specific, next-step — already microcopy table in UC-26.

### 4.6 Motion

150–250 ms fades for dialogs (UC-26). No continuous “crypto” animation (security research).
Modern Apple motion is richer; egui should stay **subtle**.

### 4.7 Accessibility (craft ∩ compliance)

| Standard | Craft implication |
|----------|-------------------|
| WCAG 2.2 AA 1.4.3 | Text contrast (UC-26 theme) |
| WCAG 1.4.11 | Input borders / icons ≥3:1 vs adjacent |
| WCAG 2.5.8 | Target size ≥24×24 (PRIMARY_BTN_HEIGHT) |
| NIST 800-63B-4 | Paste + show/hide on passphrases |

---

## 5. Peer desktop apps — visual craft (not just IA)

| App | What looks “finished” | Steal for Blindkey |
|-----|----------------------|--------------------|
| **Cryptomator** | Centered vault focus; big Unlock; clear locked/unlocked; spare chrome | Workspace home density |
| **KeePassXC** | Dense but **aligned** lists; consistent toolbar; left-nav mental model | Credentials list alignment |
| **1Password / Bitwarden desktop** | Search-first; strong primary; polished empty states | Empty state + search home |
| **Signal Desktop** | Thin chrome, content focus, restrained color | Calmness |
| **Finder / Files** | Path as secondary; actions near selection | Path as caption, not hero |

Security apps that feel cheap usually share Blindkey’s current failure: **unaligned forms + repeated marketing lines + no primary accent**.

---

## 6. Toolkit reality — egui / immediate mode

From [`ui_architecture.md`](ui_architecture.md): egui is the C20-aligned desktop shell today.

| egui strength | egui weakness | Craft mitigation |
|---------------|---------------|------------------|
| Fast to ship; Rust; no JS heap | Default widgets look “debug UI” | Custom sizing, Visuals, accent fills, consistent `desired_width` |
| Immediate mode = easy state | Easy to **accidentally** nest `horizontal` inside `vertical_centered` and break alignment | **One layout helper** for labeled fields |
| Cross-platform | Won’t match Liquid Glass | Don’t try; match **structure** of HIG |

**Critical implementation note (matches screenshot bug):**

```text
vertical_centered {
  label("Master password")           // centered
  horizontal { label; TextEdit; Show } // TextEdit starts at left of centered group → skew
}
```

Fix pattern:

```text
vertical_centered {
  // allocate a fixed-width column, then left-align inside it
  card_width = 420
  label (full width of card)
  TextEdit.desired_width(card_width - show_checkbox) + Show on same row
}
```

---

## 7. Platform HIG cheat-sheet (authoritative starting points)

| Platform | Start here | Steal for Blindkey egui |
|----------|------------|-------------------------|
| macOS | [Apple HIG](https://developer.apple.com/design/human-interface-guidelines/) · WWDC25 Liquid Glass / AppKit | Hierarchy, writing, default buttons; defer glass |
| Windows | [Fluent 2](https://fluent2.microsoft.design/) · [WinUI content basics](https://learn.microsoft.com/en-us/windows/apps/design/basics/content-basics) | 4 px spacing, type ramp, left-align forms |
| Linux (GNOME) | [GNOME HIG](https://developer.gnome.org/hig/) | Simplicity, clamp width, suggested buttons |
| Cross-cutting | Nielsen heuristics · WCAG 2.2 · ISO 9241-110/210 | Already partially in UC-26 / security research |

---

## 8. Blindkey desktop craft playbook (normative for next polish UC)

### 8.1 Design tokens (propose for `theme.rs`)

| Token | Value | Notes |
|-------|-------|-------|
| `SPACE_XS` | 4 | |
| `SPACE_S` | 8 | label→field |
| `SPACE_M` | 12 | related groups |
| `SPACE_L` | 16 | section break |
| `SPACE_XL` | 24 | band break |
| `FORM_WIDTH` | 420 | unlock/create card |
| `FIELD_HEIGHT` | ~28–32 | match PRIMARY_BTN_HEIGHT family |
| Primary CTA | filled `ACCENT` or strong egui fill | Create / Unlock / Add |
| Secondary CTA | quiet button | Choose vault file, Open existing (when not co-primary) |

### 8.2 Unlock / first-run layout (target wireframe)

```
┌─────────────────────────────────────────────┐
│ Blindkey                          · Locked  │  chrome band
├─────────────────────────────────────────────┤
│                                             │
│         ┌────── FORM 420 ──────┐            │
│         │ Local only. No       │            │  ONE trust line
│         │ account. No cloud.   │            │
│         │                      │            │
│         │ [ Create vault ]     │            │  first-run only:
│         │ [ Open existing… ]   │            │  OR unlock fields
│         │                      │            │
│         │ Create your vault —  │            │  one instruction
│         │ choose a strong…     │            │
│         │                      │            │
│         │ Master password      │            │  label above
│         │ [______________] Show│            │  field full card width
│         │ Confirm password     │            │
│         │ [______________]     │            │
│         │                      │            │
│         │ [   Create vault   ] │            │  ONE primary (accent)
│         │ Choose vault file…   │            │  text/secondary
│         │ ~/…/vault.vlt        │            │  caption
│         └──────────────────────┘            │
│                                             │
│ Drop a file… (footer caption)               │
└─────────────────────────────────────────────┘
```

Rules:

1. **No duplicate** “No account. No cloud.”
2. First-run CTAs **or** inline Create primary — if both exist, first-run CTAs dismiss into form and **disappear**.
3. Every field: label above, control width = `FORM_WIDTH` (Show shares the row without skewing the column).
4. Path + “Stored only…” = one caption block.

### 8.3 Unlocked chrome

- Left: brand + mode switch + status text.
- Right (Credentials): Lock (quiet) + **Settings…** — pad/auto-lock/clipboard/blur/audit/keyfile/import live in Settings (UC-27).
- **Seal** is Workspace-mode (UC-26), not a Credentials toolbar peer — do not put Seal next to Lock on the credential chrome.
- Color roles (§4.3): Accent = Create/Unlock/Add/Save; Danger = Delete only.

### 8.4 Workspace

Keep Cryptomator sparsity (security research). Large Create/Unlock. Seal secondary. Status Locked/Unlocked/Mounted.

### 8.5 What not to do in egui v1

- ❌ Fake Liquid Glass blur stacks
- ❌ Marketing gradients / purple AI aesthetic
- ❌ Dashboard cards with stats
- ❌ Center-aligning **only some** controls in a form

---

## 9. Research gaps / follow-ups

| ID | Item | Notes |
|----|------|-------|
| R1 | Side-by-side pixel audit: KeePassXC vs Cryptomator vs Blindkey unlock | Screenshots in PR |
| R2 | egui `Window`/`Panel` styling cookbook | Implementation notes under `docs/` when coding |
| R3 | SwiftUI shell craft (Liquid Glass) | UC-18 P3 — after egui craft pass |
| R4 | High-contrast / increased contrast macOS smoke | A11y |

---

## 10. Sources (selected)

### Historical / classic

- Apple Human Interface Guidelines (classic Macintosh through modern) — product doctrine lineage
- Microsoft Windows UX / Win32 dialog conventions; CUA influence
- Shneiderman, *Designing the User Interface*; Nielsen Norman Group heuristics

### Modern platform (✓ checked 2026-07-29)

- [Fluent 2 Layout](https://fluent2.microsoft.design/layout) — 4 px spacing, proximity
- [WinUI content layout and spacing](https://learn.microsoft.com/en-us/windows/apps/design/basics/content-basics)
- [WinUI typography / Segoe UI Variable](https://learn.microsoft.com/en-us/windows/apps/design/signature-experiences/typography)
- [GNOME HIG design principles](https://developer.gnome.org/hig/principles.html)
- [GNOME adaptive / scaling](https://developer.gnome.org/hig/guidelines/adaptive.html)
- Apple WWDC25 — Liquid Glass / AppKit new design (hierarchy, harmony, consistency; materials for **native** chrome)
- Apple Newsroom 2025-06 — Liquid Glass introduction

### Blindkey companions

- [`desktop_security_ui_research.md`](desktop_security_ui_research.md)
- [`ui_architecture.md`](ui_architecture.md)
- [UC-26](../docs/specs/UC-26-desktop-ui-information-architecture.md)
- [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md) (craft implementation contract)

### Standards

- WCAG 2.2 · NIST SP 800-63B-4 · ISO 9241-110 / 9241-210

---

## 11. Changelog

| Date | Change |
|------|--------|
| 2026-07-29 | Initial full-stack desktop craft research (eras A–F, tokens, Blindkey playbook, screenshot diagnosis) |
| 2026-07-29 | **Stack expansion** — §§12–18: Blindkey egui/eframe inventory; official Style/Spacing/Visuals/Ui APIs; Nielsen / Shneiderman / Norman / Tog / Johnson / Krug mapped to widgets; HIG→egui translation; AccessKit; IMM vs retained; anti-patterns for our unlock screen |
| 2026-07-29 | **Source cross-check** — §19 audit; fix egui **0.29.1** API drift (`text_edit_bg_color` etc.); accesskit OFF; Apple HIG pillar wording; FORM_WIDTH vs UC-26; hint_text diagnosis; Spacing defaults |
| 2026-07-29 | **Spec promotion** — craft checklist → [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md) Draft v0.1 + ROADMAP S-26 |
| 2026-07-29 | **Spec↔research cross-check** — UC-27 **Draft v0.2** closes gaps (H1–H7 map, density/bands, FIELD_HEIGHT, Add/Workspace accent, §8.5 anti-patterns, Spacing defaults, AccessKit OFF, Settings→C87, R1–R4 deferred) |

---

# Part II — Blindkey stack craft (official sources + trusted authors)

> Scope of Part II: **only** what applies to shipping `blindkey-gui` on **egui 0.29.1 + eframe 0.29.1 +
> glow**, under Blindkey constraints C20/C41/C27. Platform HIGs are **translated** into egui
> primitives — not copied as native AppKit/WinUI code.

---

## 12. Blindkey GUI stack inventory (source of truth)

### 12.1 Dependencies (✓ verified workspace)

| Crate | Pin | Role | Official docs |
|-------|-----|------|---------------|
| **eframe** | **0.29.1** | Native window + event loop + `App::update` | [docs.rs/eframe/0.29.1](https://docs.rs/eframe/0.29.1/eframe/) |
| **egui** | **0.29.1** | Immediate-mode widgets, layout, style | [docs.rs/egui/0.29.1](https://docs.rs/egui/0.29.1/egui/) · [github.com/emilk/egui](https://github.com/emilk/egui) |
| **glow** | via eframe feature | OpenGL painter (UC-20 / C41 — no wgpu unless deliberate) | eframe feature docs |
| **rfd** | (gui crate) | Native file dialogs | — |
| **blindkey-core / clip / hardware** | path deps | Secrets never reimplemented in UI (C45) | intent |

### 12.2 eframe feature posture (✓ official feature list)

From eframe 0.29 docs:

| Feature | Blindkey | Why |
|---------|----------|-----|
| `default_fonts` | **ON** | C75 — embed fonts when `default-features = false` |
| `glow` | **ON** | UC-20 painter pin |
| `wayland` / `x11` | **ON** | Linux |
| `persistence` | **OFF** | C41 — do not restore unlocked UI state from disk |
| `accesskit` | **OFF** (✓) | Upstream **default** feature, but Blindkey sets `default-features = false` and does **not** re-enable `accesskit` — not in `Cargo.lock`. Optional later a11y enable is a deliberate feature add, not “already on.” |
| `wgpu` | OFF | stick to glow unless UC changes |

Official startup hook (eframe docs — customize in `CreationContext`):

```text
cc.egui_ctx.set_visuals(...)
cc.egui_ctx.set_fonts(...)   // only if default_fonts insufficient
cc.storage                     // Blindkey: do not use for vault session (C41)
```

Blindkey already calls `theme::apply_aa_visuals` at startup (`theme.rs`).

### 12.3 Modules that own craft

| Path | Owns |
|------|------|
| `crates/blindkey-gui/src/theme.rs` | Colors, `PRIMARY_BTN_HEIGHT`, `apply_aa_visuals` |
| `crates/blindkey-gui/src/main.rs` | Unlock/create, unlocked chrome, credentials |
| `crates/blindkey-gui/src/volume_gui.rs` | Workspace Cryptomator-class UI |
| `crates/blindkey-gui/src/sealed_gui.rs` | Seal / open dialogs |
| `crates/blindkey-gui/src/gui_mode.rs` | Credentials \| Workspace |

### 12.4 Layout primitives actually used today (✓ ripgrep)

| Pattern | Where | Craft risk |
|---------|-------|------------|
| `CentralPanel` + `vertical_centered` | Locked unlock screen | Easy to mix centered labels with left-skewed `horizontal` rows → **screenshot bug** |
| `TopBottomPanel` top/bottom | Unlocked chrome + status | Good band structure |
| `Grid::new("detail"|"editor")` | Entry detail / editor | Prefer for label\|field pairs |
| `desired_width(280..320)` | Fields | Inconsistent widths; should be `FORM_WIDTH` token |
| `with_layout(right_to_left)` | Toolbar | Fine for Lock/Seal cluster |
| `set_max_width(460)` | Residual banner | Correct clamp pattern — **reuse on unlock card** |

---

## 13. Official egui / eframe API map (craft levers)

Sources: egui 0.29 `Style`, `Spacing`, `Visuals`, `Ui` docs (docs.rs); emilk/egui README (customization via `Context::set_style` / `set_visuals`).

### 13.1 Global style — `egui::Style`

| Field | Craft use for Blindkey |
|-------|------------------------|
| `spacing: Spacing` | **System spacing** — replace ad-hoc `add_space(6/10/14)` |
| `text_styles: BTreeMap<TextStyle, FontId>` | Type ramp: Heading / Body / Small / Monospace |
| `visuals: Visuals` | Dark theme fills, strokes, warn/error colors |
| `animation_time` | Keep short (UC-26 150–250 ms class) |
| `override_text_color` | Already used in `apply_aa_visuals` for AA text |

Set globally: `ctx.set_style(...)` or mutate `ctx.style_mut(|s| ...)`.  
Scoped: `ui.scope(|ui| { ui.style_mut()... })` (official `Ui` docs).

### 13.2 Spacing — `egui::style::Spacing` (✓ fields from 0.29.1 source)

Default (egui 0.29.1 `Default for Spacing`): `item_spacing = (8, 3)`, `interact_size = (40, 18)`,
`text_edit_width = 280`. Blindkey’s taller primaries already bypass `interact_size.y` via
`add_sized(..., PRIMARY_BTN_HEIGHT)`; craft pass should still raise vertical rhythm intentionally.

| Field | Proposed Blindkey mapping |
|-------|---------------------------|
| `item_spacing` | e.g. `(8, 8)` — keep Fluent-ish horizontal 8; increase Y vs default 3 |
| `button_padding` | Comfortable primary CTAs |
| `interact_size` | Keep x≈40; set y to match `PRIMARY_BTN_HEIGHT` (28) so bare buttons aren’t 18 px tall |
| `text_edit_width` | Align with `FORM_WIDTH` (420) so bare `TextEdit` isn’t stuck at default **280** |
| `window_margin` / `menu_margin` | Dialog breathing room |
| `indent` | Advanced collapsing content |

**Official meaning:** “Controls the sizes and distances between widgets.” — treat as the Fluent **4 px ramp** implementation surface inside egui (Fluent’s base unit is official; egui’s defaults are not a 4 px grid by themselves).

### 13.3 Visuals — `egui::Visuals` (✓ egui **0.29.1** struct — not newer docs.rs “latest”)

Blindkey already sets (`theme.rs`): `override_text_color`, `window_fill`, `panel_fill`,
`extreme_bg_color`, `faint_bg_color`, widget `fg_stroke`, `selection`, `hyperlink_color`,
`warn_fg_color`, `error_fg_color`.

**Pin-correct affordance levers (0.29.1):**

| Lever | Why it matters |
|-------|----------------|
| `extreme_bg_color` | egui dark theme comments this as **TextEdit background** — must contrast `panel_fill` / `window_fill` (Norman signifier; WCAG 1.4.11). Blindkey sets it but may still be too close to panel. |
| `window_stroke` | Window edge chrome |
| `widgets.*.bg_stroke` / `bg_fill` / `weak_bg_fill` | Field/button chrome + hover states (`WidgetVisuals` in 0.29.1) |
| `Button::fill(ACCENT)` | ✓ Official 0.29.1 API — primary CTA weight (note: overrides hover fill) |
| `faint_bg_color` | Optional card/panel behind unlock form (common region) |
| `ui.weak(...)` | Caption hierarchy for path / drop hint (**not** `Visuals.weak_text_alpha` — that field is **not** on 0.29.1 `Visuals`) |

**Do not cite for this pin:** `text_edit_bg_color`, `weak_text_alpha`, `window_corner_radius`
(those names appear on **newer** egui than 0.29.1; 0.29.1 uses `window_rounding`).

### 13.4 Layout — `Ui` methods (✓ official docs)

| API | Official behavior | Blindkey rule |
|-----|-------------------|---------------|
| `ui.vertical` | **Left-justified** vertical stack | Prefer **inside** a fixed-width card |
| `ui.vertical_centered` | Centers children horizontally | Use to center the **card**, not each label/field independently |
| `ui.horizontal` | Centers children on Y; initial height = `interact_size.y` | Pair Show checkbox with field **inside card width** |
| `ui.horizontal_top` | No vertical centering | Prefer when mixing labels + fields |
| `ui.with_layout(Layout::…)` | Take remaining space; RTL toolbars | Unlocked chrome OK |
| `ui.set_max_width(w)` | Clamp | Unlock form `FORM_WIDTH` |
| `Grid` | Label \| control columns | Editor already uses; unlock should too **or** label-above with equal widths |
| `collapsing` | Progressive disclosure | Volume Advanced… — keep |

**Root cause of screenshot skew (stack-specific):**

```text
vertical_centered {                    // centers each child as a group
  label("Master password")             // centered text block
  horizontal {                         // group centered as a whole, but
    TextEdit.desired_width(280)        //   field is left edge of THAT group
    checkbox("Show")                   //   → looks left-drifted vs confirm field alone
  }
  TextEdit confirm desired_width(320)  // different width + different nesting → misaligned
}
```

**Official-aligned fix:**

```text
vertical_centered {
  ui.set_max_width(FORM_WIDTH);
  ui.vertical(|ui| {                   // left-justify INSIDE centered clamp
    ui.label("Master password");
    ui.horizontal(|ui| {
      ui.add(TextEdit::...desired_width(FORM_WIDTH - SHOW_W));
      ui.checkbox(...);
    });
    ui.label("Confirm password");
    ui.add(TextEdit::...desired_width(FORM_WIDTH));
    // primary Button::new(...).fill(ACCENT) sized to FORM_WIDTH
  });
}
```

### 13.5 Panels & windows (eframe/egui)

| API | Use |
|-----|-----|
| `TopBottomPanel::top/bottom` | Chrome + status (already) |
| `CentralPanel` | Mode content |
| `egui::Window` | Dialogs (seal, volume, editor) — one primary + Cancel (UC-26 IA-07) |
| `Frame` / `ui.group` | Optional card chrome around unlock form |

### 13.6 Fonts (official)

- eframe: `default_fonts` bundles fonts via `include_bytes!` when enabled.
- egui: custom fonts via `Context::set_fonts` if hosts still blank (INSTALL.md note).
- Blindkey: **keep `default_fonts`**; do not re-disable.

### 13.7 Accessibility (official eframe + Blindkey reality)

- Upstream eframe **default** features include `accesskit` (“Enable platform accessibility API
  implementations through AccessKit.”).
- Blindkey: `default-features = false` **without** re-adding `accesskit` → AccessKit **not** in
  the dependency graph today (✓ `Cargo.lock` has no `accesskit`).
- Visible `ui.label` before every `TextEdit` remains mandatory (C54) whether or not AccessKit is
  enabled later.
- Gap / follow-up: enabling `accesskit` is a **product decision** (binary size / platform testing),
  not assumed present.

### 13.8 Immediate mode implications (emilk/egui README)

Official disadvantage: sizing dialogs may take a frame. egui caches size. **Craft implication:** don’t fight it with multi-pass custom layout; use `set_max_width` + consistent `desired_width`.

Persistence: official `cc.storage` requires `persistence` feature — **Blindkey must not enable** for vault session (C41). `GuiConfig` file for preferences is separate and OK.

---

## 14. Trusted authors → Blindkey egui (primary sources)

Only authors with **citable primary pages / editions**. Mapped to **what we change in code**.

### 14.1 Jakob Nielsen — 10 Usability Heuristics (1994; NN/g page current)

✓ Primary: [nngroup.com/articles/ten-usability-heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/)  
Origin: Molich & Nielsen 1990; refined Nielsen CHI’94 factor analysis of 249 problems.

| # | Heuristic | Blindkey / egui action |
|---|-----------|-------------------------|
| 1 | Visibility of system status | Keep `Status: Locked/Unlocked/Mounted` every frame (UC-26); progress windows for seal/volume |
| 2 | Match system ↔ real world | Human verbs (Unlock, Seal files) — not VLTF/VLTD as button text (C78) |
| 3 | User control and freedom | Cancel on every dialog; Lock always reachable; no wizard traps (IA-07) |
| 4 | Consistency and standards | Same `FORM_WIDTH`, same Show pattern, same mismatch string across vault/volume/seal |
| 5 | Error prevention | Confirm delete; passphrase match before write; Save disabled if title empty |
| 6 | Recognition rather than recall | Mode labels visible; search hint; don’t hide Lock |
| 7 | Flexibility and efficiency | ⌘K search; keyboard submit on unlock; experts: Audit, keyfile behind Advanced |
| 8 | Aesthetic and minimalist design | **Delete duplicate trust lines**; one primary CTA — NN/g: extra units compete for attention |
| 9 | Error recognition / recovery | Plain errors + next step (vault unlock microcopy; C74 volume) |
| 10 | Help and documentation | First-run ≤15 s; hover tooltips; INSTALL — not a tutorial wall |

**Screenshot fails #8 hardest** (redundant copy) and **#4** (inconsistent alignment).

### 14.2 Ben Shneiderman — Eight Golden Rules

✓ Primary: [cs.umd.edu/~ben/goldenrules.html](https://www.cs.umd.edu/~ben/goldenrules.html)  
Book: *Designing the User Interface*, 6th ed. (Pearson, 2016), §3.3.4.

| Rule | Blindkey mapping |
|------|------------------|
| 1 Consistency | Spacing tokens + field widths + button hierarchy |
| 2 Universal usability | Show/hide + paste (NIST); large targets (IA-08); AccessKit **optional** (not enabled in Blindkey pin today — §12.2) |
| 3 Informative feedback | “Entry saved.” / unlock success / “Copied. Clipboard clears in Ns.” |
| 4 Closure | IA-12 closures; Eject message; seal progress Done |
| 5 Prevent errors | Weak-password gate; sync-root refuse; confirm match |
| 6 Easy reversal | Cancel jobs; editor Cancel |
| 7 Users in control | No auto-mount; no auto-unlock; Lock on blur optional |
| 8 Reduce STM load | Don’t make users remember Dropbox warning — show Seal CTA in place. Prefer **visible state** over recalled warnings (Shneiderman STM rule; Cowan ~4 chunks nuance in §2.2) |

### 14.3 Don Norman — *The Design of Everyday Things*

✓ Primary concepts (revised editions): **affordances, signifiers, mapping, feedback, conceptual model, constraints**.

| Concept | Unlock screen application |
|---------|---------------------------|
| **Signifier** | Text fields need visible fill/stroke — dark-on-dark fails. On **0.29.1** tune `extreme_bg_color` (TextEdit bg) and `widgets.*.bg_stroke`, not a non-existent `text_edit_bg_color` |
| **Mapping** | Label directly above its field; Show next to the field it affects |
| **Feedback** | Strength meter on create; errors under the form |
| **Conceptual model** | First-run: Create vs Open — then **one** create form, not two Create buttons competing |
| **Constraints** | Disable Create until confirm matches / non-empty (optional progressive enable) |

### 14.4 Bruce Tognazzini — First Principles of Interaction Design

✓ Primary: [asktog.com/atc/principles-of-interaction-design](https://asktog.com/atc/principles-of-interaction-design/)  
(Apple HI alumni; Fitts, latency, aesthetics, discoverability, simplicity.)

| Principle (Tog) | egui practice |
|-----------------|---------------|
| **Fitts’s Law** | Large primary `add_sized([FORM_WIDTH, PRIMARY_BTN_HEIGHT], …)` |
| **Latency reduction** | Worker threads for seal/volume; DF-6 vault Argon2 still blocks UI |
| **Feedback** | Immediate `status` / `error` labels |
| **Discoverability** | First-run CTAs; mode switch labels |
| **Simplicity** | Strip duplicate trust copy |
| **Aesthetics** | Accent primary; card clamp; not “debug grey soup” |
| **Protect users’ work** | Atomic saves in core; Cancel leaves disk unchanged on jobs |

### 14.5 Jeff Johnson — *Designing with the Mind in Mind*

✓ Morgan Kaufmann, 3rd ed. 2020 — psychology behind guidelines (perception, memory, attention).

- Vision is optimized for **structure** — alignment bugs read as “broken,” not “minimal.”
- Working memory is tiny — redundant sentences burn attention.
- Color alone is weak for status — keep text status (IA-01).

### 14.6 Steve Krug — *Don’t Make Me Think*

✓ Practitioner classic. Don’t make users wonder whether Create (top) or Create (below) is the real action.

### 14.7 Usable-security authors (vault context)

Deep coverage in [`desktop_security_ui_research.md`](desktop_security_ui_research.md): Whitten & Tygar; Chiasson; Yee (*Expected Ability* → C79); Klivan SOUPS 2023. Part II adds **egui visual craft**, not a second security IA.

### 14.8 Alan Cooper — *About Face*

~ Goal-directed design / eliminate **excise**. Unlock goal = create or open vault — remove duplicate copy and competing CTAs.

---

## 15. Official platform HIGs → egui translation layer

We cannot ship AppKit/WinUI widgets inside C20 egui. We **can** steal measurable rules.

### 15.1 Microsoft Fluent 2 / WinUI (official)

Sources: [fluent2.microsoft.design/layout](https://fluent2.microsoft.design/layout), [WinUI content basics](https://learn.microsoft.com/en-us/windows/apps/design/basics/content-basics).

| Official rule | egui implementation |
|---------------|---------------------|
| 4 px spacing base | `Spacing.item_spacing` + `SPACE_*` in `theme.rs` |
| Left-align body text | `ui.vertical` inside clamped card |
| 8 epx between related; 12–16 between groups | `add_space` only from scale |
| Type ramp | `TextStyle::Heading/Body/Small` via `style.text_styles` |
| Primary accent | `Button::fill(ACCENT)` or visuals scope |

### 15.2 Apple HIG + 2025 Liquid Glass (official)

Sources: [Apple HIG](https://developer.apple.com/design/human-interface-guidelines/); WWDC25 AppKit / Liquid Glass.

| Steal | Skip on egui v1 |
|-------|-----------------|
| Hierarchy / clear default action / short writing (HIG + 2025 Hierarchy·Harmony·Consistency themes) | Translucent Liquid Glass materials, specular toolbars |
| One primary button per dialog | Native sidebar glass |

SwiftUI/AppKit = UC-18 P3 when Liquid Glass matters.

### 15.3 GNOME HIG + libadwaita (official)

Source: [developer.gnome.org/hig](https://developer.gnome.org/hig/).

| Steal | egui |
|-------|------|
| Simplicity / reduce effort | Fewer chrome controls; Settings overflow |
| Progressive disclosure | `collapsing("Advanced…")` |
| Suggested vs destructive | Accent fill vs `DANGER` |
| Clamp content width | `ui.set_max_width(FORM_WIDTH)` |

### 15.4 W3C WCAG 2.2 (official)

| SC | egui check |
|----|------------|
| 1.4.3 Contrast | `AA_FG` / `AA_BG` |
| 1.4.11 Non-text | Input chrome: `extreme_bg_color` ≠ `panel_fill`; visible `bg_stroke` where needed |
| 2.5.8 Target size | `PRIMARY_BTN_HEIGHT >= 24` |
| 3.3.8 Accessible auth | Paste + Show |

---

## 16. Heuristic evaluation of current unlock UI (stack + authors)

| ID | Finding | Source lens | Fix class |
|----|---------|-------------|-----------|
| H1 | Duplicate “No account. No cloud.” | Nielsen #8; Krug | Delete one |
| H2 | Create vault as first-run **and** form primary | Nielsen #8; Hick; Cooper | After dismiss, only form primary |
| H3 | Master field row misaligned vs confirm | Norman mapping; Fluent; egui misuse | §13.4 pattern |
| H4 | `label("Master password")` + `.hint_text("Master password")` duplicates | Nielsen #8 | Keep label; use empty or shorter hint |
| H5 | Primary not visually primary | Fluent/GNOME suggested | `Button::fill(ACCENT)` (✓ 0.29.1) |
| H6 | Path competes with passphrase | Johnson attention | Caption via `ui.weak` + Small style |
| H7 | Low-contrast inputs | Norman signifier; WCAG 1.4.11 | Tune `extreme_bg_color` + strokes |

---

## 17. Implementation checklist (egui craft — **shipped UC-27**)

Status **2026-07-29** (three-way audit code ↔ UC-27 ↔ this research):

1. **Done** — Tokens in `theme.rs`: `FORM_WIDTH`, `SPACE_*`; `apply_craft_style` for
   `Spacing` + `extreme_bg_color` / strokes (egui **0.29.1**).
2. **Done** — Locked form rewritten per §13.4 (`form_card` + secret-row helpers).
3. **Done** — One trust line (Nielsen #8 / H1).
4. **Done** — Accent Create/Unlock/Add (+ editor Save); Danger Delete (`danger_button`).
5. **Done** — Field widths unified; hints ≠ labels.
6. **Done** — Settings overflow (promoted in-scope by UC-27 / C87 — was “optional” here).
7. **Done** — `uc27_constraints.rs` + uc26 suites green.

Out of scope still: SwiftUI, Liquid Glass, multi-volume list (DF-7), vault Argon2 cancel (DF-6),
AccessKit enable (G4), peer pixel audit (R1).

---

## 18. Annotated bibliography (stack expansion)

### Official / primary (toolkit)

| Source | URL | Use |
|--------|-----|-----|
| egui 0.29 | https://docs.rs/egui/0.29.1/egui/ | Widgets, `Ui`, style |
| egui `Style` | https://docs.rs/egui/0.29.1/egui/style/struct.Style.html | Global look-and-feel |
| egui `Spacing` | https://docs.rs/egui/0.29.1/egui/style/struct.Spacing.html | Distances / interact_size |
| egui `Visuals` **0.29.1** | https://docs.rs/egui/0.29.1/egui/style/struct.Visuals.html | Colors, strokes, `extreme_bg_color` (TextEdit bg) — **not** later-only fields |
| eframe 0.29 | https://docs.rs/eframe/0.29.1/eframe/ | Features, `CreationContext` |
| emilk/egui README | https://github.com/emilk/egui | IMM tradeoffs; `set_style` |

### Official / primary (platform & a11y)

| Source | URL | Use |
|--------|-----|-----|
| Fluent 2 Layout | https://fluent2.microsoft.design/layout | 4 px ramp |
| WinUI content basics | https://learn.microsoft.com/en-us/windows/apps/design/basics/content-basics | Spacing numbers |
| GNOME HIG principles | https://developer.gnome.org/hig/principles.html | Simplicity |
| Apple HIG | https://developer.apple.com/design/human-interface-guidelines/ | Writing, hierarchy |
| WCAG 2.2 | https://www.w3.org/TR/WCAG22/ | Contrast, targets |

### Trusted authors (primary)

| Author | Work | URL / citation |
|--------|------|----------------|
| Jakob Nielsen | 10 Usability Heuristics | https://www.nngroup.com/articles/ten-usability-heuristics/ |
| Ben Shneiderman et al. | Eight Golden Rules; *DTUI* 6e | https://www.cs.umd.edu/~ben/goldenrules.html |
| Don Norman | *The Design of Everyday Things* | Book (Basic Books / revised eds.) |
| Bruce Tognazzini | First Principles of Interaction Design | https://asktog.com/atc/principles-of-interaction-design/ |
| Jeff Johnson | *Designing with the Mind in Mind* 3e | Morgan Kaufmann, 2020 |
| Steve Krug | *Don’t Make Me Think* | Book (New Riders) |
| Alan Cooper et al. | *About Face* | Book (interaction design) |

### Blindkey companions

- Intent C20, C27, C40–C54, C75–C81
- [`ui_architecture.md`](ui_architecture.md) · [`desktop_security_ui_research.md`](desktop_security_ui_research.md) · UC-26 · [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md)

---

**Part II ONE recommendation (post UC-27 ship):**

> Treat unlock/create craft as **done**. Next visual spend is optional only: R1 peer pixel
> audit, AccessKit enable (G4), or UC-26 DF-6 Argon2 cancel UI — not another unlock rewrite.

---

## 19. Source cross-check audit (2026-07-29)

Checked claims against **Blindkey tree**, **Cargo.lock**, **egui/eframe 0.29.1 crate sources**,
NN/g heuristics page, Shneiderman golden-rules page, Fluent/GNOME official pages, and WWDC25 /
Apple newsroom summaries.

| ID | Issue | Severity | Resolution |
|----|-------|----------|------------|
| X1 | Cited `Visuals.text_edit_bg_color` / `weak_text_alpha` as craft levers | **High** — wrong for pin | Use `extreme_bg_color` + `WidgetVisuals` strokes; `ui.weak()` for captions (§13.3) |
| X2 | Said AccessKit “default on / leave available” | **High** — false for Blindkey | Document **OFF** with `default-features = false` (§12.2, §13.7) |
| X3 | “Master password label beside field” | **Med** — inaccurate vs code | Code is `label` + duplicate `hint_text` (§1, H4) |
| X4 | Apple “clarity/deference/depth” stated as if one eternal HIG statute | **Med** | Split classic iOS triad (~) vs 2025 Hierarchy/Harmony/Consistency (§3 Era E/F, §15.2) |
| X5 | FORM width 400–440 vs UC-26 400–480 vs token 420 | **Low** | Canonical **420** inside UC-26 band (§4.1, §8) |
| X6 | Version said `0.29` only | **Low** | Lock resolves **0.29.1** (header, §12) |
| X7 | Spacing proposals ignored egui defaults `(8,3)` / `interact_size.y=18` / `text_edit_width=280` | **Med** | Document defaults + intentional overrides (§13.2) |
| X8 | Miller 7±2 as load-bearing without nuance | **Low** | Reframe as working-memory/chunking; Cowan ~ (§2.2) |
| X9 | Shneiderman “universal usability → AccessKit” implied present | **Med** | Mark AccessKit optional / not enabled (§14.2) |
| X10 | `Button::fill` | OK | ✓ exists in egui 0.29.1 |
| X11 | Nielsen 10 names / order | OK | ✓ matches NN/g current page |
| X12 | Shneiderman 8 rule titles | OK | ✓ matches cs.umd.edu goldenrules page |
| X13 | Fluent 4 px base / WinUI spacing examples | OK | ✓ Fluent layout + content-basics pages |
| X14 | GNOME simplicity / AdwClamp | OK | ✓ GNOME HIG pages |
| X15 | eframe `persistence` / `default_fonts` feature semantics | OK | ✓ eframe 0.29.1 Cargo.toml features |
| X16 | TextEdit bg = `extreme_bg_color` | OK | ✓ egui 0.29.1 `style.rs` dark-theme comment |

**Remaining honest gaps (not errors):**

| Gap | Notes |
|-----|-------|
| G1 | Apple HIG live pages often JS-gated in fetchers — Liquid Glass pillar wording marked ~ where only secondary/WWDC summaries available |
| G2 | Norman / Krug / Cooper / Johnson are **books** — mapped by well-known concepts, not page-quoted line numbers |
| G3 | No pixel audit vs KeePassXC/Cryptomator screenshots yet (R1) |
| G4 | Enabling AccessKit still open product choice |
