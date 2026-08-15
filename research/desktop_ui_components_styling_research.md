# Desktop UI components & styling — polished app research

> **Task:** Survey **component-level** and **styling-level** craft that makes desktop apps
> feel finished — cards, buttons, fields, lists, chrome panels, elevation, tokens — from
> **official platform design systems**, **trusted community write-ups**, and **public OSS
> repos**, then map what Blindkey’s egui shell already has vs what still reads as “wireframe.”
>
> Research date: **2026-07-30** (initial + expansion + **source cross-check §16**). Markers:
> ✓ verified this pass · ~ corroborated · ? assumed.
>
> **Trigger:** Live smoke of UC-27 craft (2026-07-30). Unlock/create form now has accent
> primary and aligned fields, but the window still feels sparse / non-native — “no navigation,”
> floating controls on a flat panel, empty lower canvas.
>
> **Where this sits:**
>
> | Doc | Owns |
> |-----|------|
> | [`desktop_app_ui_ux_research.md`](desktop_app_ui_ux_research.md) | History, heuristics H1–H7, unlock wireframe, Spacing/`Visuals` craft (UC-27) |
> | [`desktop_security_ui_research.md`](desktop_security_ui_research.md) | Security IA — modes, mount honesty, Cryptomator mental model |
> | [`ui_architecture.md`](ui_architecture.md) | Toolkit trust boundary (egui vs SwiftUI; C20) |
> | **This file** | **Components + styling systems** — what polished shells are *made of* |
> | Specs | [UC-26](../docs/specs/UC-26-desktop-ui-information-architecture.md) · [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md) · **[UC-28](../docs/specs/UC-28-desktop-ui-component-kit.md) Implemented v1.0** |

**Stack pin (✓ `Cargo.toml` workspace + lock):** `egui` / `eframe` version req **`0.29`**
(resolves **0.29.1**); `default-features = false` (AccessKit OFF); features `glow`,
`default_fonts`, `wayland`, `x11`; no `persistence`. Liquid Glass / native menus → UC-18 P3.

---

## 0. Do we need this?

**Yes.** UC-27 closed form craft (alignment, accent, trust copy, Settings overflow). It did
**not** specify a reusable **component kit** or **surface/elevation language**. Polished apps
feel finished because every control belongs to a small, named family (Accent / Subtle /
Destructive; Card / Boxed list; Header / Content / Footer) with consistent fill, stroke,
radius, and shadow — not because they dump a sidebar onto every screen.

| Need | Why |
|------|-----|
| **Yes — component research** | Leo’s “no navigation / not professional” reaction is mostly **missing surfaces + chrome components**, not missing IA on the locked screen |
| **No — fake locked-state destinations** | KeePassXC Welcome-class unlock stays chrome-light; Credentials create must not invent a Material rail. Cryptomator’s always-on **vault list** is a multi-vault shell (UC-26 DF-7), not a reason to fake nav on first-run create |
| **Yes — styling tokens beyond SPACE_*** | Fluent elevation, Adwaita `.card`, WinUI `CardBackground`/`ControlStroke` explain why Blindkey’s form still “floats” |

**ONE recommendation (end of doc):** UC-28 is **shipped** — keep polishing via smoke; do not
re-open locked-state navigation.

---

## 1. Incident — what “unprofessional” actually means (2026-07-30)

Observed create-vault screen after UC-27:

| Sensation | Likely component gap | Not the gap |
|-----------|----------------------|-------------|
| “No navigation” | Unlocked **mode chrome** not yet seen; locked has only brand + status | Missing sidebar on unlock (would fight Cryptomator / §8.2) |
| “Floating form on void” | No **card surface** (`Frame` fill + stroke + padding + optional soft shadow) | Form width / accent (already fixed) |
| “Empty window” | No **optical vertical centering** / max content height band; huge dead canvas | Need for stats/dashboard (§8.5 forbid) |
| “Debug UI buttons” (secondary) | Secondary CTAs use default egui chrome; peers use **flat / subtle / text** variants in chrome | Accent Create (already filled) |
| “Not macOS-native” | No system **menu bar / toolbar glass** | Unfixable cleanly in egui — UC-18 |

So: more polishing **yes**, but the next polish is **components & surfaces**, not a nav rail on lock.

---

## 2. Anatomy of a polished desktop shell (component layers)

Cross-platform polished apps share the same **layers**, even when widgets differ:

```text
┌─ OS chrome (title bar / traffic lights / menu bar)     ← native / UC-18
├─ App header / toolbar / header-bar                     ← TopBottomPanel
├─ Optional nav (sidebar / rail / vault list)            ← SidePanel — unlocked only
├─ Content canvas                                        ← CentralPanel
│    ├─ Surface (card / boxed list / canvas)             ← Frame / group
│    ├─ Controls (button family, fields, switches)       ← themed widgets
│    └─ Feedback (toast / info bar / inline error)       ← status band
└─ Footer / status / drop hint                           ← TopBottomPanel bottom
```

**Rule of thumb from peers + HIGs:**

- **Authentication / unlock** → strip layers 3–4 to the minimum (header + one card).
- **Working session** → full chrome: header + (optional) nav + content + status.
- Never put primary destinations in a **Material navigation rail** until there are
  **3–7** destinations (✓ [M3 Navigation rail guidelines](https://m3.material.io/components/navigation-rail/guidelines) —
  collapsed rail “should contain 3–7 navigation items”; rail should be the only visible
  nav element). Blindkey’s **2** modes are below that band → header/mode switch, not a rail.

Blindkey destinations today: Credentials | Workspace (2). That is **mode-switcher chrome**,
not a Material rail. Correct pattern: segmented / header switch (UC-26), not a persistent
left rail of icons.

---

## 3. Official platform sources — components & styling

### 3.1 Apple (macOS) — hierarchy via materials, not more buttons

| Source | What to steal for Blindkey | What **not** to fake in egui |
|--------|----------------------------|------------------------------|
| [Adopting Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass) ✓ | Navigation lives in the **topmost** glass layer; content is the canvas underneath | Specular blur stacks in egui |
| WWDC25 [AppKit new design](https://developer.apple.com/videos/play/wwdc2025/310/) ✓ | Toolbar floats above content; sidebar vs inspector materials differ | `NSSplitViewController` glass |
| WWDC25 [SwiftUI new design](https://developer.apple.com/videos/play/wwdc2025/323/) ✓ | Bordered buttons → capsule on large; mini/small stay denser rounded-rect; dialogs morph from presenting control | Capsule fashion on every egui button |
| HIG Toolbars / Sidebars | Prefer [developer.apple.com HIG](https://developer.apple.com/design/human-interface-guidelines/); third-party mirrors ~ only | Full AppKit glass chrome |

**Component lesson:** “Professional” on Mac = **clear layers** (chrome vs content) + **one
default action**, not denser chrome. Blindkey’s locked screen correctly omits glass chrome;
it incorrectly omits a **content card** that would create figure–ground.

### 3.2 Microsoft Fluent 2 / WinUI — tokens, cards, button roles

| Source | Steal |
|--------|-------|
| [Fluent 2 Design tokens](https://fluent2.microsoft.design/design-tokens) ✓ | Global → alias tokens (never hardcode hex in call sites) |
| [Fluent 2 Layout](https://fluent2.microsoft.design/layout) ✓ | 4 px base ramp (Blindkey `SPACE_*` already aligns) |
| [Fluent 2 Elevation](https://fluent2.microsoft.design/elevation) ✓ | Shadow ramp by role; light cards often shadow-2/4/8; pop-up dialogs shadow-64; **“Windows uses strokes instead of key shadows to outline an object”** (verbatim platform distinction) |
| [WinUI Buttons](https://learn.microsoft.com/en-us/windows/apps/design/controls/buttons) ✓ | Button vs HyperlinkButton vs SplitButton vs Toggle; verb labels; min width **120px** for short text; max label ~**26** characters |
| [Microsoft.UI.Reactor styling](https://microsoft.github.io/microsoft-ui-reactor/styling/) ~ | Community helper over WinUI brushes — `Theme.CardBackground` / `CardStroke`, `.AccentButton()` / `.SubtleButton()`; useful names, **not** a Fluent Design System primary page |

**WinUI-oriented semantic surfaces (~ Reactor accessors → WinUI resource keys):**

| Role | Token idea | Blindkey map |
|------|------------|--------------|
| Page | `SolidBackground` / panel fill | `AA_BG` |
| Card | `CardBackground` + `CardStroke` | **Missing** → `egui::Frame` |
| Control | `ControlFill*` + `ControlStroke*` | Partial via `AA_FIELD_*` |
| Accent | Accent brush | `ACCENT` + `primary_button` |
| Danger | destructive / critical styling | `DANGER` + `danger_button` |
| Subtle | secondary / subtle button | `secondary_button` (needs quieter style) |

**Dialog button order — platform conflict (do not paper over):**

| Source | Order (LTR) |
|--------|-------------|
| [GNOME Dialogs](https://developer.gnome.org/hig/patterns/feedback/dialogs.html) ✓ | **Cancel before** affirmative |
| [WinUI Buttons](https://learn.microsoft.com/en-us/windows/apps/design/controls/buttons) ✓ | Lists commit responses as **Do-it → Don’t → Cancel** (affirmative-first in the recommendation list) |

**Blindkey stance:** keep **Cancel then Affirm** in egui dialogs (matches current Create/Unlock
rows and GNOME; macOS default button is typically trailing). Document WinUI divergence; do not
“fix” Windows order into the Mac-primary shell.

### 3.3 GNOME HIG / libadwaita — header bars, boxed lists, style classes

| Source | Steal |
|--------|-------|
| [Header bars](https://developer.gnome.org/hig/patterns/containers/header-bars.html) ✓ | Start = primary verbs; center = title/switcher; end = menu. Icon buttons **flat** in header |
| [Boxed lists](https://developer.gnome.org/hig/patterns/containers/boxed-lists.html) ✓ | Settings as semantic card-lists; switch/action/entry/property rows; min+max width |
| [Dialogs](https://developer.gnome.org/hig/patterns/feedback/dialogs.html) ✓ | Cancel **before** affirm; verb on affirm; avoid surprise dialogs; prefer toast/undo for soft errors |
| [libadwaita style classes](https://gnome.pages.gitlab.gnome.org/libadwaita/doc/main/style-classes.html) ✓ | `.suggested-action` / `.destructive-action` / `.flat` / `.card` / `.boxed-list` |
| Alice Mikhaylenko, [Cleaning up header bars](https://blogs.gnome.org/alicem/2021/09/10/cleaning-up-header-bars/) ✓ community | Flat header buttons cut visual noise — “lighter” = remove chrome, don’t add it |

**Component lesson for Settings:** Blindkey’s Settings `Window` should migrate toward
**boxed-list rows** (label + control), not a pile of free checkboxes — GNOME’s polished look
is mostly this pattern.

### 3.4 Material Design 3 — navigation rail (when it applies)

| Source | Steal | Blindkey note |
|--------|-------|---------------|
| [M3 Navigation rail guidelines](https://m3.material.io/components/navigation-rail/guidelines) ✓ | Collapsed rail **3–7** items; leading edge; only visible nav element; don’t use on compact phone layouts | Blindkey has **2** modes → **not** a rail |
| M3 Cards / elevation ~ | Contained / outlined / elevated variants | Prefer Fluent/Adwaita card recipes (M3 cards page often JS-heavy) |

Do **not** copy Material’s phone-first density into unlock.

---

## 4. Component catalog (normative roles for Blindkey)

Named roles — independent of toolkit — that polished apps keep small and consistent:

### 4.1 Buttons

| Role | When | Platform names | Blindkey today |
|------|------|----------------|----------------|
| **Accent / Suggested / Primary** | One default commit per focus task | WinUI/Fluent accent · Adw `.suggested-action` · Apple default | ✓ `primary_button` |
| **Neutral / Quiet / Secondary** | Cancel, Choose file, Open existing | Reactor/WinUI subtle · Adw default / flat in header | ~ `secondary_button` (still “raised” egui look) |
| **Destructive** | Delete / confirm delete | Adw `.destructive-action` · WinUI critical/destructive patterns | ✓ `danger_button` |
| **Text / Link** | Tertiary navigation (“Choose vault file…”) | WinUI `HyperlinkButton` | ✗ still plain `ui.button` |
| **Split / Menu** | Action + overflow | WinUI SplitButton · Adw SplitButton | ✗ not needed yet |
| **Icon-flat (header)** | Lock, Settings in toolbar | GNOME flat header buttons | ~ Lock/Settings use sized buttons |

**WinUI text rules (✓ Learn Buttons):** verb; concise; prefer ≥120 px for short labels; max ~26 chars.

### 4.2 Text fields

| Role | Styling | Blindkey |
|------|---------|----------|
| Labeled field | Label **above**; fill ≠ panel; stroke ≥ WCAG 1.4.11 | ✓ `labeled_secret_row` + `AA_FIELD_*` |
| Password | Paste + Show (NIST) | ✓ |
| Inline search | Hero when unlocked (Bitwarden/1Password pattern) | ✓ Search exists unlocked |
| Settings entry row | Label | control on one row inside card | ✗ Settings still free-form |

### 4.3 Surfaces & containers

| Role | Styling | Blindkey |
|------|---------|----------|
| **Card** | Distinct fill + 1 px stroke (or soft shadow); inner padding `SPACE_L`; radius 6–12 | ✗ unlock uses width clamp only — **open Q from UC-27** |
| **Boxed list** | Card containing rows + separators | ✗ Settings |
| **Group / section** | Weak heading + related controls | Partial |
| **Dialog / Window** | Modal parent; **Cancel then Affirm** (GNOME / Blindkey stance — see §3.2 conflict note) | ~ egui `Window`; most dialogs already Cancel→Create |
| **Canvas / empty state** | Illustration optional; one CTA | ✓ empty-state Add |

### 4.4 Chrome / navigation components

| Role | Unlocked | Locked |
|------|----------|--------|
| Title + status | Required | Required |
| Mode switch (Credentials \| Workspace) | Required | Hidden |
| Search | Credentials | Hidden |
| Primary Add | Credentials | Hidden |
| Settings overflow | Credentials | Hidden |
| Lock | Credentials | N/A |
| Workspace vault list / status | Workspace | Hidden / N/A |
| System menu bar | Ideal (native) | Ideal — **UC-18** |

This table is why the Credentials **create/unlock** screenshot feels nav-less: that screen is
supposed to be **chrome-light** (KeePassXC Welcome-class). Cryptomator’s always-on vault list is
a **different product shell** (multi-vault), not a reason to fake destinations on first-run create.

### 4.5 Feedback

| Role | Prefer | Avoid |
|------|--------|-------|
| Soft status | Footer caption / toast / info bar (Cryptomator renamed notification→info bar) | Modal for every error |
| Hard fail | Inline `DANGER` under form (already) | Stack traces |
| Destructive confirm | Inline confirm or dialog; GNOME prefers undo when possible | Habit-click OK dialogs |

---

## 5. Peer OSS — component anatomy (public repos)

### 5.1 Cryptomator (JavaFX) — vault list + unlock dialog

✓ Official docs ([accessing vaults](https://github.com/cryptomator/docs/blob/develop/docs/desktop/accessing-vaults.mdx)) + public app tree
([cryptomator/cryptomator](https://github.com/cryptomator/cryptomator)):

| Component | Role |
|-----------|------|
| Vault list (main window) | **Always present** — select a vault even when locked |
| Vault detail + large Unlock | Primary CTA on selected vault |
| Password / unlock stage | **Dialog/flow after Unlock** — not a nav-less empty shell |
| Info bar | Soft feedback strip (NotificationBar → InfoBar in a11y work) |
| Context menu | Secondary verbs (Share…, etc.) |

**Steal:** polish = **list + detail + unlock dialog**, not “empty window until unlock.” Blindkey’s
locked Credentials create is closer to KeePassXC Welcome than to Cryptomator’s always-on list.
Workspace DF-7 should grow toward Cryptomator list|detail — **without** putting a vault rail on
the Credentials unlock/create card.

**Nuance vs earlier draft:** saying Cryptomator has “no locked nav” was **wrong**. The list is the
nav; the password UI is modal/flow. What Blindkey should *not* copy onto first-run create is a
fake multi-destination rail with nowhere to go.

**A11y note (✓ PR #4103):** list cells bind accessible text to vault name + state; dialogs get
`AccessibleRole.DIALOG`. Component polish includes **screen-reader contracts**, not only pixels.

### 5.2 KeePassXC (Qt) — stacked screens prove state-specific chrome

✓ Custom widgets in public [`MainWindow.ui`](https://raw.githubusercontent.com/keepassxreboot/keepassxc/develop/src/gui/MainWindow.ui)
(`WelcomeWidget`, `DatabaseTabWidget`, `ApplicationSettingsWidget`, `PasswordGeneratorWidget`,
`MessageWidget`, `KPToolBar`) + `MainWindow.cpp` search-in-toolbar wiring:

| Component | Role |
|-----------|------|
| `QMenuBar` | Database / Entries / Groups / Tools / View / Help |
| `KPToolBar` | Quick actions; search widget added in code |
| Stacked content | Switches Welcome · Database tabs · Settings · Password generator |
| `DatabaseTabWidget` | Multi-DB tabs when a database is open |
| View menu | Compact Mode, Theme, Show Menubar/Toolbar/Group Panel/Preview Panel |
| `MessageWidget` | Global soft messages |

**Critical polish lesson:** KeePassXC does **not** show the full database list chrome on every
screen — Welcome/unlock-adjacent flows use a different stack page. “Professional” means
**the right component stack for the state**.

~ Status-bar entry counts: reported in secondary DeepWiki summaries of the same tree — treat as
~ until confirmed in `MainWindow.cpp` / status-bar setup; not load-bearing for Blindkey.

### 5.3 Bitwarden desktop (Electron) — what *not* to copy blindly

~ Community redesign write-ups + 2026 GitHub regressions ([clients#20804](https://github.com/bitwarden/clients/issues/20804),
[#20802](https://github.com/bitwarden/clients/issues/20802), [#20851](https://github.com/bitwarden/clients/issues/20851)):

| Pattern | Lesson for Blindkey |
|---------|---------------------|
| Left hierarchy + search-first vault | Good target for **unlocked Credentials** |
| Excess list padding after refresh | Users revolt when density collapses visible rows — keep **medium** density (UC-26) |
| Search not focused / Cmd+F broken | Polish = **keyboard contracts** on Search component |
| Row hover highlight without full-row hit target | Entire list row must be the click target |
| System font > custom web font | Prefer platform / egui default fonts (already UC-26 `default_fonts`) |

Bitwarden is Electron — **rejected for Blindkey by C20** — but its **component failures** are
reusable warnings: search focus, row hit-testing, density, shortcut wiring.

### 5.4 Signal Desktop / 1Password (pattern level)

~ From prior craft research + product observation:

| App | Component cue |
|-----|---------------|
| Signal | Thin chrome; content-first; restrained accent |
| 1Password / Bitwarden (unlocked) | Search hero; list + detail; empty states with one CTA |

---

## 5b. Cross-app component comparison (locked vs unlocked)

| Component | Cryptomator | KeePassXC | Bitwarden | Blindkey now | Blindkey target |
|-----------|-------------|-----------|-----------|--------------|-----------------|
| Locked primary surface | Vault list + Unlock → password dialog | Welcome / stacked page | Unlock gate | Form on flat panel | **Card Frame** (Credentials create/unlock) |
| Locked “nav” | **Vault list yes** (select then unlock) | No full DB chrome on Welcome | No vault chrome | No | Stay **no list** on Credentials first-run; Workspace list = DF-7 |
| Unlocked nav | Vault list + detail | Groups + entries | Folders + items | Mode switch only | Mode switch; Workspace list later |
| Header | App chrome + vault actions | Menu + toolbar + search | App chrome + search | Brand · modes · Lock | + flatter actions |
| Settings | Preferences window | Settings stack page | Preferences | egui Window | **Boxed-list rows** |
| Soft feedback | Info bar | MessageWidget | Toasts (~) | Status string | Status strip / toast |
| Destructive | Confirm flows | Confirm | Confirm | `danger_button` | Keep |

---

## 6. egui 0.29.1 — what we can implement without leaving C20

### 6.1 First-party (pin-correct)

| Need | egui API | Notes |
|------|----------|-------|
| Card surface | [`Frame`](https://docs.rs/egui/0.29.1/egui/containers/frame/struct.Frame.html) ✓ | `inner_margin`, `fill`, `stroke`, `rounding`, optional `shadow` |
| Side nav (later) | [`SidePanel`](https://docs.rs/egui/0.29.1/egui/containers/panel/struct.SidePanel.html) ✓ | Unlocked Workspace list; animated expand available |
| Header / footer | `TopBottomPanel` | Already used unlocked |
| Grouping | `Frame::group` / `ui.group` | Settings sections |
| Accent fill | `Button::fill` | Already |
| Per-state chrome | [`Widgets`](https://docs.rs/egui/0.29.1/egui/style/struct.Widgets.html) + [`WidgetVisuals`](https://docs.rs/egui/0.29.1/egui/style/struct.WidgetVisuals.html) ✓ | `noninteractive` / `inactive` / `hovered` / `active` / `open` — each has `bg_fill`, `weak_bg_fill`, `bg_stroke`, `rounding`, `fg_stroke`, `expansion` |

**Forbidden still:** `Visuals.text_edit_bg_color` / `weak_text_alpha` (not on 0.29.1) — see
prior research §19 X1.

### 6.2 Community crates (evaluate, do not blindly vendor)

| Crate / repo | Idea | Risk for Blindkey |
|--------------|------|-------------------|
| [egui_styled](https://github.com/dspray95/egui_styled) ✓ | Per-widget style builders; `StyledFrame`; avoids `visuals_mut` leakage | New dep; API churn; audit license |
| [egui-elegance](https://github.com/stephenberry/egui-elegance) ✓ | Theme install; Card/Modal/Toast; focus ring on inputs | Opinionated web aesthetic may fight calm security UI |
| [Armas](https://github.com/OpenLLT/Armas) ✓ | Shadcn-like component kit | Web-inspired look; may violate §8.5 “no purple AI aesthetic” if misused |
| emilk/egui#7445 ~ | Upstream desire for per-widget `Frame` | Track; don’t wait |

**Recommendation for Blindkey:** prefer **thin in-repo helpers** in `theme.rs`
(`form_card_frame`, `subtle_button`, `settings_row`) over a web-UI kit — keeps C20, calm
security aesthetic, and pin control. Steal *ideas* from those crates, not their dependency
weight, unless a crate is tiny, MIT/Apache, and visually quiet.

### 6.3 Concrete `Frame` recipe (authoring sketch — egui 0.29.1)

```rust
// Illustrative — tune colors against AA_BG in theme.rs
egui::Frame::none()
    .fill(AA_CARD_BG)
    .stroke(egui::Stroke::new(1.0, AA_CARD_STROKE))
    .rounding(egui::Rounding::same(RADIUS_CARD))
    .inner_margin(egui::Margin::same(SPACE_L))
    // Prefer stroke-only on dark AA; add soft Shadow only if smoke still feels flat
    .show(ui, |ui| { /* form_card contents */ });
```

Optical vertical balance sketch:

```text
CentralPanel
  allocate remaining height H
  top_spacer = max(WINDOW_GUTTER, (H - card_h) * 0.35)   // optically center, slightly high
  card
  bottom_spacer / footer caption pinned near bottom band
```

---

## 6b. Visual states matrix (interactive components)

Platform design systems describe rest / hover / pressed / disabled / focus. **egui 0.29.1**
exposes five `Widgets` slots (✓ `style.rs`):

| egui slot | Meaning |
|-----------|---------|
| `noninteractive` | Non-clickable chrome / window outline |
| `inactive` | Interactive widget at rest |
| `hovered` | Pointer hover or highlight |
| `active` | Clicking/dragging **or** `Response::has_focus()` (focus shares active visuals) |
| `open` | Open menu under a button (combo) |

| Design-system state | Fill / stroke intent | egui map |
|---------------------|----------------------|----------|
| Rest | Control default | `inactive` |
| Hover | Wash / stronger stroke | `hovered` |
| Pressed | Tertiary / stronger | `active` |
| Focus (keyboard) | Visible focus | **Also `active`** in egui — no separate focus `WidgetVisuals` |
| Disabled | Muted | Sense off → `noninteractive` path |
| Error | Danger stroke / text | App-level (`DANGER` label), not a `Widgets` slot |

Blindkey today: accent/danger fills on some buttons; **hover differentiation on quiet buttons
and list rows is under-specified** — UC-28 should tune `hovered`/`inactive` for quiet controls.

---

## 6c. Deep dive — fields (WinUI TextBox → Blindkey)

✓ [WinUI Text box](https://learn.microsoft.com/en-us/windows/apps/design/controls/text-box):

| Rule | Blindkey map |
|------|--------------|
| Prefer **Header/label visible whether empty or not**; placeholder is secondary | Keep label-above; hints ≠ label (UC-27 CRAFT-05) |
| Placeholder disappears once valued | egui `hint_text` OK for `••••••••` / path examples |
| Width sized to expected input; split long fields | `FORM_WIDTH` / `secret_field_width` |
| PasswordBox for secrets | `password(true)` + Show |
| AutoSuggestBox for search | Unlocked Search field (not TextBox-as-search without focus contract) |
| Don’t grow multiline height unboundedly | Editor notes: fixed rows |
| Clear-all “X” on focused single-line | Optional later — not required for vault passphrase |
| Paste supported | NIST — already sacred |

---

## 6d. Deep dive — chrome (CommandBar / HeaderBar / View switcher)

### WinUI CommandBar (✓ [Learn](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/command-bar))

- Primary commands vs overflow (“…”).
- Closed modes: Compact (icons) / Minimal / Hidden.
- Labels short (prefer one word); overflow distinct from bar.

**Blindkey map:** unlocked trailing actions ≈ compact command cluster; Settings already is
overflow. Do not build a full WinUI CommandBar clone — steal **primary vs overflow** only.

### GNOME HeaderBar + View switcher (✓ HIG)

- Header: start verbs · center title/switcher · end menu.
- [View switchers](https://developer.gnome.org/hig/patterns/nav/view-switchers.html) ✓: rule of
  thumb **3–5 views**; nouns not verbs; **more than that → sidebar**; bottom switcher when narrow.

**Blindkey map:** Credentials | Workspace is a **2-way mode switch** — **below** the GNOME
view-switcher 3–5 band. Still valid as a compact toggle/segmented control; **do not** call it a
GNOME view switcher or escalate to a sidebar solely for two modes. Sidebar/list belongs to
Workspace multi-vault (DF-7), not Credentials IA.

### Apple Sidebars / Split views (~ HIG + ✓ Liquid Glass docs)

- Sidebars for **many** destinations; hideable; avoid critical actions at bottom of sidebar
  (~ [HIG Sidebars](https://developer.apple.com/design/human-interface-guidelines/sidebars) —
  primary pages often JS-gated in fetchers; corroborated via WWDC25 / Liquid Glass + mirrors).
- Split views: list | detail; thin dividers; hideable panes (~ HIG Split views).
- ✓ [Adopting Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass):
  nav in topmost glass layer; use standard split-view APIs for sidebar/inspector.

**Blindkey map:** Credentials list | editor already is a soft split. Workspace DF-7 ≈ Cryptomator
list | detail. Locked Credentials create: **no sidebar**.

---

## 6e. Deep dive — cards & elevation

| System | Card recipe |
|--------|-------------|
| Fluent | Outlined/elevated cards via tokens; elevation tables assign shadow-2/4/8 to various card cases; Windows prefers **strokes vs key shadows** (✓ Elevation) |
| Adwaita | `.card` / `.boxed-list` / `.boxed-list-separate` |
| M3 | Contained / outlined / elevated card variants (site often JS-gated — treat as ~) |
| egui | `Frame` fill + stroke + rounding (+ optional `Shadow`) |

**Blindkey decision (research stance):** dark AA theme → **outlined card** (fill delta + 1 px
stroke) first; add ambient shadow only if stroke-only still fails figure–ground smoke.

---

## 6f. Accessibility & keyboard contracts (component-level)

| Component | Contract |
|-----------|----------|
| Search | Focus on unlock→Credentials (or Cmd/Ctrl+F); Enter/Tab → first result (Bitwarden regression warning) |
| List row | Full-row hit target; focus ring; accessible name = title (+ meta) |
| Dialog | Initial focus on first field; Esc = Cancel; Return = Affirm when safe |
| Show password | Adjacent, labeled; not icon-only without text |
| Status / error | Not color-alone (UC-26 IA-01) |
| AccessKit | OFF today — visible labels mandatory (C54); enabling later is G4 |

---

## 7. Gap matrix — Blindkey vs polished component set

| Component / style | Research / HIG | Blindkey 2026-07-30 | Priority |
|-------------------|----------------|---------------------|----------|
| Unlock **card Frame** | Fluent card · Adw `.card` · Gestalt figure–ground | Width only | **P0** |
| Vertical optical centering / max-height band | Sparse ≠ empty void | Content top-heavy | **P0** |
| Subtle / text button variants | WinUI HyperlinkButton · Adw flat / subtle | Partial | **P1** |
| Settings as boxed-list rows | GNOME boxed lists | Free checkboxes in Window | **P1** |
| Hover/focus states on quiet controls | WidgetVisuals / Fluent | Under-specified | **P1** |
| Search keyboard contract | Bitwarden regressions | Partial | **P1** |
| Full-row list hit targets | Bitwarden #20804 | Verify | **P1** |
| Unlocked header density (flat icon actions) | GNOME header bar cleanup | Sized buttons OK | **P2** |
| Info / toast strip | Cryptomator info bar · KeePassXC MessageWidget | Status string only | **P2** |
| Density preference (compact/comfortable) | KeePassXC View menu | Fixed medium | **P3** |
| Workspace vault list + detail | Cryptomator | Single-volume home | DF-7 |
| Native menu bar / Liquid Glass | Apple HIG / WWDC25 | Absent | UC-18 |
| Nav rail | M3 | N/A (only 2 modes) | **Out** |
| Third-party egui kit | Community | None | Optional later |

---

## 8. Proposed Blindkey component kit (authoring target — next UC)

Names are **capability-first** (for a future `theme.rs` / `widgets.rs`), not ticket IDs.

| Helper | Behavior |
|--------|----------|
| `surface_card(ui, …)` | `Frame` with `AA_CARD_BG`, `AA_CARD_STROKE`, radius 8, pad `SPACE_L`; wraps unlock + settings sections |
| `accent_button` | Existing `primary_button` |
| `quiet_button` | Flat/low-contrast secondary (header + Cancel) |
| `text_button` | No fill; for “Choose vault file…” |
| `danger_button` | Existing |
| `settings_switch_row` / `settings_value_row` | GNOME-style row: label (+ weak subtitle) \| control |
| `app_header` | Brand · status · mode switch · trailing actions |
| `status_strip` | Weak one-line / toast host |
| `focus_search()` | Programmatic focus helper for unlocked Credentials |

**Explicit non-goals for that UC:** Liquid Glass, Material rail, Armas/Shadcn look, locked-state
sidebar, dashboard cards with metrics.

### 8.1 UC-28 acceptance sketch (see Draft v0.2 for full contract)

Minimum from this research; **UC-28 Draft v0.2** also requires dialog Esc/Return, list
full-row hit, `focus_search`, CRAFT-S11–S12 non-regression:

1. Locked create/unlock: form sits inside visible card; card optically centered (not glued to top).
2. “Choose vault file…” / Cancel / first-run strip use text/quiet style — do not compete with accent.
3. Settings: ≥3 controls presented as labeled rows inside a card/boxed list.
4. Search Cmd/Ctrl+F + full-row list hit; hover on quiet controls.
5. uc27 suites remain green; new uc28 static tests for `AA_CARD_*` + `surface_card` wiring.
6. Screenshot re-check: H1–H7 still closed; “floating on void” sensation reduced.

---

## 9. Styling token additions (beyond UC-27 `SPACE_*`)

Propose (values to tune against screenshot; keep 4 px grid):

| Token | Intent | Seed (dark) |
|-------|--------|-------------|
| `AA_CARD_BG` | Card fill ≠ `AA_BG` | slightly lighter than panel (~RGB 32–36) |
| `AA_CARD_STROKE` | Card edge | ~1 px, ≥3:1 vs card fill when possible |
| `RADIUS_CONTROL` | Buttons / fields | 4–6 |
| `RADIUS_CARD` | Cards | 8–12 |
| `SHADOW_CARD` | Optional soft ambient | Fluent shadow-2 class; or **stroke-only** on dark (Win pattern) |
| `ROW_HEIGHT_LIST` | Credential row | ~28–32 (medium density) |
| `HEADER_HEIGHT` | App header band | ~40–48 |

Elevation on dark UIs: Fluent notes Windows often prefers **stroke over key shadow** —
prefer stroke-first for Blindkey dark AA theme (less “glow,” more secure-tool calm).

### 9.1 Type roles inside components

| Role | egui | Use |
|------|------|-----|
| Header | `heading` / strong | App title once |
| Body | default | Instructions |
| Label | default | Field labels |
| Caption | `Small` + `weak` | Path, drop hint, trust |
| Mono | monospace | Paths only |
| Danger text | `DANGER` color | Errors |

Do not invent a fourth display size for marketing on lock.

---

## 10. Anti-patterns (component edition)

| ❌ | Why |
|----|-----|
| Sidebar on locked create/unlock | Fights Cryptomator + security IA; fake “pro” |
| Material nav rail for 2 modes | Overbuilt; modes belong in header |
| Importing Shadcn-like kits wholesale | Risk of web/AI aesthetic (§8.5) |
| Shadow soup / neon accents | Security apps read as toys |
| Replacing egui with Electron for “polish” | Breaks C20 (`ui_architecture.md`); Bitwarden shows Electron ≠ automatic polish |
| New Visuals fields from egui > 0.29.1 | Pin breakage |
| Huge list padding “for modern look” | Bitwarden user revolt — keep scannable density |
| Hover highlight without clickable row | False affordance |
| Search without keyboard focus contract | Power-user breakage |

---

## 11. Sources

### Official

- Apple — [Adopting Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass); WWDC25 sessions [310](https://developer.apple.com/videos/play/wwdc2025/310/), [323](https://developer.apple.com/videos/play/wwdc2025/323/), [356](https://developer.apple.com/videos/play/wwdc2025/356/); HIG Sidebars / Split views (developer.apple.com + mirrors)
- Fluent 2 — [Design tokens](https://fluent2.microsoft.design/design-tokens), [Layout](https://fluent2.microsoft.design/layout), [Elevation](https://fluent2.microsoft.design/elevation)
- Microsoft Learn — [Buttons (WinUI)](https://learn.microsoft.com/en-us/windows/apps/design/controls/buttons), [Text box](https://learn.microsoft.com/en-us/windows/apps/design/controls/text-box), [Command bar](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/command-bar)
- GNOME HIG — [Header bars](https://developer.gnome.org/hig/patterns/containers/header-bars.html), [Boxed lists](https://developer.gnome.org/hig/patterns/containers/boxed-lists.html), [Dialogs](https://developer.gnome.org/hig/patterns/feedback/dialogs.html), [View switchers](https://developer.gnome.org/hig/patterns/nav/view-switchers.html)
- libadwaita — [Style classes](https://gnome.pages.gitlab.gnome.org/libadwaita/doc/main/style-classes.html)
- Material 3 — [Navigation rail guidelines](https://m3.material.io/components/navigation-rail/guidelines) (3–7 collapsed items ✓)
- egui 0.29.1 — [`Frame`](https://docs.rs/egui/0.29.1/egui/containers/frame/struct.Frame.html), [`SidePanel`](https://docs.rs/egui/0.29.1/egui/containers/panel/struct.SidePanel.html), [`Widgets`](https://docs.rs/egui/0.29.1/egui/style/struct.Widgets.html), [`WidgetVisuals`](https://docs.rs/egui/0.29.1/egui/style/struct.WidgetVisuals.html)

### Community / public repos

- Alice Mikhaylenko — [Cleaning up header bars](https://blogs.gnome.org/alicem/2021/09/10/cleaning-up-header-bars/) (GNOME)
- Microsoft.UI.Reactor — [Styling](https://microsoft.github.io/microsoft-ui-reactor/styling/) / [Theme tokens](https://microsoft.github.io/microsoft-ui-reactor/theming-tokens/)
- Cryptomator — [docs accessing-vaults](https://github.com/cryptomator/docs/blob/develop/docs/desktop/accessing-vaults.mdx); [cryptomator/cryptomator](https://github.com/cryptomator/cryptomator) (a11y PR #4103)
- KeePassXC — [`MainWindow.ui`](https://raw.githubusercontent.com/keepassxreboot/keepassxc/develop/src/gui/MainWindow.ui) + `src/gui` (not DeepWiki as primary)
- Bitwarden — [clients#20804](https://github.com/bitwarden/clients/issues/20804) et al. (density / search / hit-target regressions); community UI refresh write-ups
- egui ecosystem — [egui_styled](https://github.com/dspray95/egui_styled), [egui-elegance](https://github.com/stephenberry/egui-elegance), [Armas](https://github.com/OpenLLT/Armas), [egui#7445](https://github.com/emilk/egui/issues/7445)

### Blindkey companions

- [`desktop_app_ui_ux_research.md`](desktop_app_ui_ux_research.md) · [`desktop_security_ui_research.md`](desktop_security_ui_research.md) · [`ui_architecture.md`](ui_architecture.md)
- UC-26 · UC-27 · **[UC-28](../docs/specs/UC-28-desktop-ui-component-kit.md)** Implemented v1.0

---

## 12. Honest gaps left after this pass

| ID | Gap |
|----|-----|
| G1 | Live pixel side-by-side vs Cryptomator/KeePassXC still deferred (prior R1) |
| G2 | Apple HIG interactive pages often JS-gated — Liquid Glass + WWDC + partial HIG used |
| G3 | Cryptomator CSS token values not extracted — behavior from docs + public UI structure |
| G4 | Vendoring egui styling crates needs dependency/threat review before adopt |
| G5 | M3 Cards overview still thin — card recipe from Fluent/Adwaita |
| G6 | Bitwarden lessons are issue-thread ~ — not a formal design-system doc |
| G7 | KeePassXC status-bar details remain ~ (DeepWiki); stacked widgets ✓ from `.ui` |

---

## 13. ONE recommendation

> **[UC-28](../docs/specs/UC-28-desktop-ui-component-kit.md)** is **Implemented v1.0** / ROADMAP
> **S-27** ✅: `surface_card`, quiet/text buttons, Settings boxed-list rows, optical vertical
> balance, hover via egui `Widgets`, full-row list + Search focus — **no locked-state rail**.
> Keep this file as craft SoT; UC-27/UC-28 suites green.

---

## 14. Changelog

| Date | Change |
|------|--------|
| 2026-07-30 | Initial component/styling research — platforms, peers, egui map, Blindkey gap matrix, UC-28 proposal |
| 2026-07-30 | **Expanded** — KeePassXC stacked-screen anatomy; Bitwarden regression lessons; locked/unlocked comparison table; WidgetVisuals state matrix; WinUI TextBox/CommandBar deep dives; GNOME view switcher; Apple sidebar/split notes; Frame centering recipes; UC-28 acceptance sketch; denser sources |
| 2026-07-30 | **Source cross-check** — §16 audit; fix Cryptomator locked-list claim; GNOME 3–5 vs Blindkey 2; WinUI↔GNOME dialog order conflict; M3 rail 3–7 + guidelines URL; Reactor ~; egui focus=`active`; stack pin `0.29`→0.29.1 |
| 2026-07-30 | Spec promotion — cookbook → [UC-28](../docs/specs/UC-28-desktop-ui-component-kit.md) Draft v0.1 + ROADMAP S-27 |
| 2026-07-30 | **Spec ↔ research sync** — UC-28 Draft v0.2 cross-check; fix §0 Cryptomator “post-auth nav” wording; expand §8.1 acceptance; bump Draft pointers |
| 2026-07-30 | **UC-28 Implemented v1.0** — cookbook executed; intent G20 C88–C93 PASS |

---

## 15. Implementation cookbook (operator checklist for UC-28)

Ordered so each step is screenshot-checkable:

1. **Tokens** — add `AA_CARD_BG` / `AA_CARD_STROKE` / `RADIUS_*` to `theme.rs`; unit assert ≠ `AA_BG`.
2. **`surface_card`** — wrap locked `form_card` contents; Settings sections.
3. **Vertical balance** — spacer math in `locked_screen`; footer stays band-bottom.
4. **`text_button` / quieter secondary** — Choose vault file…; Cancel in dialogs; header Lock stays quiet.
5. **Settings rows** — Pad / Auto-lock / Clipboard / Blur as switch rows inside card.
6. **State pass** — hover (`Widgets.hovered`) on quiet buttons + credential rows.
7. **Search focus** — Cmd/Ctrl+F or post-unlock focus (minimal).
8. **Tests** — `uc28_constraints.rs`; keep uc26/uc27 green; clippy `-D warnings`.
9. **Docs** — mark UC-28 Implemented; pointer from this research §14; keep Draft v0.2 CRAFT-S11–S12 in checklist.

Stop before: native menus, Liquid Glass, multi-volume list, AccessKit enable, third-party kits.

---

## 16. Source cross-check audit (2026-07-30)

Checked claims against Fluent Elevation, WinUI Buttons/TextBox/CommandBar, GNOME HIG
(header/boxed-lists/dialogs/view-switchers), libadwaita style classes, M3 navigation-rail
**guidelines**, Apple Liquid Glass + WWDC25 summaries, egui **0.29.1** crate sources
(`Frame`, `Widgets`, `Button::fill`), Cryptomator docs + PR #4103, KeePassXC `MainWindow.ui`,
Bitwarden GitHub issues.

| ID | Issue | Severity | Resolution |
|----|-------|----------|------------|
| X1 | “Cryptomator locked = no nav” | **High** | Cryptomator **keeps vault list**; unlock is password dialog after Unlock — §5.1 + §5b fixed |
| X2 | “≥2 destinations → rail” | **High** | M3 collapsed rail is **3–7** items — §2 + §3.4 fixed |
| X3 | Blindkey 2 modes called “GNOME view switcher” | **Med** | HIG rule of thumb is **3–5**; 2-way = compact mode switch — §6d fixed |
| X4 | WinUI + GNOME dialog button order stated as one rule | **Med** | Documented **conflict**; Blindkey = Cancel→Affirm — §3.2 |
| X5 | Reactor tokens marked ✓ as Fluent primary | **Med** | Downgraded to **~ community-on-WinUI** — §3.2 |
| X6 | “Fluent Subtle / Fluent critical” as official names | **Low** | Renamed to WinUI/Reactor / Adw terms — §4.1 |
| X7 | egui “four states” + separate Focus slot | **Med** | egui has 5 `Widgets` slots; **focus uses `active`** — §6b |
| X8 | Stack pin said only `0.29.1` | **Low** | Cargo req is `0.29`, lock resolves 0.29.1 — header |
| X9 | KeePassXC status bar as ✓ via DeepWiki | **Low** | Softened to ~; `.ui` widgets remain ✓ — §5.2 |
| X10 | M3 linked overview only | **Low** | Guidelines URL (3–7 verified) — §3.4 / §11 |
| X11 | Apple HIG via third-party mirrors as ✓ | **Low** | Prefer developer.apple.com; mirrors ~ — §3.1 / §6d |
| X12 | Fluent “Windows uses strokes…” | OK | ✓ Elevation platform distinction |
| X13 | WinUI 120px / 26-char button rules | OK | ✓ Buttons Learn page |
| X14 | `Frame::none` / `Button::fill` / `Margin::same` | OK | ✓ egui 0.29.1 sources |
| X15 | GNOME Cancel-before-affirm | OK | ✓ Dialogs HIG |
| X16 | KeePassXC Welcome/Settings/PasswordGenerator/MessageWidget/KPToolBar | OK | ✓ `MainWindow.ui` customwidgets |

**Still honest (not errors):** G1 pixel audit; G2 Apple JS gates; G4 crate adopt; G6 Bitwarden issues.
