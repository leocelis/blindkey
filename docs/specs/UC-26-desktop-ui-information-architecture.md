# UC-26 — Desktop UI Information Architecture & Usability Redesign

> **Tech spec** · **Implemented v1.0** · July 2026 · **Status:** implemented — `blindkey-gui`
> fonts/AA theme, Credentials\|Workspace modes, Seal secondary, mount honesty, first-run/next-beat,
> Advanced progressive disclosure; **C75–C81 PASS** (`uc26_constraints.rs`).  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-26 · **Constraints:** C75–C81 (G18, intent **v1.9.3**);  
> reuses C20, C27, C40–C54, C72, C73, C74 culture  
> **Extends:** [UC-18](UC-18-native-ui.md) (thin shell), [UC-20](UC-20-desktop-gui-hardening.md),  
> [UC-21](UC-21-desktop-gaps-closure.md), [UC-25](UC-25-local-encrypted-volume.md) (Workspace surface)  
> **Research:** [desktop_security_ui_research.md](../../research/desktop_security_ui_research.md),  
> [desktop_app_ui_ux_research.md](../../research/desktop_app_ui_ux_research.md) (craft / layout / HIG history),  
> [ui_architecture.md](../../research/ui_architecture.md)  
> **Sibling (not this UC):** SwiftUI/uniffi shell remains UC-18 P3 / ROADMAP S-18 (post-v1);
> visual craft polish (layout/hierarchy/spacing/accent) is [UC-27](UC-27-desktop-ui-visual-craft.md) / ROADMAP S-26  
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the **intent wins**.  
> **Cross-check:** research §14 ↔ Draft v0.2; **Implemented 2026-07-29** (ROADMAP S-25).

This document is the **implementation contract** for making `blindkey-gui` calm, honest, and
usable for the two primary jobs — **store credentials** and **use a local encrypted workspace** —
without changing crypto, format, or delivery logic in `blindkey-core`.

---

## 1. Scope & goals

`blindkey-gui` already ships unlock, search, copy-default (C27), keyfile 2FA, seal, and UC-25
volume Create/Mount/Eject. The chrome still presents Volume/Seal as peer toolbar buttons next to
credential actions, and the workspace `eframe` pin omits embedded fonts — labels can render blank
(research §11). Usability research (Whitten, Chiasson, Nielsen, Yee) and peer products
(Cryptomator) converge on: **visible lock state**, **mode-separated IA**, **human labels**,
**honest mount capability**, and **progressive disclosure**.

| # | Goal |
|---|------|
| 1 | **Readable chrome** — every primary label/glyph visible at WCAG AA contrast (fonts + theme) |
| 2 | **Mode IA** — primary switch: **Credentials** \| **Workspace**; **Seal** is secondary CTA |
| 3 | **Status always visible** — Locked / Unlocked (Workspace: Locked / Unlocked / Mounted) |
| 4 | **Copy & journeys** — Credentials ≤60 s cold; Workspace ≤90 s cold (research §5.8) |
| 5 | **Honesty** — Mount/Reveal never imply Finder mount when packaging is absent (Yee *Expected Ability*) |
| 6 | **Thin shell** — no crypto/format in GUI; preserve C40–C54, C27, C72/C73 |

**Feel goals** (research §5.1 — non-negotiable): calm, fast, honest, trusted (local-only),
recoverable, readable. Great = competence + control (Shneiderman) without dangerous errors
(Whitten) — not flashy; not a metrics dashboard.

**Non-goals (this UC):**

- Toolkit swap (Electron, Tauri webview secrets in JS, SwiftUI — UC-18 P3)
- Changing C27 copy-default, clipboard timeouts, or reveal time-box (UC-21)
- New crypto, volume format, FUSE packaging (UC-25 Phase C / ADR-0010)
- Auto-unlock on login, auto-mount without gesture, confetti/marketing theater
- Full WCAG AAA, AccessKit overhaul beyond C44/C54 baselines
- Private operator pattern trees in this public repo (encode rules here + intent)
- `blindkey-tui` Workspace parity (open question §9 #3 — follow-up only)

---

## 2. Standards & process alignment

Blindkey specs are not claiming formal certification. This UC **aligns** delivery with common
international practice for interactive systems and accessibility:

| Standard / guidance | How this UC uses it |
|---------------------|---------------------|
| **ISO 9241-210** (human-centred design) | Research → draft IA → heuristic eval → small user walkthrough → iterate (§7) |
| **ISO 9241-110** (interaction principles) | Maps to Nielsen/Shneiderman behaviors in research §5.2–§5.3 |
| **ISO/IEC/IEEE 29148** (requirements engineering) | Goals, non-goals, constraints, acceptance tests, open questions — Blindkey UC template |
| **WCAG 2.2** Level AA | Text contrast **1.4.3** (4.5:1); non-text **1.4.11** (3:1); target size **2.5.8** (≥24×24 CSS px); paste/auth **3.3.8** |
| **NIST SP 800-63B-4** | Allow paste on password fields; offer show/hide while entering (§3.1 research) |
| **Apple HIG** (Writing / layout) | Empty states with next action; inline errors; human verbs; avoid “we” |
| **Microsoft Fluent** (app settings) | Settings pages: scrollable column ~1000–1100 px max; unlock forms stay ~400–480 px focus width |

Academic / security-UX anchors (full citations in research §10): Whitten & Tygar (USENIX Security
1999), Chiasson et al. (USENIX Security 2006), Yee (UCB CSD-02-1184), Alodhyani et al. (2020),
Klivan et al. (SOUPS 2023).

---

## 3. Prior art

### 3.1 Open source (product IA)

| Source | What we take | Confidence |
|--------|--------------|------------|
| **Cryptomator** desktop | Vault **list + detail**; large **Unlock**; **Reveal Drive** / **Lock**; residual risk documented — model for Workspace mode. Blindkey maps Cryptomator **Lock** → **Eject** for volumes; vault session still uses **Lock** | ✓ verified ([docs](https://docs.cryptomator.org/desktop/accessing-vaults/)) |
| **KeePassXC** | Search-first credential list; Lock always reachable; copy primary | ~ inferred (common pattern; not primary-doc audited this pass) |
| **Bitwarden / Vaultwarden clients** | Search-first unlocked home; Copy primary; Reveal secondary | ~ inferred (IA only) |
| **Signal Desktop / libsignal** | Thin clients over audited core — already UC-18 posture | ✓ verified |
| **egui / eframe** | Immediate-mode; `default_fonts` feature when `default-features = false` | ✓ verified (workspace `Cargo.toml`) |

### 3.2 This repo (shipped baseline)

| Module | Current behavior | Gap this UC closes |
|--------|------------------|--------------------|
| Workspace `eframe` pin | `default-features = false`, features `glow, wayland, x11` — **no `default_fonts`** | Blank labels (research §11; ~ causal) |
| `main.rs` top bar | Peer buttons: Add, Volume, Mount, Seal, Lock… | Flattened IA; Volume not a mode |
| `volume_gui.rs` | Create/Mount/Eject + residual banner + Seal CTA (C73) | Mount wording honesty on macOS stub |
| UC-20 / UC-21 | Glow, cache, virtualize, reveal timeout, labels | Keep; do not regress |

### 3.3 Alternatives considered (toolkit)

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| Stay egui + fix fonts/IA | C20, thin shell, already shipped | Not pixel-native macOS | ✅ **this UC** |
| SwiftUI now | Best HIG | Months; post-v1 S-18 | ❌ defer |
| Electron | Designer velocity | Violates C20; JS heap | ❌ rejected |
| Tauri + webview for chrome only | Native menus | Secrets must never enter JS; escape hatch only | ❌ out of scope |

---

## 4. Problem statement (normative)

1. **Legibility gate:** With `default-features = false` and without `default_fonts`, egui may ship
   with no embedded fonts → empty button/label glyphs. No IA redesign is evaluable until glyphs
   and contrast work (research §11).
2. **Mental model collision:** Credentials (vault entries), Workspace (`.vltd` live folder), and
   Seal (`.vltf` for untrusted storage) compete as peer toolbar actions. Users need **named modes**
   (research §5.3 #8, §6). Exactly **two** modes — Seal is secondary, not a third radio.
3. **Status / honesty:** Lock state must remain visible every frame. “Mount” must not claim Finder
   mount when only unlock/validate is available (Yee *Expected Ability*; UC-25 ADR-0010 residual).
4. **Trust copy:** First-run, About, and unlock footer state **local-only / no account / no cloud**
   (Alodhyani et al.; research §5.9) without marketing overclaim.

---

## 5. Proposed design

### 5.1 Architecture (presentation only)

```
┌─────────────────────────────────────────────────────────────┐
│  Blindkey                    [ status: Locked | Unlocked ]  │
├───────────────┬─────────────────────────────────────────────┤
│ Mode          │  Content pane                               │
│ ○ Credentials │  unlock / search / entry detail / Add        │
│ ○ Workspace   │  volume list / Create / Unlock / Reveal /   │
│               │  Eject                                      │
│ ───────────── │                                             │
│ Seal files…   │  secondary entry (picker / drop) → .vltf    │
│ (not a mode)  │                                             │
└───────────────┴─────────────────────────────────────────────┘
```

- **Mode enum** on the GUI app state (e.g. `GuiMode { Credentials, Workspace }`).
- Seal remains a **dialog/flow**, reachable from Workspace sync-refuse CTA (C73) and a secondary
  control — not a third equal radio (research §0 / §6 diagram fixed 2026-07-29).
- All secret delivery stays in `blindkey-core` / `blindkey-clip` (C27, C45).

### 5.2 Phase A — Legibility gate (blocker)

**Normative Cargo change** (workspace pin):

```toml
eframe = { version = "0.29", default-features = false,
           features = ["glow", "default_fonts", "wayland", "x11"] }
```

Rules:

- Keep **no `persistence`** (C41 / UC-20).
- After enable: screenshot unlock screen; assert non-empty glyph bounds in an automated
  smoke if feasible, else maintainer screenshot in PR.
- Theme: egui `Visuals` with text/background contrast meeting **WCAG 2.2 AA** for primary labels
  (**1.4.3:** 4.5:1 normal text) and UI chrome (**1.4.11:** 3:1 non-text). Do not rely on
  emoji alone for meaning.
- Color rhythm (research §5.7): one accent for primary; green only for confirmed safe completion;
  amber for warnings (sync CTA, residual); red only for destructive confirm. Status **Locked**
  uses icon + text (not color alone).
- Optional later: embed a known TTF via egui font APIs if `default_fonts` proves insufficient
  on a platform — document in `docs/INSTALL.md`.

**Exit criterion:** Unlock, Lock, Credentials, Workspace, Copy labels are visually present on
macOS and Linux smoke builds.

### 5.3 Phase B — Mode chrome & status

| Rule ID | Behavior |
|---------|----------|
| IA-01 | Persistent status chip/text: vault **Locked** / **Unlocked**; Workspace also **Mounted** when a mount path exists. After **Eject**, status returns to **Locked** (Eject is a closure event, not a persistent status). Never status-by-color-alone |
| IA-02 | Mode switch: **Credentials** \| **Workspace** only (radio or segmented control) |
| IA-03 | Credentials top actions: Search focus, **Add**, **Lock**, Audit (existing) — not Volume |
| IA-04 | Workspace top actions: **Create volume**, list selection → Unlock / Reveal / Eject |
| IA-05 | Seal: control labeled **Seal files…**; from C73 refuse, primary recovery is Seal CTA |
| IA-06 | Primary chrome verbs are human: Credentials, Workspace, Seal files, Unlock, Eject, Reveal in Finder — not VLTF/VLTD/Kcom as sole primary button text |
| IA-07 | One primary button per dialog; Cancel always available; no wizard traps |
| IA-08 | Primary interactive targets ≥ **24×24 CSS px** (WCAG 2.5.8) or documented equivalent-control exception |
| IA-09 | Paste **enabled** on all passphrase/secret fields; show/hide toggle on passphrase entry (NIST SP 800-63B-4 / WCAG 3.3.8) |
| IA-10 | Workspace create path picker **defaults to local**; warn/refuse sync roots (align C73) |
| IA-11 | Create flows: confirm passphrase match before write; Delete entry requires confirm |
| IA-12 | Every crypto job ends with explicit closure (“Volume created,” “Entry saved,” “Ejected — files locked,” unlock success line) |
| IA-13 | Long jobs (Argon2 / create / seal): indeterminate progress + **Cancel**; on cancel, leave disk unchanged (research §7.4) |
| IA-14 | Residual-risk banner once/session before first Workspace unlock (C72); include best-effort lock-on-sleep note per UC-25 residual copy |

### 5.4 Phase C — Credentials mode (Chiasson / C27)

Screen contract (research §7.1–§7.2):

| Screen | Primary | Feedback |
|--------|---------|----------|
| Unlock / Create | Unlock · Create vault; secondary **Choose vault file…**; show/hide + paste | Argon2 “Deriving key…” + Cancel when long; footer “Stored only on this computer.” |
| Home | Search (focus) · **Copy** (primary) · Reveal (secondary, timed C46) · Add · Lock | “Copied. Clipboard clears in Ns.” (config default **30s**; ✓ `DEFAULT_CLIPBOARD_TIMEOUT_SECS`) |
| Add / Edit | Save · Generate | Inline field errors; Save disabled until title non-empty |
| Empty | **Add entry** + secondary **Import keys.txt** | Apple HIG empty-state pattern |
| About / help | One trust line | “Local only. No account. No cloud.” (research §5.9) |

Preserve: copy-default, timed reveal (C46 / **15s** `REVEAL_TIMEOUT_SECS`), virtualized list (C52),
search metadata-only (C35).

### 5.5 Phase D — Workspace mode (Cryptomator-class)

Screen contract (research §7.3):

| Screen | Primary | Feedback |
|--------|---------|----------|
| Empty | **Create volume** | Path defaults **local** (IA-10); one line: Workspace = edit as folder; Seal = encrypt for Dropbox/USB |
| Locked row | **Unlock** | Residual-risk banner **once per session** + lock-on-sleep note (IA-14 / C72) |
| Unlocked / mounted | **Reveal in Finder** · **Eject** | Status pill Locked / Unlocked / Mounted |
| Sync-root path | Refuse | Seal CTA (C73) — already in `volume_gui` |

**Mount honesty (normative):**

- If OS mount is unavailable (macOS stub / missing Fuse-T packaging): primary success copy after
  unlock is **“Volume unlocked (validated). Finder mount needs Fuse packaging on this Mac.”**
  — not a silent “Mounted” success (research §5.8 B4).
- Button labels: prefer **Unlock** when mount is unavailable; **Reveal in Finder** only when a
  mount path exists.
- Never auto-remount in background (Shneiderman control; UC-25 posture).

### 5.6 Phase E — Progressive disclosure & microcopy

| Always visible | Behind Advanced / Settings |
|----------------|----------------------------|
| Passphrase, Unlock/Create | Weak-KDF, expect-min-version, YubiKey enroll |
| Title, secret, Generate, Save | Custom fields, notes, URL, keyfile 2FA |
| Workspace path, size, passphrase, Create | Block size, max size, `--no-pad`, KDF params |
| Workspace unlock passphrase | Keyfile path, ignore-anchor / trust-anchor |

Microcopy table (research §5.6) is normative for new/changed strings:

| Situation | Prefer |
|-----------|--------|
| Unlock fail (vault) | “Vault could not be unlocked. Check passphrase.” (optional Caps Lock / keyfile hint — vault only; never for sealed/volume open — C74) |
| Volume open fail | Uniform open string culture (C74) — no parse oracle |
| Copy | “Copied. Clipboard clears in Ns.” |
| Sync refuse | “Dropbox sync of a live volume is unsupported. Seal files instead.” |
| First run / About | “Blindkey keeps secrets and encrypted folders on this computer. No account. No cloud.” |
| Create vault | “Choose a strong passphrase. You cannot recover it if forgotten.” |
| Passphrase mismatch | “Passphrases don’t match — retype confirm.” |

### 5.7 First-run (≤15 s reading)

On first launch (config flag, dismissible forever):

```
Blindkey keeps secrets and encrypted folders on this computer.
No account. No cloud.

[ Create vault ]     [ Open existing… ]
```

Optional second beat after first vault unlock (dismissible):

```
Next: Add an API key, or open Workspace to create an encrypted folder.
[ Add entry ]  [ Open Workspace ]  [ Not now ]
```

### 5.8 Motion & density

- 150–250 ms fade only for mode switch / dialog — no continuous “crypto” animation
- Indeterminate progress for Argon2 / create / seal
- Countdown for clipboard / reveal only
- Credentials density ≈ mail client (list + detail); Workspace ≈ Cryptomator (list + big Unlock)

---

## 6. Constraint compliance map

### 6.1 Existing (must not regress)

| Constraint | Note |
|------------|------|
| C20 | Single binary; egui stays |
| C27 | Copy-default; no secret strings in shell state beyond timed reveal |
| C40–C45 | Reactive repaint, glow, cache, virtualize, password mask, thin shell |
| C46–C54 | Reveal timeout, blur lock, keyfile GUI, banner, clipboard config, labels |
| C72 / C73 | Residual banner; sync-root refuse + Seal CTA |
| C74 | Uniform volume open error culture |

### 6.2 Candidate constraints (promote on Accept → intent)

Propose as **G18** in `blindkey_intent.yaml` when this spec is Accepted (same pattern as UC-20/21).

| ID | Title | Test sketch |
|----|-------|-------------|
| **C75** | Desktop GUI embeds readable fonts | Manifest includes `default_fonts` (or documented embedded TTF); unlock smoke shows non-empty labels |
| **C76** | Desktop GUI shows lock/mount status every frame | Status widget present in Credentials + Workspace when window open |
| **C77** | Desktop GUI separates Credentials and Workspace modes | Mode switch exists; Volume actions only in Workspace; Seal is not a third mode |
| **C78** | Desktop GUI primary chrome uses human labels | No VLTF/VLTD/Kcom as sole primary button text |
| **C79** | Desktop GUI does not claim mount when unavailable | macOS-without-provider path: unlock success ≠ “Mounted”; Reveal gated on mount path |
| **C80** | Desktop GUI progressive-discloses advanced volume/vault options | Advanced KDF / anchors behind disclosure; create/unlock usable without opening Advanced |
| **C81** | Desktop GUI primary chrome meets WCAG AA contrast + target size | Theme fg/bg documented (≥4.5:1 text); primary targets ≥24×24 or exception noted |

Until promotion, treat C75–C81 as **spec-normative** for implementation PRs; intent remains SoT after merge.
IA-09–IA-14 are **design-normative** in this spec (regression via T8–T12) without separate constraint IDs unless promotion expands G18.

---

## 7. Test plan

### 7.1 Automated / in-tree

| ID | Covers | Method |
|----|--------|--------|
| T1 | C75 | `Cargo.toml` feature assertion test (mirror UC-20 persistence absence test) |
| T2 | C77 | GUI unit/UI-state test: Workspace actions unreachable while mode=Credentials; no Seal mode enum variant |
| T3 | C79 | Mount-unavailable path asserts honest status string (fixture / cfg flag) |
| T4 | C73 | Existing `volume_gui` Seal CTA tests remain green |
| T5 | C40–C54 | Existing `uc20` / `uc21` / `uc25` GUI constraint suites remain green |
| T6 | Regression | Manual or scripted: unlock → search → Copy → Lock; Workspace create → unlock → eject |
| T7 | C76 | Status widget present after unlock and in Workspace (state assertion / snapshot) |
| T8 | C78 | Grep/UI test: primary chrome strings exclude sole-token VLTF/VLTD/Kcom |
| T9 | C80 | Create volume / unlock reachable with Advanced collapsed |
| T10 | C81 | Documented `Visuals` contrast constants; review checklist for 24×24 targets |
| T11 | IA-09 | Passphrase `TextEdit` accepts paste; `.password(true)` + show/hide control present |
| T12 | IA-10–IA-13 | Create confirm-match; cancel create leaves no partial volume; closure strings on success |

### 7.2 Heuristic evaluation (ISO 9241-210 lightweight)

Before inviting users: walk research §5.2 (Nielsen) + §5.3 (Shneiderman); log severity
cosmetic / minor / major / catastrophic. **Ship gate:** zero catastrophic + zero major open.

### 7.3 Cognitive walkthrough (Whitten / Chiasson bar)

Five users, three tasks (research §9.2):

1. Create vault → add API key → copy → lock  
2. Create local `.vltd` → unlock → read residual banner → eject  
3. Attempt sync-root path → see Seal CTA  

**Pass:** ≥4/5 complete each without dangerous error; all can state locked vs unlocked at end.

**Great bar (Likert median ≥4):** “I always knew whether things were locked”; “I would trust this
with an API key I care about”; “I understand Credentials vs Workspace.”

---

## 8. Implementation segments (IVD)

For 3+ constraints, implement **one segment at a time**; re-read this spec + intent candidates
from disk between segments.

| Seg | Work | Exit |
|-----|------|------|
| **A0** | Fonts + AA theme + screenshot proof | Legibility gate |
| **A1** | `GuiMode` + status chip; relocate Volume controls; Seal secondary | Mode chrome compiles |
| **A2** | Credentials empty/first-run/About + microcopy + paste/show-hide | Journey A smoke |
| **A3** | Workspace Cryptomator layout + mount honesty + local path default | Journey B smoke |
| **A4** | Progressive disclosure Advanced + confirm-match / cancel / closure | Create usable without Advanced |
| **A5** | Tests T1–T12 + heuristic log in PR | Spec → Implemented candidate |
| **A6** | Intent promotion C75–C81 + CONSTRAINT_INDEX | Gate for “Accepted · implemented” |

No ADR required unless a future change abandons egui or changes C20 — IA inside egui is reversible.

---

## 9. Open questions

1. **Intent timing:** Promote C75–C81 in the same PR as A5, or Accept this Draft first then implement?
2. **Default mode after unlock:** Credentials (recommended) vs remember last mode?
3. **TUI parity:** Out of scope here — file follow-up if `blindkey-tui` needs Workspace mode labels?
4. **About placement:** Prefer a quiet About/help control vs unlock-footer-only for the trust line (trust line itself is **in scope** — research §5.9).

---

## 10. Deferred ledger

| ID | Item | Why deferred |
|----|------|--------------|
| DF-1 | SwiftUI shell | UC-18 P3 / S-18 |
| DF-2 | macOS FUSE packaging | UC-25 ADR-0010 / Phase C |
| DF-3 | Full AccessKit audit | Beyond C44/C54 |
| DF-4 | eframe 0.34 bump | UC-21 DG-3 |
| DF-5 | Private `*_patterns.yaml` distill | Operator tree only; public SoT = this spec + research MD |
| DF-6 | Vault unlock Argon2 “Deriving key…” + Cancel on UI thread | Seal/volume jobs already cancel; credential unlock remains sync until a shared unlock-job pattern lands |
| DF-7 | Multi-volume list (Cryptomator vault list) | v1 Workspace is single active_path + Create/Unlock; list selection deferred |
| DF-8 | Live `Mounted` / Reveal when Fuse packaging ships | `mount_path` gated correctly; setter awaits UC-25 ADR-0010 provider |

---

## 11. Changelog

| Date | Change |
|------|--------|
| 2026-07-29 | **Draft v0.1** — IA + legibility + honesty contract from `desktop_security_ui_research.md` |
| 2026-07-29 | **Draft v0.2** — Spec↔research cross-check: ISO §7 ref; KeePassXC ~; Seal not a mode (align research §6); status Locked after Eject; IA-08–IA-14 (target size, paste/show-hide, local path, confirms, closure, cancel, residual/sleep note); Credentials Reveal secondary + Choose vault file; About trust line in-scope; color rhythm; Cryptomator Lock→Eject mapping; tests T7–T12; C81 includes target size; feel goals pointer |
| 2026-07-29 | **Implemented v1.0** — `default_fonts` + `theme.rs`; `GuiMode`/`SessionStatus`; Credentials\|Workspace chrome; Seal secondary; Workspace home; mount honesty; Advanced disclosure; first-run/next-beat; intent G18 C75–C81; `uc26_constraints.rs`; ROADMAP S-25 |
| 2026-07-29 | **Validate polish** — simplified unlocked chrome; `SessionStatus` for Workspace; platform Reveal labels; uc25/uc26/uc20 test sync; DF-6 vault Argon2 cancel residual |
| 2026-07-29 | **In-depth review + harden** — first-run Create\|Open CTAs; seal show/hide + preferred mismatch; empty-state Import; C73 Seal recovery CTA; expanded T1–T12 + unit tests; DF-7/DF-8 |
