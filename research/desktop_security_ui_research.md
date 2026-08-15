# Desktop security UI for Blindkey — research (usable security + great UX)

> **Task:** Survey **trusted standards, academic usable-security literature, classic UX
> heuristics, and peer product patterns** for a desktop experience that is both **secure and
> delightful** — local-first credential vault **and** local encrypted workspace volume — then
> recommend one information architecture **and** a concrete UX practice playbook for Blindkey.
>
> Research date: **2026-07-29** (expanded same day: UX playbook §5–§7; **source
> cross-check** same day — see §13). Markers:
> ✓ verified against primary source this pass · ~ corroborated / secondary · ? assumed
> (do not treat as load-bearing).
>
> **Companion docs:** [`ui_architecture.md`](ui_architecture.md) (toolkit / trust-boundary:
> egui vs Tauri vs SwiftUI — **how** to render), this doc (**what** screens, mental models,
> and **how it should feel** security-wise). **Visual craft / history / layout systems:**
> [`desktop_app_ui_ux_research.md`](desktop_app_ui_ux_research.md) (classic → 2026 HIGs — **how it
> should look**). **Components / styling:**
> [`desktop_ui_components_styling_research.md`](desktop_ui_components_styling_research.md)
> (cards, button roles, boxed lists — post–UC-27 polish). Volume crypto:
> [`encrypted_volume_mount_research.md`](encrypted_volume_mount_research.md).
> Specs: [UC-18](../docs/specs/UC-18-native-ui.md), [UC-20](../docs/specs/UC-20-desktop-gui-hardening.md),
> [UC-21](../docs/specs/UC-21-desktop-gaps-closure.md), [UC-25](../docs/specs/UC-25-local-encrypted-volume.md),
> [UC-26](../docs/specs/UC-26-desktop-ui-information-architecture.md) (IA/usability contract),
> [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md) (visual craft contract — Draft).
>
> **Incident that triggered the usable-security pass:** macOS `blindkey-gui` screenshot (2026-07-29)
> showed widget outlines / buttons with **no visible labels** — missing fonts. **Follow-up craft
> incident (same day):** fonts fixed; unlock/create screen still looked unfinished (alignment,
> redundancy, hierarchy) — see `desktop_app_ui_ux_research.md` §1.

---

## 0. Executive finding (read this first)

Security UIs fail when they look “pretty” but leave users with the wrong **mental model** of
what is protected, what is cleartext, and whether a task finished (Whitten & Tygar 1999;
Chiasson et al. 2006). Password-manager studies add: many users treat managers as
**convenience**, not security tools, and **distrust** blocks storing high-value secrets
(Klivan et al., SOUPS 2023); adoption is limited more by **trust/transparency** than by
raw usability friction in some surveys (Alodhyani et al. 2020). Volume apps that work
(Cryptomator) use a tiny action set: **Unlock → Reveal → Lock**, with status always visible.

A **great** Blindkey experience (not merely a correct one) also applies Nielsen’s heuristics
and Shneiderman’s golden rules: fast status feedback, progressive disclosure of power features,
closure after every crypto job, undo where safe, recognition over recall, and calm minimal
chrome focused on the user’s goal — not on crypto vocabulary (NN/g; Shneiderman UMD).

**ONE recommended UI for Blindkey (desktop):**

> **Two named product modes, never mixed on one toolbar:**
> 1. **Credentials** — unlock vault → search-first home → **Copy** (default) / time-boxed
>    Reveal / Add entry. Feels like a fast, trusted notebook for secrets (C27).
> 2. **Workspace** — create / unlock `.vltd` → honest residual banner once → **Reveal in
>    Finder** when FUSE is available / **Eject**. Feels like Cryptomator: three verbs, always
>    know locked vs open. Never imply cloud-sync of a live volume (C73); Seal CTA for cloud.
>
> **Feel goals:** calm, fast, honest, local-first trust — never “security theatre,” never blank
> glyphs, never surprise cleartext. Toolkit stays C20-aligned (fix egui fonts first; native
> SwiftUI shell later per `ui_architecture.md`).

Do **not** lead with a dense “security dashboard.” Do **not** put Volume next to Add as
equal chrome without mode framing — that recreates the PGP “many buttons, wrong model”
failure mode.

---

## 1. Problem statement (Blindkey-specific)

Blindkey’s desktop app must support three **different** security objects:

| Object | File | User goal | Cleartext while “open”? |
|--------|------|-----------|-------------------------|
| Credential vault | `.vlt` | Store/retrieve secrets | Only after unlock; prefer clipboard |
| Sealed archive | `.vltf` | Encrypt files for cloud/USB | Only after extract |
| Workspace volume | `.vltd` | Edit files as a folder | **Yes — OS sees cleartext while mounted** (C72 / SC10) |

Mixing these without naming them produces dangerous errors: users think a mounted volume is
“as blind as clipboard copy,” or think Seal and Volume are the same feature. Academic
usable-security work treats that class of error as a **first-class design failure**, not a
help-doc problem.

---

## 2. Academic usable-security literature (primary)

### 2.1 Whitten & Tygar — *Why Johnny Can’t Encrypt* (USENIX Security 1999)

✓ Primary: [USENIX proceedings](https://www.usenix.org/conference/8th-usenix-security-symposium/why-johnny-cant-encrypt-usability-evaluation-pgp-50);
PDF case study [Berkeley mirror](https://people.eecs.berkeley.edu/~tygar/papers/Why_Johnny_Cant_Encrypt/Usability_case_study.pdf).

**Claims that still bind Blindkey:**

1. Effective security needs a **different usability standard** than consumer software —
   attractive chrome is not enough.
2. Usable security software must let users:
   - be reliably **aware** of the security tasks they must perform;
   - **figure out how** to perform them;
   - avoid **dangerous errors**;
   - be comfortable enough to **keep using** the tool.
3. Lab result (N=12, 90 minutes): only **one third** correctly signed and encrypted email;
   **one quarter** accidentally sent the secret in the clear while believing it was encrypted
   (✓ USENIX write-up). The abstract’s “majority … unable” is accurate as a summary of task
   failure; use the N=12 fractions when citing precision.

**Design translation:** every Blindkey screen must answer “Am I locked or unlocked?” and
“Did my last security action succeed?” without jargon. Prefer **few primary verbs**.

### 2.2 Chiasson, van Oorschot, Biddle — password managers (USENIX Security 2006)

✓ Primary: [PDF](https://www.usenix.org/legacy/event/sec06/tech/full_papers/chiasson/chiasson.pdf)
(*A Usability Study and Critique of Two Password Managers*).

Extends Whitten/Tygar with two criteria especially relevant to vault UIs:

5. Users must be able to tell **when the task completed**.
6. Users must have enough feedback to know the **current system state**.

They warn that **over-transparency** (hiding security state so the UI “feels like a normal
app”) lets users invent wrong mental models — e.g. believing a secret is protected when it
is not.

**Design translation:** lock badge, vault path, volume mount state, and “copied — clears in
N s” toasts are not decoration; they are security UI. Residual-risk copy on volume mount is
mandatory honesty (already in UC-25), not optional marketing.

### 2.3 SOUPS — mental models & setup friction (2017–2023)

| Paper | Venue | Finding for Blindkey |
|-------|-------|----------------------|
| Prinz et al., *Mental Models of Password Managers* | SOUPS 2017 poster | ✓ Qualitative interviews (N=14) + drawings; mental spaces include **Create / Organize and Commit** (and related coping); generators + guidance matter; personalization/adaptation proposed to raise adoption. [USENIX PDF](https://www.usenix.org/sites/default/files/soups17_poster_prinz.pdf) |
| Klivan, Höltervennhoff, Huaman, Acar, Fahl | SOUPS 2023 | ✓ Survey N=279 + expert review of 14 PMs: many use PMs for **convenience**, not as a security tool; prioritize what to add; **severe distrust** leads some to skip important passwords. [USENIX](https://www.usenix.org/conference/soups2023/presentation/klivan) · [PDF](https://www.usenix.org/system/files/soups2023-klivan.pdf) |
| Carreira, Ferreira, Mendes — PassCert / Bitwarden notes | INFORUM 2021 | ✓ Review of PM usability challenges + proposed Bitwarden improvements; cites Shneiderman’s golden rules, security-by-default, tooltips over jargon. [PDF](https://joaoff.com/publication/2021/Inforum/INFORUM2021_UsabilityPMs.pdf) |

**Design translation for “encrypt a key”:** one obvious **Add** path; generator on the form;
no “security theatre” checkboxes; local-first / no-account messaging on first unlock to
address distrust.

### 2.4 Cranor & Garfinkel context

✓ SOUPS community (Symposium on Usable Privacy and Security) and the *Security and Usability*
line of work treat “user-centered security” as a research field since the mid-1990s
(Zurko & Simon 1996, cited widely in Chiasson et al.). Blindkey should evaluate UI changes
with **task success** (create vault, add secret, copy, create volume, refuse sync root), not
only aesthetic review.

---

## 3. Standards & platform guidelines (authoritative)

### 3.1 NIST SP 800-63B-4 (Digital Identity — Authentication)

✓ Primary: [NIST pages](https://pages.nist.gov/800-63-4/sp800-63b.html);
[PDF SP 800-63B-4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf).

Relevant to **vault** UX (not federal AAL certification of Blindkey itself):

- Verifiers **SHALL** allow password managers and autofill; **SHOULD** allow **paste** into
  password fields so managers work when autofill APIs are unavailable (✓ SP 800-63B-4
  authenticator / memorized-secret requirements pages).
- Verifiers **SHOULD** offer an option to **display the password** while it is entered
  (same source).
- Broader digital-identity guidance favors longer secrets and generators over complex
  composition rules (~ product translation; exact composition-rule language lives in the
  memorized-secret requirements — do not over-cite as a UI mandate).

**Design translation:** never block paste on master-password or entry-secret fields; offer
show/hide on entry; keep generator on Add/Edit (already aligned with Blindkey).

### 3.2 WCAG 2.2 (W3C Recommendation, 2023-10-05)

✓ Primary: [What’s new in WCAG 2.2](https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/).

| Criterion | Level | Blindkey implication |
|-----------|-------|----------------------|
| **1.4.3 Contrast (Minimum)** | AA | Text ≥ **4.5:1** vs background (large text ≥ 3:1). Dark-on-dark body text **fails**. |
| **1.4.11 Non-text Contrast** | AA | UI components and graphical objects ≥ **3:1** against adjacent colors. |
| **2.5.8 Target Size (Minimum)** | AA | Interactive targets ≥ **24×24 CSS px** (or spacing / equivalent-control exceptions). |
| **3.3.8 Accessible Authentication (Minimum)** | AA | Auth must not rely on cognitive tests without an assist mechanism — **password managers / paste** count. Do not disable paste. |
| **2.4.11 Focus Not Obscured** | AA | Keyboard focus must remain at least partially visible (relevant if AccessKit / keyboard nav expands). |

**Design translation:** fix contrast and fonts before any visual redesign. Empty-looking
controls with missing glyphs are an **accessibility failure**, not a style choice.

### 3.3 Apple Human Interface Guidelines (writing + privacy)

✓ Writing: [HIG — Writing](https://developer.apple.com/design/human-interface-guidelines/writing)
(fetched 2026-07-29).

- Match tone to context; **be clear**; put the most important information first.
- Buttons: **verbs**; prefer “Send” over clever copy.
- Errors: near the problem, **no blame**, say how to fix (“Choose a password with at least
  8 characters,” not “Invalid”).
- Empty states: say **what to do next** with a control.
- Avoid “we” in errors (“Unable to unlock vault” > “We’re having trouble”).

✓ Privacy pillars (WWDC24): data minimization, on-device processing, transparency & control,
security — [WWDC 2024 What’s new in privacy](https://developer.apple.com/videos/play/wwdc2024/10123/).
Blindkey’s local-first story matches on-device processing; UI must make that **legible**.

### 3.4 Microsoft Fluent / Windows app settings

✓ [Guidelines for app settings](https://learn.microsoft.com/en-us/windows/apps/design/app-settings/guidelines-for-app-settings):
group related settings; immediate effect; binary toggles; descriptive one-word headers;
separate elevation-sensitive actions (UAC shield pattern historically).

✓ [Passkeys design patterns](https://learn.microsoft.com/en-us/windows/apps/develop/security/design):
clear create/manage affordances; avoid vague crypto jargon — prefer familiar biometrics
language when relevant.

**Design translation:** Blindkey Settings (clip timeout, lock-on-blur) as a short card list;
hardware enroll (YubiKey / keyfile) clearly marked as advanced, not on the home chrome.

---

## 4. Peer product patterns (encrypted volume + vault)

### 4.1 Cryptomator (volume / vault UX — best peer for UC-25)

✓ Docs: [Accessing vaults](https://github.com/cryptomator/docs/blob/develop/docs/desktop/accessing-vaults.mdx);
redesign intent [#926](https://github.com/cryptomator/cryptomator/issues/926).

Canonical flow:

1. Select vault in a **list** (status: locked / unlocked).
2. **Unlock** → password → success.
3. **Reveal** (open Finder/Explorer at mount point).
4. **Lock** when done.

Detail pane always shows: name, storage location (ciphertext), access point (cleartext view),
**current status**.

**Why this wins for Blindkey Workspace mode:** tiny verb set; status is impossible to miss;
Reveal separates “unlocked in app” from “open in OS” — critical for C72 honesty.

### 4.2 VeraCrypt

~ Traditional mount dialog (drive-letter / volume list, Mount / Dismount, PIM and other
advanced options) — described in VeraCrypt UI documentation and maintainer materials;
**high cognitive load** for novices (same risk class as PGP). Not re-verified against a
single official “UI design guide” PDF this pass.

**Design translation:** keep advanced KDF / keyfile behind “Advanced”; default path stays
Cryptomator-simple.

### 4.3 Credential managers (lessons, not to copy Electron)

- ~ **1Password 8 Electron backlash** (documented in `ui_architecture.md`): users punish
  non-native feel + RAM for a security tool. Reinforces C20 thin-shell choice.
- Pattern that works across Bitwarden / native managers: **search-first** unlocked home;
  **Copy** as primary; Reveal secondary; autofill/paste friendliness (NIST).

---

## 5. Making the experience *great* — UX practice playbook

This section turns “usable security” into **product feel**: what makes Blindkey pleasant to
reach for daily without weakening C27/C72/C73. Sources: Nielsen Norman Group heuristics
(✓ [NN/g ten heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/)),
Shneiderman’s Eight Golden Rules (✓ [UMD](https://www.cs.umd.edu/users/ben/goldenrules.html)),
NN/g progressive disclosure (✓ [article](https://www.nngroup.com/articles/progressive-disclosure/)),
Ka-Ping Yee’s secure interaction principles (✓ [UCB CSD-02-1184](https://digitalassets.lib.berkeley.edu/techreports/ucb/text/CSD-02-1184.pdf)),
and Apple HIG Writing (§3.3).

### 5.1 Feel goals (non-negotiable)

| Goal | What the user should feel | Anti-pattern |
|------|---------------------------|--------------|
| **Calm** | “I know what’s locked.” Quiet chrome, one focus | Alarm spam, red everywhere, emoji soup |
| **Fast** | Search → Copy in &lt;2 clicks after unlock | Multi-step wizards for common tasks |
| **Honest** | Mounted = OS can see files; clipboard clears | Marketing “military grade” without state |
| **Trusted** | Local-only, no account, no telemetry | Ambiguous cloud sync affordances |
| **Recoverable** | Mistakes are undoable or clearly fixable | Silent failure; “Invalid” with no next step |
| **Readable** | Every label visible at WCAG AA | Missing fonts / low contrast (current bug) |

Great ≠ flashy. Great = **competence + control** (Shneiderman) without dangerous errors
(Whitten).

### 5.2 Nielsen’s 10 heuristics → Blindkey behaviors

✓ Source: Nielsen (1994 / NN/g 2020 refresh).

| # | Heuristic | Blindkey “great” behavior |
|---|-----------|---------------------------|
| 1 | **Visibility of system status** | Persistent **Locked / Unlocked** (and for volumes: Locked / Unlocked / Mounted — **Eject** is a closure event, then status returns to Locked). Argon2 shows “Deriving key…” with cancel when long. Clipboard: “Copied. Clipboard clears in Ns.” with live countdown (Blindkey GUI default **`DEFAULT_CLIPBOARD_TIMEOUT_SECS = 30`**; reveal timeout **15s** — ✓ `gui_config.rs`). |
| 2 | **Match the real world** | Say **Credentials**, **Workspace**, **Seal files** — not VLTF/VLTD/Kcom in primary UI. “Eject” / “Reveal in Finder” beat “umount”. |
| 3 | **User control and freedom** | Cancel on create/unlock jobs; Lock always one click; Exit dialogs without saving; never trap in a wizard. |
| 4 | **Consistency and standards** | Same password field pattern everywhere; same primary button placement; macOS: ⌘W / Esc close; Follow Finder file-picker habits (`rfd`). |
| 5 | **Error prevention** | Default save path = local (not Dropbox); confirm **Delete entry**; refuse sync-root mount; disable Save until title non-empty; confirm passphrase match on create. |
| 6 | **Recognition rather than recall** | Recent volumes / vault path shown; search highlights matches; generator on Add form; don’t force remembering CLI flags. |
| 7 | **Flexibility and efficiency** | Power users: keyboard focus search, Enter to copy selected, shortcuts for Lock; novices never see Advanced KDF until they ask. |
| 8 | **Aesthetic and minimalist** | Home = search + list + one detail pane. No metrics dashboard. Seal is secondary, not a third equal tab competing for attention. |
| 9 | **Error recognition & recovery** | Plain language + fix: “Passphrases don’t match — retype confirm.” Wrong vault unlock → clear recovery hint (Caps Lock / keyfile) **without** leaking whether the file parsed (align with C64/C74 culture for sealed/volume: uniform open string). Sync refuse → button **Seal files instead**. |
| 10 | **Help and documentation** | Context tooltips (“While mounted, Finder sees cleartext”). First-run card: 3 bullets max. Deep docs linked, not stuffed into the unlock screen. |

### 5.3 Shneiderman’s Eight Golden Rules → product rules

✓ Source: Shneiderman, *Designing the User Interface* (UMD golden rules page).

1. **Consistency** — Unlock/Create/Copy/Eject always mean the same thing across modes.
2. **Universal usability** — Large targets, high contrast, AccessKit path later; no hover-only meaning.
3. **Informative feedback** — Every click that touches crypto gets proportional feedback (toast or status line).
4. **Closure** — Every job ends with a clear Done state: “Volume created,” “Entry saved,” “Ejected — files locked.”
5. **Prevent errors** — Constraints & defaults over post-hoc warnings when possible.
6. **Easy reversal** — Soft-delete or confirm for entry delete; cancel long seal/create; re-lock is always available (reversal of unlock).
7. **Keep users in control** — No background remount; no auto-unlock without explicit gesture; agent broker stays out of GUI primary path.
8. **Reduce memory load** — One mode at a time; don’t ask users to remember whether Volume and Seal are different — **name them**.

### 5.4 Progressive disclosure (NN/g) — keep power, hide complexity

✓ [NN/g Progressive Disclosure](https://www.nngroup.com/articles/progressive-disclosure/): show only
the most important options first; disclose the rest on request.

| Layer | Always visible | Behind “Advanced…” / Settings |
|-------|----------------|-------------------------------|
| Credentials unlock | Passphrase, Unlock/Create | Weak-KDF (hidden), expect-min-version, YubiKey enroll |
| Add entry | Title, secret, Generate, Save | Custom fields, notes, URL, keyfile 2FA |
| Workspace create | Path, size, passphrase, Create | Block size, max size, `--no-pad`, KDF params |
| Workspace unlock | Passphrase, Unlock | Keyfile path, ignore-anchor / trust-anchor |

Cisco’s security-UX writeup (~) reinforces the same pattern for overloaded security consoles:
summary first, drill-down later — Blindkey is smaller, but the principle holds.

### 5.5 First-run, empty states, and onboarding (delight without lectures)

✓ Apple HIG Writing: empty states need a **next action**; be clear; avoid “we.”

**First launch (≤15 seconds of reading):**

```
Blindkey keeps secrets and encrypted folders on this computer.
No account. No cloud.

[ Create vault ]     [ Open existing… ]
```

Optional second beat after vault unlock (dismissible forever):

```
Next: Add an API key, or open Workspace to create an encrypted folder.
[ Add entry ]  [ Open Workspace ]  [ Not now ]
```

**Empty Credentials home:** illustration-free; one sentence + **Add entry** + “Import keys.txt”
as secondary. Never a blank void (the broken-font screenshot is the anti-example).

**Empty Workspace:** “No volumes yet” + **Create volume** + one-line difference from Seal:
“Workspace = edit as a folder. Seal = encrypt files for Dropbox/USB.”

### 5.6 Microcopy & tone (trust + clarity)

| Situation | Prefer | Avoid |
|-----------|--------|-------|
| Unlock fail | “Vault could not be unlocked. Check passphrase.” | Stack traces; “Error 0x…” |
| Copy success | “Copied. Clipboard clears in 30s.” (or live `N` from config) | “Success!” with no expiry |
| Mount residual | Banner from UC-25 (honest FileVault-class) | “Your files are 100% private while open” |
| Sync refuse | “Dropbox sync of a live volume is unsupported. Seal files instead.” | “Are you sure?” alone |
| Create vault | “Choose a strong passphrase. You cannot recover it if forgotten.” | Fear-mongering paragraphs |

Yee (UCB CSD-02-1184): ten principles include **Clarity** (“effect of any security-relevant
action must be clearly apparent … before the action is taken”), **Visibility**, and
**Expected Ability** (“must not generate the impression that it is possible to do something
that cannot actually be done”) — ✓ fetched tech report. Never imply an action is possible
that isn’t (e.g. “Mount” on macOS without FUSE must say what’s missing, not fail silently).

### 5.7 Motion, density, and visual rhythm

For a security desktop app, motion should **confirm state change**, not decorate:

| Motion | Use | Don’t |
|--------|-----|-------|
| 150–250 ms fade/slide | Dialog open/close; mode switch | Continuous particle “crypto” animations |
| Progress indeterminate | Argon2 / seal / create | Fake determinate bars |
| Countdown | Clipboard clear; reveal timeout | Flashing urgency colors |

**Density:** Credentials home ≈ mail client (list + detail). Workspace ≈ Cryptomator (list +
big Unlock). Prefer **whitespace + hierarchy** over packing every UC into the title bar.

**Color:** one accent for primary actions; green only for confirmed safe completion; amber for
warnings (sync CTA, residual); red only for destructive confirm. Status “Locked” should be
readable without color alone (icon + text) — WCAG.

### 5.8 Journey maps — the two “great” paths

**A. Encrypt / store a key (Credentials)** — target ≤60 s cold:

1. Open app → unlock (or create) with clear passphrase field + show/hide.
2. Land on **search-focused** home (focus in search).
3. **Add** → title + secret + Generate → Save → closure toast.
4. Select entry → **Copy** (primary) → countdown feedback.
5. **Lock** before walking away — one obvious control.

**B. Encrypted disk (Workspace)** — target ≤90 s cold:

1. Switch to **Workspace** mode (labeled).
2. **Create volume** → local path → passphrase → Create → closure.
3. Residual banner once → Unlock.
4. **Reveal in Finder** (when mount exists) / else honest “open validated; mount needs
   Fuse packaging on this Mac.”
5. Work in Finder → return → **Eject** → status Locked.

**C. Cloud path (Seal)** — from Workspace or drag-drop: Seal CTA when sync root detected;
never the default create path.

### 5.9 Trust & transparency (adoption)

✓ Alodhyani, Theodorakopoulos, Reinecke (2020), *Password Managers—It’s All about Trust and
Transparency*, Future Internet 12(11):189 ([MDPI](https://www.mdpi.com/1999-5903/12/11/189)) —
**not** a SOUPS paper. Finding: **usability is not the major barrier**; **lack of trust and
transparency** are the main reasons for low adoption; users still have trust/security concerns
even when using a PM. Blindkey should surface **local-only** and **no network** as positive,
legible product traits on first run and in About — not buried.

✓ Klivan et al. (SOUPS 2023): severe distrust leads users to skip storing important passwords —
so the Add flow must feel as safe as the marketing claim (local file, Lock control visible,
no account signup).

### 5.10 “Great” vs “dangerous delight”

| Delight that helps | Delight that hurts |
|--------------------|--------------------|
| Instant search, generator, keyboard Copy | Auto-reveal secrets on select |
| Smooth unlock progress | Auto-mount on login without consent |
| Satisfying Eject confirmation | Confetti after seal (trivializes security) |
| Helpful Seal CTA | Hiding residual risk behind “Don’t show again” forever without ever showing once |

---

## 6. Recommended Blindkey information architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Blindkey                          [ Locked | Unlocked ]    │
├───────────────┬─────────────────────────────────────────────┤
│ Mode switch   │  Content                                    │
│ ○ Credentials │  (vault list / search / entry detail)       │
│ ○ Workspace   │  (volume list / create / unlock / eject)    │
│ ───────────── │                                             │
│ Seal files…   │  secondary CTA (picker / drop → .vltf)      │
│ (not a mode)  │  also C73 recovery from sync-root refuse    │
└───────────────┴─────────────────────────────────────────────┘
```

**Normative:** exactly **two** modes (Credentials | Workspace). Seal is **not** a third radio —
aligned with §0 and [UC-26](../docs/specs/UC-26-desktop-ui-information-architecture.md) §5.1.
(Earlier draft of this diagram incorrectly showed Seal as a peer radio.)

### 6.1 Credentials mode (encrypt / store a key)

| Screen | Primary actions | Feedback required |
|--------|-----------------|-------------------|
| Unlock / Create vault | Unlock · Create | Argon2 progress; success → unlocked home |
| Home | Search · **Copy** · Add | “Copied. Clipboard clears in Ns.”; lock control always visible |
| Add / Edit | Save · Generate | Strength meter (optional); errors inline |
| Lock | Lock | Immediate return to unlock; zeroize UI buffers |

Aligns with Chiasson criteria 5–6 and C27 copy-default.

### 6.2 Workspace mode (encrypted disk)

| Screen | Primary actions | Feedback required |
|--------|-----------------|-------------------|
| Empty | **Create volume** | Path picker defaults to **local** (warn sync roots) |
| Locked volume | **Unlock** | Residual-risk banner **once/session** before first unlock |
| Unlocked | **Reveal in Finder** · **Eject** | Status = Locked / Unlocked / Mounted (after Eject → Locked + closure toast) |
| Sync-root path | Refuse + **Seal files instead** | C73 Seal CTA (already in volume_gui) |

Do not bury Volume as a silent top-bar icon next to Add without mode context.

### 6.3 Visual / interaction rules (checklist)

1. **State before content** — lock status in title bar or header on every frame.
2. **One primary button** per dialog (Create / Unlock / Save / Eject).
3. **Contrast** — WCAG AA; never rely on emoji alone for meaning.
4. **Target size** ≥ 24×24 CSS px for primary controls.
5. **Paste allowed** on all secret fields (NIST / WCAG 3.3.8).
6. **Dangerous errors impossible** — wrong password → uniform message; sync-root mount →
   refuse; no silent “success” when crypto failed (Johnny #3).
7. **Empty states** with next action (Apple HIG Writing).
8. **Mount honesty** — residual banner + lock-on-sleep best-effort note (UC-25 / C72).
9. **Progressive disclosure** — Advanced KDF / keyfile behind a disclosure control (§5.4).
10. **Closure** — every crypto job ends with an explicit done state (§5.3).

---

## 7. Screen-level UX specs (implementation-ready)

### 7.1 Unlock / Create (Credentials)

- Single column for the form (~400–480 px content width) so the passphrase field stays focused;
  if a full Settings page is added later, Fluent guidance is a **scrollable** column with max
  width around **1000–1100 px** (✓ Microsoft app-settings guidelines) — do not conflate the two.
- Passphrase field: show/hide toggle; paste enabled; focus on open.
- Primary button label matches mode: **Unlock** vs **Create vault**.
- Secondary: “Choose vault file…”
- Footer quiet line: “Stored only on this computer.”

### 7.2 Credentials home

- **Search** is the hero (focus on open when unlocked).
- List virtualized (already UC-20); selection → detail pane.
- Detail: title, username, **Copy** (filled primary), Reveal (secondary, timed), Edit.
- Top bar: Lock | Audit | Add — not Volume/Seal as peers without mode switch.

### 7.3 Workspace home (Cryptomator-class)

- Left: volume list with status pill (Locked / Unlocked).
- Right: name, ciphertext path, access path (if mounted), **big Unlock** or **Reveal + Eject**.
- Empty: Create volume CTA + one-sentence Seal contrast.

### 7.4 Dialogs

- One primary, one Cancel; destructive = separate confirm step.
- Errors **inline** under the field that failed (Apple HIG).
- Long jobs: progress + Cancel; on cancel, leave disk unchanged.

---

## 8. Toolkit note (pointer only — details in `ui_architecture.md`)

| Choice | Fits Blindkey? | Notes |
|--------|----------------|-------|
| egui / eframe (current) | ✓ C20 | Must ship **embedded fonts** + readable theme; not pixel-native macOS |
| ratatui TUI | ✓ C20 | Strong secret hygiene; not the GUI ask |
| SwiftUI via FFI | ✓ long-term macOS | Best HIG / Touch ID; after core API stable |
| Electron / Tauri webview | ✗ / escape hatch | Electron fails C20; Tauri only if secrets never enter JS |

This research does **not** change the C20 recommendation; it constrains **layout, copy, and feel**.

---

## 9. Evaluation plan (lightweight, research-backed)

### 9.1 Heuristic evaluation (designer / engineer)

Walk the UI against §5.2 (Nielsen) and §5.3 (Shneiderman); log severity
(cosmetic / minor / major / catastrophic). Fix all catastrophic + major before user tests.

### 9.2 Cognitive walkthrough (Whitten method) — 5 users

Tasks:

1. Create vault → add an API key → copy it → lock.
2. Create a local `.vltd` → unlock → understand residual banner → eject.
3. Attempt mount under a Dropbox-like path → see Seal CTA.

Pass bar (Chiasson): ≥4/5 complete each task without dangerous errors; all can state whether
the vault/volume is locked at the end.

### 9.3 “Great experience” bar (extra)

After tasks, ask (Likert 1–5):

- “I always knew whether things were locked.”
- “I would trust this with an API key I care about.”
- “I understand the difference between Credentials and Workspace.”

Ship bar: median ≥4 on all three after the fonts/IA fix.

---

## 10. Sources index

### Academic / venue

- Whitten, A. & Tygar, J. D. (1999). *Why Johnny Can’t Encrypt.* USENIX Security.
- Chiasson, S., van Oorschot, P. C., & Biddle, R. (2006). *A Usability Study and Critique of
  Two Password Managers.* USENIX Security.
- Prinz et al. (2017). *Mental Models of Password Managers.* SOUPS poster.
- Klivan, S., Höltervennhoff, S., Huaman, N., Acar, Y., & Fahl, S. (2023). *“Would You Give
  the Same Priority to the Bank and a Game? I Do Not!”* SOUPS.
- Carreira, C., Ferreira, J. F., & Mendes, A. (2021). *Towards Improving the Usability of
  Password Managers.* INFORUM (PassCert / Bitwarden).
- Yee, K.-P. (2002). *User Interaction Design for Secure Systems.* UCB CSD-02-1184.
- Spero, E. & Biddle, R. (2020). *Out of Sight, Out of Mind.* NSPW ’20 (ACM).
- Alodhyani, F., Theodorakopoulos, G., & Reinecke, P. (2020). *Password Managers—It’s All
  about Trust and Transparency.* Future Internet 12(11):189 (MDPI) — trust/transparency, not SOUPS.
- Zurko, M. E. & Simon, R. T. (1996). User-centered security — cited in Chiasson et al. as
  foundational “user-centered security” framing (~ via Chiasson; original not re-fetched this pass).

### UX heuristics & industry

- Nielsen, J. — *10 Usability Heuristics* (NN/g; 1994 set, 2020 article refresh).
- Shneiderman, B. — *Eight Golden Rules of Interface Design* (UMD).
- NN/g — *Progressive Disclosure*.
- Cisco Security blog (~) — progressive disclosure in SOC tooling (secondary illustration only).

### Standards

- NIST SP 800-63B-4 (2024). Digital Identity Guidelines: Authentication.
- W3C WCAG 2.2 (2023). Especially 1.4.3, 1.4.11, 2.5.8, 3.3.8.
- Apple HIG — Writing; WWDC24 Privacy.
- Microsoft Learn — App settings guidelines; Passkeys design patterns.

### Products / docs

- Cryptomator desktop docs (unlock / reveal / lock).
- VeraCrypt UI overview (cautionary: power-user density).
- Blindkey `ui_architecture.md` (toolkit trust boundary).

---

## 11. Observed GUI failure (2026-07-29) — research implication

Screenshot of `blindkey-gui` on macOS: dark window, **outlined text field**, **checkbox**,
**separator**, **button-sized bar** — **no readable labels**.

✓ Workspace `Cargo.toml` pins:

```toml
eframe = { version = "0.29", default-features = false, features = ["glow", "wayland", "x11"] }
```

`default-features = false` **without** `"default_fonts"` ✓ omits egui’s embedded font feature
from the workspace pin (eframe 0.29 feature set). That configuration is the **leading
hypothesis** for empty labels (~ causal until a rebuild with `default_fonts` is screenshot-
compared). Related egui reports: [egui#2276](https://github.com/emilk/egui/issues/2276).
Secondary hypothesis: text color ≈ background (WCAG fail) — less likely given *all* labels
missing including buttons.

**Research implication:** no IA / UX redesign is testable until glyphs and contrast work. First
engineering gate for any UI work informed by this doc: enable `default_fonts` (and/or embed
a known TTF), force a high-contrast `Visuals` set, screenshot-verify unlock screen text.

---

## 12. What to distill next (patterns / PRD)

**Tech spec (public):** [docs/specs/UC-26-desktop-ui-information-architecture.md](../docs/specs/UC-26-desktop-ui-information-architecture.md)
(**Implemented v1.0**, 2026-07-29 — ROADMAP S-25; C75–C81 PASS) — fonts, IA, honesty, tests.
**Craft follow-up:** [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md) (**Draft v0.2** — ROADMAP S-26;
research↔spec cross-check in UC-27 §13) covers layout/hierarchy/spacing/accent from
[`desktop_app_ui_ux_research.md`](desktop_app_ui_ux_research.md).

When implementing:

1. Fix egui fonts/contrast (§11) — **blocker for “great.”** (UC-26 Phase A) ✅
2. Restructure chrome into **Credentials | Workspace** modes (§6). (UC-26 Phase B–D) ✅
3. Apply UX playbook §5 (status, progressive disclosure, microcopy, journeys). ✅ (IA)
4. Ship screen specs §7; validate with §9 / UC-26 §7. ✅
5. Visual craft polish — [UC-27](../docs/specs/UC-27-desktop-ui-visual-craft.md) / S-26 (next).
6. Distill operator patterns privately if needed; keep this file as the public evidence base.

---

## 13. Source cross-check log (2026-07-29)

| Issue | Was | Fix |
|-------|-----|-----|
| Section refs in header | “playbook §5–§8”, incident “§12” | §5–§7; incident §11 |
| Whitten lab summary | Vague “mostly failed” | N=12; 1/3 success; 1/4 cleartext accident (USENIX) |
| Clipboard “12s” | Invented | ✓ `DEFAULT_CLIPBOARD_TIMEOUT_SECS = 30`; reveal 15s |
| “Alodah” / SOUPS | Misspelled + wrong venue | Alodhyani et al. 2020 *Future Internet*; trust ≠ usability |
| “Klívan” | Accent / incomplete authors | **Klivan**, Höltervennhoff, Huaman, Acar, Fahl (SOUPS 2023) |
| PassCert | Vague “notes” | Carreira, Ferreira, Mendes — INFORUM 2021 ✓ |
| WCAG 1.4.3 vs 1.4.11 | Merged in one row | Split text vs non-text contrast |
| Fluent “420 px” | Mis-attributed | Form focus width vs Fluent ~1000–1100 settings max |
| VeraCrypt UI | ✓ without primary UI guide | Downgraded to ~ |
| Yee principles | Named without quote | Clarity / Visibility / Expected Ability quoted from CSD-02-1184 |
| Heuristic #9 Caps Lock | Conflicted with C74 uniform open | Scoped: vault hints OK; sealed/volume keep uniform culture |
| egui fonts | Stated as certain cause | Config gap ✓; causality ~ pending rebuild proof |
| Spero & Biddle | OK | Confirmed Eric Spero + Robert Biddle, NSPW ’20 |

---

## 14. Spec ↔ research cross-check log (2026-07-29)

Cross-check of this file vs [UC-26](../docs/specs/UC-26-desktop-ui-information-architecture.md) Draft.

| Issue | Was | Fix |
|-------|-----|-----|
| §6 IA diagram | Seal as third `○` radio — contradicted §0 “two modes” + Seal secondary | Diagram + note: Seal **not** a mode; matches UC-26 §5.1 |
| First-run copy | “on this Mac” (macOS-only) | “on this computer” (Linux/macOS; matches UC-26) |
| Spec links in header | UC-18, UC-25 only | + UC-20, UC-21, UC-26 |
| Workspace status | “Ejected” as persistent status | Persistent = Locked / Unlocked / Mounted; Eject → Locked + toast |
| Copy toast punctuation | “Copied — clears…” vs §5.6 “Copied. Clipboard…” | Unified to §5.6 / UC-26 form |
| Lock emoji in IA wireframe | Status by emoji alone risk | Plain text status (WCAG / §6.3 #3) |
| UC-26 gaps vs §6.3 / §7 | Spec omitted target size, paste/show-hide, local path default, confirm-match, Reveal secondary, closure, cancel-disk, lock-on-sleep note, About trust line | Addressed in UC-26 Draft **v0.2** |
| KeePassXC in UC-26 | Marked ✓ verified | Downgraded to ~ in UC-26 (pattern, not primary-doc pass) |
)