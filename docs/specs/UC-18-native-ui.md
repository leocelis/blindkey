# UC-18 — Use the Blindkey Through a Fast, Native UI

> **Tech spec** · Implemented · June 2026 · **Status:** ✅ `blindkey-tui` + `blindkey-gui` shipped (pre-1.0 beta); SwiftUI/uniffi shell post-v1 (S-18)
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-18 · **Constraints:** C20, C11, C12, C25, C27, C5, C23; candidate C-presentation
> **Research:** [research/ui_architecture.md](../../research/ui_architecture.md)
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

A front-end that is *fast, simple, secure, and runs on this Mac as nicely as on Linux* — without
duplicating or weakening the Rust security core. **Pure-Rust TUI and egui GUI shells are shipped**
(`blindkey-tui`, `blindkey-gui`). The **remaining post-v1 piece** is the native **SwiftUI** shell via uniffi
(Touch ID / Secure Enclave). The v1 prerequisite — a UI-agnostic `blindkey-core` API — is in place.

Goals:

1. Every UI is a **thin client over `blindkey-core`** — zero crypto, zero format logic in the shell.
2. The presentation layer never holds long-lived plaintext; **copy-not-display** by default (C27),
   on-screen reveal is opt-in, auth-gated, and time-boxed.
3. Preserve C20's "single binary, no Node/JVM/Python" property for the default shells.
4. First-class macOS integration (Touch ID, Secure Enclave, clipboard) **mapped to C5**, reachable
   without abandoning the shared core.
5. Phased delivery: ship value early (TUI) without blocking on a designed GUI.

Out of scope: browser extension (intent `non_goals`), autofill into other apps' fields, the agent
interface (that is [UC-16](UC-16-agent-interface-future.md)).

## 2. Prior art

### 2.1 Open source

| Source | Relevance | Confidence |
|---|---|---|
| **Signal `libsignal`** ([github](https://github.com/signalapp/libsignal)) | Platform-agnostic **Rust** core (protocol, crypto, attestation) exposed as Java/Swift/TS bindings to *all* clients + server — the exact "one audited core, native shells" pattern §3 adopts. | ✓ verified |
| **Mozilla UniFFI** ([github](https://github.com/mozilla/uniffi-rs)) | Generates Swift/Kotlin/Python/Ruby bindings from Rust; Rust → dynamic lib → **XCFramework** → idiomatic Swift layer; used across Firefox. The FFI mechanism for the SwiftUI shell. | ✓ verified |
| **egui / eframe** ([egui.rs](https://www.egui.rs/)) | Pure-Rust immediate-mode GUI, native (wgpu/glow) + web/wasm, single binary — the C20-aligned windowed shell. | ✓ verified |
| **ratatui** ([ratatui.rs](https://ratatui.rs/concepts/backends/alternate-screen/)) | Terminal UI on crossterm; **alternate screen + raw mode**, restored on exit — the secret-hygiene property of §3.4. | ✓ verified |
| **Tauri 2** ([gethopp comparison](https://www.gethopp.app/blog/tauri-vs-electron)) | OS-native webviews (WKWebView/WebView2/WebKitGTK), 5–15 MB; the "designed app" escape hatch under the metadata-only rule. | ✓ verified |
| **1Password 8 (Electron)** ([community thread](https://www.1password.community/discussions/1password/1password-8-memory-usage-vs-1password-7-aka-why-electron-is-no-good-/131959)) | Cautionary precedent: ~85 MB vs 8 MB native (~10×), lag, non-native feel, user revolt — why Electron is rejected. | ✓ verified |
| macOS-from-Rust: `security-framework`, `localauthentication-rs`, `keychain-services` (experimental) | Keychain / Touch ID / Secure-Enclave access from Rust — the §3.5 integration path. | ✓ verified (maturity caveat) |

### 2.2 Academic / standards

- The intent's own C11/C12/C25 (zeroize/mlock/auto-lock) and C27 (model-blind delivery) — the
  constraints the presentation layer must not regress; this spec extends C27 to UI surfaces (§5).
- W3C/Apple platform security (Secure Enclave device-bound keys) already cited in the intent's C5 —
  the basis for the Touch-ID-maps-to-C5 claim.

## 3. Proposed design

### 3.1 Architecture: shared core, thin shells

```
blindkey-core (Rust, #![forbid(unsafe_code)])     ← the single audited boundary (CP-1..CP-4)
   ▲ crate        ▲ crate        ▲ uniffi/C-ABI       ▲ Tauri command (opt)
ratatui TUI    egui GUI       SwiftUI (macOS)        web-styled app
(all OSes)     (all OSes)     Kotlin (Android, later) (broader audience)
```

- **Rust-native shells** (`ratatui`, `egui`) depend on `blindkey-core` as a normal crate — **no FFI,
  secrets never leave Rust**.
- **Native shells** (SwiftUI/Kotlin) link `blindkey-core` through **uniffi**-generated bindings packaged
  as an **XCFramework** (the Signal/Firefox model). The FFI surface returns structured data and
  **secret-handles**, and performs reveal/copy *inside Rust* (§3.3).

### 3.2 The UI-agnostic, FFI-ready core API (THE v1 deliverable)

The CP-4 `blindkey-core` public API must satisfy, from day one, all of:

```rust
// Illustrative — the contract, not the final signatures.
pub struct EntrySummary { pub id: Uuid, pub title: String, pub kind: EntryKind, pub tags: Vec<String> }
//                         ^ NO secret fields — safe to hand to any shell, incl. a webview.

impl Blindkey {
    pub fn unlock(&mut self, factor: UnlockFactor) -> Result<Session>;     // password | biometric-wrapped stanza
    pub fn search(&self, q: &str) -> Vec<EntrySummary>;                    // metadata only (SC2, in-memory)
    pub fn deliver(&self, id: Uuid, field: Field, sink: Sink) -> Result<()>; // §3.3 — core does delivery
}
pub enum Sink { Clipboard, /* explicit, warned: */ Stdout, /* future: */ FieldInject(Destination) }
```

Rules baked into the API so a shell *cannot* misuse it:

1. **No function returns a secret as a plain owned string by default.** Retrieval is `deliver(...)` —
   the core writes the secret to a `Sink` (clipboard by default) and never hands it to the caller.
   A `reveal()` that returns a `Secret<…>` exists but is `#[must_use]`, auth-gated, and documented as
   "for an in-process Rust shell that will render under §3.4 — never marshal across FFI."
2. **`EntrySummary` is secret-free** — the only type a webview/JS or Swift heap ever sees.
3. **Delivery and clipboard auto-clear live in the core** (C13/C27), so every shell gets identical
   behavior; the UI cannot accidentally re-implement a leak.
4. **No printing in the core** — it returns data/handles; shells render. (UI-agnostic.)

This API is the single thing UC-18 contributes to v1; everything else below is post-v1.

### 3.3 Secret delivery from a UI (copy-not-display)

- Default UI action on an entry = **`deliver(id, field, Sink::Clipboard)`** → the UC-04 clipboard
  holder (concealed-type hints, clear-iff-unchanged after C13 timeout). The shell shows only a status
  line ("Copied · clears in 30s"). The plaintext never enters the shell's own memory.
- This holds across FFI: SwiftUI calls `deliver(...)`; the secret is handled in Rust and placed on
  `NSPasteboard`; **no Swift `String` ever holds it**.

### 3.4 On-screen reveal (the opt-in, hardened path)

When a user explicitly reveals (eye icon / `r` key):

- **Auth-gate it** (Touch ID on macOS via §3.5; password re-prompt elsewhere).
- **Time-box it** (default ~10 s, then re-mask) and require the window/pane focused.
- Render to the buffer with the best hygiene available:
  - ratatui: draw into the **alternate screen** cell grid; overwrite the cells on hide; never echo to
    the main buffer (no scrollback leak — ✓ verified alt-screen property).
  - egui: draw the glyphs for that frame only; clear on hide; the value lives in a `Zeroizing` buffer
    the core lent for the reveal window and reclaims after.
  - webview (Tauri): **reveal is disabled** in the webview; reveal is a native-side overlay or simply
    not offered — the webview is metadata-only.
- The reveal buffer is the *only* place plaintext is shown, briefly, by user action — documented as
  residual exposure in the threat model.

### 3.5 macOS integration (maps to C5)

| Capability | Implementation (Mac shell) | Constraint | Confidence |
|---|---|---|---|
| Clipboard + concealed hints | `NSPasteboard` (UC-04) | C13/C27 | ✓ verified |
| Touch ID unlock | `LocalAuthentication` `LAContext`/`LAPolicy` (native in SwiftUI; `localauthentication-rs` for a Rust shell) | unlock UX | ✓ verified |
| Secure Enclave data-key wrap | `SecKey` in the SEP, Touch-ID-guarded; the wrap secret feeds the **C5 macOS keychain stanza** | **C5** | ✓ verified; maturity caveat |
| Code signing | `codesign`/Xcode + notarization before Keychain APIs work | release (UC-13) | ✓ verified |

- **Touch ID is an additive C5 stanza, not a new trust root**: the Secure-Enclave-wrapped data key is
  one more OR-stanza; the password stanza is always present (lose your Mac → password still opens the
  vault on another machine). This is exactly C5's any-of-N model.
- ~ caveat: prefer the **SwiftUI shell calling `LocalAuthentication` + `SecKey` natively** over the
  experimental `keychain-services` Rust crate; `blindkey-core` holds the resulting wrap secret. Confirm
  the API set in the §7 spike.

### 3.6 Phasing

| Phase | Shell | Why first/next |
|---|---|---|
| **P0 (v1)** | *no UI* — ship the UI-agnostic FFI-ready core API (§3.2) | unblocks every shell; the only v1 work |
| **P1** | `ratatui` TUI | C20-exact, pure Rust, dev core loop, alt-screen hygiene |
| **P2** | `egui` window | non-terminal users, still pure Rust |
| **P3** | SwiftUI macOS via uniffi | native feel + Touch ID/Secure Enclave (C5) |
| **P4 (opt)** | Tauri designed app / Kotlin Android | broader audience, metadata-only webview rule |

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Electron ("app like Claude") | one web codebase, familiar | 80–150 MB, 200–300 MB RAM, unzeroable JS heap, non-native; **violates C20 (Node) + C11/12 spirit**; 1Password-8 precedent | ❌ rejected |
| Tauri as the default UI | small, modern, cross-platform, Rust backend | webview trust boundary; not a single static binary (off C20); secrets must be kept out of JS | ⚠️ escape hatch only (P4) |
| **Pure-Rust shells (ratatui + egui)** | C20-exact, single binary, secrets never leave Rust | not pixel-native on macOS | ✅ **default (P1/P2)** |
| SwiftUI-only (Mac-native, no shared core) | best Mac feel | Mac-only; would re-implement crypto → forks the audited boundary | ❌ rejected (shell yes, fork no) |
| Shared Rust core + native shells via uniffi | one audited core, native integration, Signal/Firefox-proven | FFI plumbing + XCFramework build | ✅ **chosen for native (P3)** |
| Return secrets as strings across FFI for the UI to render | simple | plaintext in Swift/JS heap, unzeroable — defeats C11/C27 | ❌ prohibited (core does delivery, §3.2) |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C20** | default shells (ratatui/egui) stay single-binary, no Node/JVM/Python; Tauri flagged as off-spec and optional |
| **C11/C12/C25** | secrets stay in `blindkey-core`'s zeroized/mlock'd buffers; UI holds no long-lived plaintext; reveal uses a core-lent `Zeroizing` buffer reclaimed on hide; auto-lock unchanged |
| **C27** | copy-not-display default via `deliver()`; the FFI surface never returns a secret string by default; **forward constraint extended to UI surfaces** (amendment, §7) |
| **C5** | macOS Touch ID / Secure Enclave wrap is an additive keychain stanza; password stanza always present (any-of-N) |
| **C13** | clipboard auto-clear lives in the core, shared by all shells |
| **C23** | shells make no network calls; native integration is local-only (clipboard, LAContext, SEP) |
| C-presentation (candidate) | the §3.4 secret-display-boundary rule, made testable (§7) |

## 6. Test plan

1. **API shape (v1):** assert no `blindkey-core` public fn returns a secret-bearing owned value except
   the `#[must_use]`, documented `reveal()`; `EntrySummary` contains no secret field (compile-time +
   review gate). This is the gate that makes UC-18 buildable later.
2. **Delivery, not return:** call `deliver(id, password, Clipboard)`; assert the secret is on the
   clipboard and **never** returned to or stored by the calling shell (memory-scan the shell heap for
   the known value → zero hits).
3. **No-leak across FFI (P3):** drive the uniffi Swift binding; assert no Swift `String`/`Data` holds
   the secret after `deliver` (instrumented test); only `EntrySummary` crosses.
4. **Alt-screen hygiene (P1):** ratatui reveal then hide then exit; assert the terminal's main-buffer
   scrollback never contains the revealed value.
5. **Reveal hardening (P2/P3):** reveal requires auth (mock Touch ID), re-masks after the timeout,
   and the egui reveal buffer is zeroized on hide (memory hook).
6. **C5 stanza (P3):** enroll a Secure-Enclave-wrapped stanza; remove biometric availability; assert
   the password stanza still unlocks (any-of-N, no lockout).
7. **No-network (C23):** `strace`/`dtruss` each shell during search+deliver; assert zero sockets.

## 7. Open questions

1. **macOS SEP API choice:** native SwiftUI `LocalAuthentication` + `SecKey` (preferred) vs the
   experimental `keychain-services` Rust crate — resolve in a time-boxed spike before P3; record as an
   ADR (this is a hard-to-reverse boundary decision per GOVERNANCE).
2. **uniffi vs hand-written C-ABI** for the Swift boundary — uniffi is the default (Signal/Firefox
   precedent); confirm it handles the secret-handle pattern without forcing owned strings.
3. **Reveal timeout + auth policy defaults** — 10 s / always-auth? Surface in `~/.vault.toml`
   alongside `clipboard_timeout`/`auto_lock_seconds` (UC-06 §3.6).
4. **Does the candidate presentation-layer constraint get a number now** (ratify alongside the Part-2 C35+ batch) or
   stay as the extended C27 forward constraint only? (See §5 + the intent amendment.)
5. **Quick-open / global hotkey** (Spotlight-style) on macOS — powerful but a system-integration and
   focus-stealing surface; defer to a P3+ design with its own threat note.
