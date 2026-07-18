# UI Architecture for a Local-First Credential Blindkey — Options, Security, Native Integration

> **Status:** Research (June 2026). Companion to [`vault_spec.md`](vault_spec.md). Informs PRD
> UC-18 and [`docs/specs/UC-18-native-ui.md`](../docs/specs/UC-18-native-ui.md).
> **Confidence markers:** `✓ verified` = checked against a primary/authoritative source this pass ·
> `~ reported` = stated by a named source, retrieved via summary · `? open` = projected or
> single-source.
>
> **Scope:** how a *graphical or terminal* front-end should sit on top of the Rust `blindkey-core`
> security boundary without weakening it. Not about the crypto (that is `vault_spec.md`); about the
> presentation layer and the trust boundary between it and the core.

---

## 0 — Executive summary

A vault UI is a **thin client over `blindkey-core`**, never a re-implementation. Three facts from the
existing intent pick the technology more than aesthetics do:

1. **C20** mandates a single statically-linked binary with *no runtime dependencies (no JVM, no
   Python, no Node.js)*, and its rationale is literally *"complexity is a security risk."* An
   Electron/Node app contradicts C20 by name.
2. **C11/C12/C25** harden secret memory (zeroize, mlock, auto-lock) — properties a JavaScript heap
   cannot honor (GC'd strings are neither lockable nor reliably wipeable).
3. **C27** requires model-blind delivery (copy to clipboard by default, never dump plaintext). The
   same principle generalizes to *any* presentation surface: a secret rendered to a buffer you
   cannot zeroize (terminal scrollback, a GPU glyph texture) is a leak of the same family.

The recommendation that falls out: **one audited Rust core, thin per-platform shells** — the
architecture Signal (`libsignal`) and Mozilla (Firefox via UniFFI) already run in production. Ship a
`ratatui` TUI first (pure Rust, C20-exact), add an `egui` window for non-terminal users, and expose
`blindkey-core` over a stable FFI (`uniffi`) so a native **SwiftUI** shell can deliver best-in-class
macOS integration (Touch ID, Secure Enclave) without forking the security core. Tauri is a viable
"designed, web-styled app" escape hatch but adds a webview trust boundary and is not C20-clean.

---

## 1 — The decisive security principle: the secret-display boundary

Every option can call `blindkey-core` and receive a secret. The question that ranks them is **where the
plaintext goes after that**:

- ✓ verified (by construction): the secure path is **copy, not display** — `blindkey get` → OS
  clipboard (UC-04), the secret never rendered, auto-cleared after a timeout (C13). Any UI inherits
  this for free by calling the same path.
- The weak point in *every* toolkit is an on-screen **reveal**: the bytes must enter a render buffer
  the core cannot wipe. The buffers differ in how leaky they are:
  - **Terminal (ratatui):** ✓ verified — TUIs run in the **alternate screen buffer** (a separate
    buffer restored on exit) under raw mode, so a revealed value does **not** persist to the
    terminal's scrollback/history *if the app never echoes it to the main buffer*. This is a genuine
    advantage: render in the alt-screen, clear the cell on hide, never `println!` a secret.
  - **GPU-backed GUI (egui):** the glyphs become a texture in VRAM the process owns; tighter than a
    browser DOM, but still a buffer outside `mlock`. Reveal must be explicit, brief, and re-drawn
    over on hide.
  - **Webview (Tauri/Electron):** worst — plaintext crosses into a JS heap/DOM you neither control
    nor zeroize. Acceptable *only* if secrets never enter the webview at all (metadata-only UI;
    reveal/copy done in Rust).
- **Design rule for all UIs (candidate constraint, see §8):** the UI process holds **no long-lived
  plaintext** — it calls `blindkey-core` per operation; default action is clipboard copy; on-screen
  reveal is opt-in, auth-gated, time-boxed, and drawn to a buffer cleared on hide. This is C27's
  spirit extended from "LLM-readable channels" to "presentation surfaces."

---

## 2 — Option survey

### 2.1 Electron — rejected by C20

- ~ reported: Electron bundles Chromium + Node; minimal apps are **80–150 MB** and idle at
  **200–300 MB** RAM.
- ✓ verified (cautionary precedent): **1Password 8**'s move to Electron drew sustained user
  backlash — the Electron build measured **~85 MB vs the native app's ~8 MB (~10×)**, with reports
  of lag, higher idle CPU, and a "non-native feel"; users formally lobbied to abandon it. For a
  password manager whose pitch is *fast, simple, secure*, this is the anti-pattern, and it violates
  C20 (Node.js) and the spirit of C11/C12 (unzeroable JS heap).

### 2.2 Tauri 2 — small and modern, but not C20-clean

- ✓ verified: Tauri uses **OS-native WebViews** (WebView2 / WKWebView / WebKitGTK) instead of
  bundling Chromium — **~5–15 MB** binaries, **~30–40 MB** idle RAM, and as of 2.x it targets
  desktop **and** iOS/Android. Rust backend; the existing `blindkey-core` is the backend.
- Caveats: (a) it is *not* a single static binary and adds a webview dependency, so it is off-spec
  vs C20 even if far better than Electron; (b) cross-platform webviews introduce *behavioral*
  variance; (c) the hard rule from §1 applies — **secrets must never cross into the webview**;
  the JS side sees metadata, and reveal/copy is a Rust command. Verdict: the "designed app" escape
  hatch, not the default.

### 2.3 egui / eframe — pure-Rust GUI, C20-aligned

- ✓ verified: `egui` is an **immediate-mode** GUI in Rust running on native **and** web/wasm;
  `eframe` wraps it into an app for Linux/macOS/Windows/Android/web. Native backend is **wgpu**
  (GPU); switching to **glow** notably shrinks the binary. Single self-contained executable, no
  webview, no Node — keeps C20 intact and keeps every secret inside the Rust boundary.
- Tradeoff: immediate-mode redraws each frame (cheap for a form-like vault UI), and the look is a
  clean *cross-platform* app, **not** pixel-native macOS. Verdict: the "runs on anything, still
  pure-Rust" windowed option.

### 2.4 ratatui — terminal UI, fastest to ship, strong hygiene

- ✓ verified: `ratatui` renders via the `crossterm` backend in **raw mode** on the **alternate
  screen**, restored on exit. Immediate-rendering model (render all widgets each frame).
- Fits the developer audience and the core loop (*type to search → Enter → clipboard*, UC-06 +
  UC-04). Pure Rust, effectively a single binary, alt-screen hygiene (§1). Verdict: **ship first.**

### 2.5 SwiftUI native (macOS) — best integration, platform-bound

- Best-in-class macOS feel (native menus, SF Symbols, system appearance) and the *easiest* path to
  Touch ID / Secure Enclave / Keychain (§4). It is macOS-only, so it is a **shell**, not the whole
  story — and only worthwhile *because* the security logic lives in a shared Rust core it links to.

---

## 3 — The recommended pattern: shared Rust core + thin native shells

This is not novel; it is how the most security-sensitive apps already ship:

- ✓ verified — **Signal `libsignal`**: a platform-agnostic **Rust** core (protocol, `signal-crypto`,
  zkgroup, attestation) exposed as **Java / Swift / TypeScript** bindings used by *all* Signal
  clients (Android, iOS, Desktop) and the server. Bridge macros auto-generate the per-language
  interface. One audited core, many native shells.
- ✓ verified — **Mozilla UniFFI**: generates **Swift / Kotlin / Python / Ruby** bindings from a Rust
  core; used across Firefox mobile and desktop. The Rust lib is compiled to a dynamic library,
  packaged as an **XCFramework**, and surfaced through an idiomatic Swift API layer (a low-level C
  FFI module + a high-level Swift wrapper).

Applied to Blindkey:

```
              ┌──────────────────────────────────────────────┐
              │  blindkey-core (Rust, #![forbid(unsafe_code)])    │  ← the one audited boundary
              │  crypto · format · memory(mlock/zeroize) ·     │
              │  envelope · rollback · model-blind delivery    │
              └──────────────────────────────────────────────┘
                 ▲            ▲              ▲             ▲
        C ABI / uniffi   direct crate   direct crate   C ABI / uniffi
                 │            │              │             │
            SwiftUI       ratatui TUI     egui GUI      (Tauri cmd
            (macOS)       (all OSes)     (all OSes)      backend, opt)
```

- Rust-native shells (`ratatui`, `egui`) link `blindkey-core` as a normal crate — **zero FFI**, secrets
  never leave Rust.
- The **SwiftUI** shell links `blindkey-core` via **uniffi**-generated bindings (XCFramework). The FFI
  surface returns *structured data and secret-handles*, and performs reveal/copy **inside Rust** so
  plaintext is not marshalled into Swift heap strings any longer than a single delivery call.

---

## 4 — macOS integration specifics (answering "integrate nicely with this Mac")

All reachable from Rust today; the cost is FFI plumbing, not a rewrite:

| Capability | Rust path | Maps to | Confidence |
|---|---|---|---|
| Clipboard (concealed-type hints) | `NSPasteboard` via `objc2` / `arboard` (UC-04 already specs this) | C13, C27 | ✓ verified (UC-04) |
| Touch ID / biometric gate | `localauthentication-rs` (`LAPolicy` biometry) or `objc2` `LAContext` | unlock UX | ✓ verified (crate exists) |
| Keychain + **Secure Enclave** keys | `security-framework` (Keychain/TLS); `keychain-services` (Touch-ID-guarded **SEP** keys — *experimental*) | **C5 macOS keychain stanza** | ✓ verified; ~ caveat below |
| Code signing requirement | `codesign` / Xcode required before most Keychain APIs work | release/notarization | ✓ verified |

Key takeaways:

- **Touch-ID-to-unlock is not a detour — it is C5.** The intent's macOS keychain stanza (C5) is
  exactly a Secure-Enclave-wrapped data-key path; a Touch-ID gate over it is the additive factor,
  with the password stanza always present (C5 OR-model: losing biometrics never locks you out).
- ~ caveat: the most direct crate for SEP-guarded keys (`keychain-services`) self-describes as
  **experimental** — treat as a spike, and prefer the SwiftUI shell calling `LocalAuthentication` +
  `SecKey` natively for the Mac build, with `blindkey-core` holding the resulting wrap secret. Confirm
  the exact crate/API set before committing (UC-18 §7).
- Native *look-and-feel* (menus, Share sheet, Spotlight-style quick-open) is the one thing pure-Rust
  shells only approximate — the reason a SwiftUI shell exists at all.

---

## 5 — Performance reality

- ✓ verified posture: all four options compile to native code with millisecond startup (vs
  Electron's seconds). Idle memory: egui/ratatui single-digit-to-low-tens of MB; Tauri ~30–40 MB;
  Electron 200–300 MB.
- The honest point: **the only user-visible latency is Argon2id**, and it is *intentional* — C22
  targets <500 ms unlock as a security floor. No toolkit changes that; the KDF dominates rendering
  by orders of magnitude. "Fast UI" is therefore already solved in `blindkey-core`; the UI's job is to
  not *add* latency (Electron does; native toolkits do not).

---

## 6 — Recommendation (phased, one core)

1. **`ratatui` TUI** — first UI. C20-exact, pure Rust, alt-screen hygiene, nails the dev core loop.
2. **`egui` window** — for non-terminal users; still pure Rust, still C20-aligned.
3. **Native shells via `uniffi`** — **SwiftUI on macOS** (Touch ID + Secure Enclave = C5), Kotlin on
   Android later; all on the same audited core.
4. **Tauri** — only if a *designed, web-styled* app for a broader-than-developer audience is wanted,
   under the strict metadata-only-in-the-webview rule.
5. **Cross-cutting rule:** copy-not-display by default; reveal is opt-in, auth-gated, time-boxed;
   the UI process holds no long-lived plaintext (§1).

**The one decision that touches current work:** at the CP-4 sync point, make the `blindkey-core` public
API **UI-agnostic *and* FFI-friendly** (uniffi-shaped: return structured data + secret-handles,
perform delivery in-core, never print). Get this right once and TUI, egui, SwiftUI, and a possible
Tauri backend are all thin clients on a single frozen, audited core.

---

## 7 — Implications for the intent (see UC-18 §5 and the amendment note)

- **C27 forward constraint** should be extended from "future agentic/MCP interface" to **"any future
  UI surface (TUI/GUI/native shell)"**: copy-not-display default, no long-lived plaintext in the UI
  process, reveal auth-gated and time-boxed. Minimal, non-weakening, no number collision.
- **`non_goals` GUI line** should be clarified from "GUI is a future layer" to name the architecture:
  *shared Rust `blindkey-core` + thin per-platform shells over a stable FFI*; UI remains post-v1.
- **Candidate presentation-layer constraint** (for the maintainers to ratify with a number alongside
  the other Part-2 — C35+ — candidates): the secret-display boundary rule of §1, made testable.

---

## 8 — Sources index

- Tauri vs Electron (binary/memory, native webviews): gethopp.app, dolthub.com blog (2025-11),
  oflight.co.jp, tech-insider.org (2026).
- egui / eframe / wgpu / glow: github.com/emilk/egui, egui.rs, docs.rs/eframe.
- UniFFI (Swift bindings, XCFramework, Mozilla/Firefox usage): github.com/mozilla/uniffi-rs,
  mozilla.github.io/uniffi-rs.
- Signal `libsignal` (Rust core, Java/Swift/TS bindings, all clients + server):
  github.com/signalapp/libsignal.
- macOS-from-Rust crates: lib.rs/crates/security-framework, lib.rs/crates/localauthentication-rs,
  github.com/iqlusioninc/keychain-services.rs (experimental).
- 1Password 8 Electron criticism (memory ~10×, non-native feel): 1password.community discussions,
  appleinsider.com (2021-08).
- ratatui (alternate screen, raw mode, crossterm): ratatui.rs/concepts/backends, docs.rs/ratatui.

*All load-bearing claims above are marked with verification confidence. Crate maturity (esp.
`keychain-services`) and exact macOS API choices must be re-confirmed during the UC-18 spike before
they are treated as settled.*
