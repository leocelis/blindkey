# UC-20 — Desktop GUI Performance & Security Hardening

> **Tech spec** · Draft v0.1 · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-20 · **New constraints:** C40–C45; touches C20, C27, C30, C35, C38, C13
> **Extends:** [UC-18](UC-18-native-ui.md) P2 (`vault-gui`) · **Shipped baseline:** `crates/vault-gui`
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

`vault-gui` (egui/eframe) is **shipped** and covers unlock, import, fuzzy omni-search, copy,
edit, and auto-lock ([UC-18](UC-18-native-ui.md) P2). This spec hardens that shell so it stays
**secure on weak machines and fast on any hardware** — without moving crypto, format, or delivery
logic out of `vault-core`.

Goals:

1. **Pin the lightweight renderer** (glow) explicitly so release builds stay small (~5–6 MB LTO),
   low-RAM (~31 MB idle), and snappy on old laptops — the default posture for a credential utility.
2. **Eliminate redundant per-frame work** — cache fuzzy search results until the query changes;
   bound entry-list layout cost for large vaults.
3. **Close presentation-layer gaps** — verify no eframe persistence, password fields are not
   exposed to accessibility APIs, Linux file-dialog deps are documented.
4. **Preserve reactive repaint** — ~0% CPU when idle; auto-lock timer wakes at ≤1 Hz only.
5. **Document the eframe ≥0.34 upgrade path** — glow stay-or-switch decision + low-latency wgpu
   config if wgpu is chosen.

Out of scope: SwiftUI shell (UC-18 P3), Tauri/webview, new GUI features (keyfile enrollment wizard
is a separate card), egui version bump in this UC (only the decision matrix + Cargo pin land here).

Non-goals: rewriting UC-18's FFI-ready core API; changing fuzzy matcher or frecency (UC-19).

## 2. Prior art

### 2.1 Open source (GUI stack)

| Source | What we take | Confidence |
|---|---|---|
| **egui README** ([github](https://github.com/emilk/egui/blob/main/README.md)) | Immediate mode ~1–2 ms/frame; **reactive repaint** (~0% CPU idle); huge `ScrollArea` is the perf trap. | ✓ verified |
| **eframe docs** ([docs.rs](https://docs.rs/eframe/latest/eframe/)) | Two renderers: **glow** (smaller) vs **wgpu** (default in ≥0.34); **`persistence` feature must stay off** for credential apps. | ✓ verified |
| **egui #5889** — wgpu default switch | Maintainer rationale; glow remains opt-in for lightweight builds. | ✓ verified |
| **egui #7761** — wgpu transition benchmarks | glow ~31 MB RAM / ~5.6 MB LTO binary vs wgpu ~90–176 MB / ~11 MB; glow ~2 frames input lag vs wgpu ~3 @120 Hz; wgpu startup 1–7 s in some apps. | ✓ verified |
| **egui #5037 / commit 8d5a7b4** | `desired_maximum_frame_latency: Some(1)` cuts FIFO lag when wgpu is used. | ✓ verified |
| **rfd docs** ([docs.rs](https://docs.rs/rfd/latest/rfd/)) | Native file dialogs; Linux needs xdg-desktop-portal + backend; sync pick on main thread under eframe. | ✓ verified |
| **vault `research/ui_architecture.md`** | Thin-shell, copy-not-display, GPU texture leak class for on-screen reveal. | ✓ verified |

### 2.2 Shipped code (this repo)

| Module | Pattern already implemented |
|---|---|
| `vault-gui/src/main.rs` | `Action` dispatch, search precompute block, `enforce_auto_lock`, `highlight_title`, shadowed password |
| `vault-gui/src/clip.rs` | stdin clipboard copy, clear-iff-unchanged thread |
| `vault-core::search` | UC-19 fuzzy match; GUI calls `Vault::find` |

## 3. Proposed design

### 3.1 Renderer pin — glow default (C41)

**Problem:** Workspace pins `eframe = "0.29"` with default features; future bumps may silently
switch to wgpu (heavier on weak hardware per §2.1).

**Change:** In the workspace `Cargo.toml`, pin glow explicitly:

```toml
eframe = { version = "0.29", default-features = false, features = ["glow", "wayland", "x11"] }
```

`vault-gui/Cargo.toml` inherits via `{ workspace = true }`. **Do not** enable `persistence`.

**Upgrade matrix** (eframe ≥0.34 — document in `docs/INSTALL.md` GUI section, implement when bumped):

| Target | Renderer | Config |
|---|---|---|
| Weak / old hardware (default) | glow | `default-features = false`, `features = ["glow", "wayland", "x11"]` |
| GPU-rich, measured faster | wgpu | `Renderer::Wgpu` + `desired_maximum_frame_latency: Some(1)` |

```rust
// Only when wgpu is selected (eframe ≥0.34):
let options = eframe::NativeOptions {
    renderer: eframe::Renderer::Wgpu,
    wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
        present_mode: wgpu::PresentMode::AutoVsync,
        desired_maximum_frame_latency: Some(1),
        ..Default::default()
    },
    ..Default::default()
};
```

### 3.2 Search result cache (C38 complement)

**Problem:** `unlocked_screen` calls `vault.find(&self.query, …)` every repaint while the query
is unchanged (e.g. auto-lock's 1 Hz tick, window focus changes).

**Change:** Add a cache on `VaultApp`:

```rust
struct SearchCache {
    query_fingerprint: String,   // the query string at last compute
    items: Vec<(usize, String, Vec<u32>)>,  // idx, title, highlight positions
    total_entries: usize,
}
```

Rules:

- Recompute when `self.query` changes **or** vault entry set changes (add/edit/delete/import).
- On cache hit, skip `vault.find`.
- Still synchronous on miss (no debounce — UC-19 C38).
- Clear cache on `lock()`.

### 3.3 Virtualized entry list (large vaults)

**Problem:** egui `ScrollArea` lays out **all** child rows each frame; cost grows with N ([egui README](https://github.com/emilk/egui/blob/main/README.md)).

**Change:** When `items.len() > LIST_VIRTUALIZE_THRESHOLD` (constant **500**):

1. Compute visible row range from `ScrollArea` scroll offset + viewport height (estimate row height
   24 px).
2. `ui.allocate_ui` only for `items[lo..hi]` plus a spacer for above/below scroll extent.
3. When `items.len() ≤ 500`, keep current simple loop (no regression for typical vaults).

Soft cap documented: vaults above ~2000 entries remain supported (C38 search budget) but list paint
is bounded to ~20–30 rows.

### 3.4 Reactive repaint invariants (C40)

**Rules** (audit + enforce in code review):

| Allowed `request_repaint*` | When |
|---|---|
| `request_repaint_after(1s)` | Unlocked + `auto_lock_secs > 0` only |
| `request_repaint()` | After state change that needs immediate redraw (copy status, lock, import modal) |
| **Forbidden** | Unconditional `request_repaint()` at end of `update()` (Continuous mode) |

`eframe` stays in default **reactive** integration mode — no demo-app `RunMode::Continuous`.

### 3.5 Security hardening (presentation layer)

| ID | Gap | Fix |
|---|---|---|
| VG-S5 | eframe `persistence` | Assert absent in `vault-gui/Cargo.toml` features; add `#[test] fn eframe_has_no_persistence_feature()` reading `cargo tree` or manifest |
| VG-S6 | AccessKit may read password `TextEdit` | Editor password field: `egui::TextEdit::singleline(&mut pw).password(true)`; unlock field already masked; manual VoiceOver/NVDA spot-check — label reads "Password", not value |
| VG-S9 | Control chars in titles | Already `one_line` / `highlight_title`; add test vector with `\x1b[31m` in imported title |
| VG-R2 | Linux rfd | Add **Desktop app (Linux)** subsection to `docs/INSTALL.md`: `xdg-desktop-portal-gtk` or `-kde`, `zenity` |

Existing behaviors **unchanged** (already satisfy UC-18/UC-19): `harden_process()`, `Action`
dispatch, shadowed password default, minimize→lock, masked import, clipboard via stdin.

### 3.6 Frame update workflow (unchanged architecture)

```
update()
  ├─ enforce_auto_lock(ctx)     // may lock; 1 Hz repaint if timer on
  ├─ handle_dropped_files(ctx)
  ├─ unlocked_screen(ctx)     // cache search → virtualized list → collect Actions
  ├─ modals (editor, import, rollback, audit)
  └─ dispatch Actions           // vault-core save / clip — never inside Ui closures
```

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Switch to wgpu now on 0.29 | Higher FPS on some GPUs | 2× binary, 3× RAM, worse startup on weak HW | ❌ defer until eframe bump + benchmark |
| Debounce search in GUI | Fewer find() calls | Violates C38 synchronous UX | ❌ rejected |
| egui `Table` / third-party virtualize crate | Mature virtualization | New dep, C3 review | ⚠️ defer; manual viewport slice first |
| Disable AccessKit entirely | Simpler a11y surface | Regresses platform accessibility | ❌ rejected — fix password exposure instead |
| Persist window geometry via eframe | Nice UX | Wrong feature flag family; use winit only if needed later | ❌ out of scope |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C40** *(new)* | Reactive-only repaint; ≤1 Hz timer tick; test T1 + T2. |
| **C41** *(new)* | glow pinned in manifest; no `persistence`; wgpu path uses `desired_maximum_frame_latency: Some(1)`. |
| **C42** *(new)* | Search cache — no redundant `find` when query/entries unchanged; test T4. |
| **C43** *(new)* | List virtualization above 500 rows; test T6. |
| **C44** *(new)* | Password `TextEdit` fields use `.password(true)`; test T9 + a11y review. |
| **C45** *(new)* | Thin shell — no crypto in GUI; `Action` dispatch after panels; review gate. |
| **C20** | Still single binary, no Node/webview; glow keeps dep tree smaller. |
| **C27** | No change to delivery path; status line shows title only. |
| **C30** | Control-char title test T5. |
| **C35** | Search cache uses same `vault.find` metadata-only path. |
| **C38** | Cache reduces CPU on idle repaints; search on query change still synchronous < 100 ms. |
| **C13** | Clipboard thread unchanged (`clip.rs`). |
| C11/C12/C25 | Editor `Drop` zeroize unchanged; lock clears buffers. |

## 6. Test plan

- **T1 (C40):** Unlock vault, set `auto_lock_secs = 0`, idle 5 s — process CPU ~0% (manual or
  `ps` sample). Grep `update()` — no bare `request_repaint()` without guard.
- **T2 (C40):** `auto_lock_secs = 60` — exactly one repaint scheduling path uses
  `request_repaint_after(Duration::from_secs(1))`.
- **T3 (C41):** `cargo tree -p vault-gui -i eframe` shows `glow`; `persistence` feature absent.
- **T4 (cache):** Unit test on `SearchCache` logic: same query + unchanged entries → `find` not
  called (mock or call counter); query edit → recompute.
- **T5 (C30):** Import entry with ANSI in title; list row shows flattened spaces, no escape sequences.
- **T6 (virtualize):** With 600 synthetic entries, assert row layout hook only runs for ≤
  `LIST_VIRTUALIZE_THRESHOLD + margin` widgets per frame (debug flag or test hook).
- **T7 (C38):** With cache cold, 8-char query at N=2000 still < 100 ms (reuse UC-19 bench ceiling).
- **T8 (regression):** Existing GUI manual smoke — unlock, search `githb`, copy, lock on minimize.
- **T9 (C44):** REVIEW: unlock, editor password, and OTP fields use `password(true)`; manual
  a11y spot-check (VoiceOver/NVDA reads label, not secret).

## 7. Open questions

1. **Intent amendment timing:** C40–C45 promoted in `vault_intent.yaml` v1.5.0 (spec-first);
   implementation PR requires second-maintainer sign-off per GOVERNANCE before merge.
2. **LIST_VIRTUALIZE_THRESHOLD:** 500 is the patterns default; tune after profiling on 2000-entry fixture?
3. **eframe 0.29 → 0.34 bump:** Separate ROADMAP sidequest after this UC, using §3.1 matrix?
4. **GUI keyfile enrollment:** Tracked separately (handoff priority #2) — not part of UC-20.

## 8. Implementation segments (IVD)

| Segment | Files | Patterns |
|---|---|---|
| S1 Renderer pin | `Cargo.toml`, `docs/INSTALL.md` | VG-P3, VG-S5, VG-P4 doc |
| S2 Search cache | `vault-gui/src/main.rs`, `vault-gui/src/search_cache.rs` (if split) | VG-P5, VG-A3 |
| S3 List virtualization | `vault-gui/src/main.rs` | VG-P6 |
| S4 Security + tests | `vault-gui/src/main.rs`, `vault-gui/tests/`, `docs/INSTALL.md` | VG-S6, C44–C45, VG-R2 |
| S5 Validate | `crates/vault-gui/tests/uc20_constraints.rs` | IVD Rule 2 table |

Each segment: re-read constraints from disk → implement → verify → next.
