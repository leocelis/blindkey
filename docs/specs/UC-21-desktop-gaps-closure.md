# UC-21 — Desktop Gaps Closure

> **Tech spec** · Implemented · June 2026  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-21 · **New constraints:** C46–C54  
> **Builds on:** [UC-20](UC-20-desktop-gui-hardening.md) (C40–C45), [UC-09](UC-09-hardware-factors.md), [UC-18](UC-18-native-ui.md)

## 1. Scope

Closes **mitigable** gaps from the UC-20 post-ship review. Each gap is **fixed**, **mitigated**, or **deferred** with an explicit ledger (§7).

### In scope (code)

- Time-boxed password reveal (15 s)
- Optional lock-on-blur
- Keyfile 2FA unlock + enrollment GUI (CLI parity)
- Pre-1.0 security banner
- Configurable clipboard clear timeout
- List virtualization threshold → 100
- Search scope tooltip (C35)
- A11y labels on password fields
- C38 search latency regression hook

### Out of scope (deferred §7)

SwiftUI shell, eframe 0.34 bump, search index at 10k+, private-title mode, eliminating clipboard.

## 2. Proposed design

### 2.1 Session hygiene (C46, C47)

- `reveal_until: Option<Instant>` — auto `reveal = false` after 15 s; schedule `request_repaint_after(1s)` only while reveal active.
- `lock_on_blur` in `~/.vault/config` (default `0`). When `1` and `viewport.focused == false`, call `lock()`.

### 2.2 Keyfile GUI (C48, C49)

**Unlock:** If `Vault::requires_keyfile(bytes)`:
- Show keyfile path picker (`rfd`) + optional "Use recovery code" toggle.
- Open via `Vault::open_keyfile` or `Vault::open` with recovery code bytes.

**Enroll:** Top-bar "🔑 Keyfile 2FA" when unlocked and `!vault.is_2fa()`:
- Pick/create path → `enroll_keyfile_2fa` → `save` → modal with recovery code (copy-friendly, one-time).

### 2.3 Trust & clipboard (C50, C51)

- Banner after unlock until `dismissed_pre10=1` in config.
- `clipboard_timeout_secs` in config; combo 15/30/60 in top bar.

### 2.4 Performance & a11y (C52–C54)

- `LIST_VIRTUALIZE_THRESHOLD = 100`
- Search `hint_text` documents metadata-only scope.
- `ui.label("Master password")` before each password `TextEdit`.

## 3. Constraint map

| ID | Satisfaction |
|----|--------------|
| C46 | Reveal ≤15 s; test T1 |
| C47 | lock_on_blur config; test T2 |
| C48 | Keyfile unlock UI; test T3 |
| C49 | Enroll wizard; test T4 |
| C50 | Pre-1.0 banner; test T5 |
| C51 | Clipboard timeout config; test T6 |
| C52 | Threshold 100; test T7 |
| C53 | C38 bench delegation; test T8 |
| C54 | Labels on password fields; test T9 |

## 4. Test plan

- T1–T9 in `vault-gui/tests/uc21_constraints.rs` + keyfile helper unit tests
- Full workspace `cargo test`

## 5. Implementation segments

| Seg | Work |
|-----|------|
| S1 | `gui_config.rs`, session hygiene |
| S2 | Keyfile unlock + enroll modals |
| S3 | Banner, clipboard, search tooltip, labels |
| S4 | Threshold + tests |

## 6. Open questions

None — consent given via "implement all gaps" instruction.

## 7. Deferred gap ledger

| ID | Gap | Why deferred |
|----|-----|--------------|
| DG-1 | Native SwiftUI | UC-18 P3; months of work |
| DG-2 | Third-party security review | Optional human process; not required for v1.0 (CP-7 = automated gate) |
| DG-3 | eframe 0.34 | Needs benchmark sidequest |
| DG-4 | Search index 10k+ | C38 sufficient for v1 |
| DG-5 | No clipboard | Contradicts C27 UX |
