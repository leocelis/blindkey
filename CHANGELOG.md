# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepablechangelog.com/en/1.1.0/), and the project aims to adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source project scaffolding: governance, security policy, CI/security automation,
  documentation skeleton, and the `vault-core` / `vault-cli` / `vault-hardware` workspace.
- Intent specification with 34 constraints across 11 groups ([vault_intent.yaml](vault_intent.yaml)),
  including AI-era hardening (CSPRNG generation `C26`, model-blind delivery `C27`).
- Research foundation: security spec, AI-era offensive-LLM threat landscape, a security
  coverage-gap analysis, and a UI-architecture study ([research/](research/)).
- Product & design layer: a PRD with 18 major use cases ([docs/PRD.md](docs/PRD.md)), a tech spec
  per use case ([docs/specs/](docs/specs/README.md)), a dependency-ordered roadmap (critical path +
  sidequests), and a two-maintainer co-work protocol ([cowork.yaml](cowork.yaml)).
- UI direction (post-v1): shared Rust `vault-core` + thin per-platform shells over a stable FFI
  (Signal/UniFFI pattern); `ratatui` → `egui` → SwiftUI; copy-not-display delivery — `UC-18`.
- Quick-capture import of an unstructured secrets file with masked interactive review — `UC-17`.
- **CP-1 file-format core** implemented in `vault-core`: hardened, bounded header / stanza /
  HmacBlockStream parsers; the bounded TLV **entry/payload model** (`Entry`, `Payload`, and a
  zeroizing/redacted/constant-time `Protected` type — the C18/C19 structure, inner-stream
  encryption deferred to the crypto segment); Argon2id floor+ceiling validation; `data_key`-keyed
  integrity; and **four** fuzz targets wired to the real parsers (constraints `C2`, `C5`, `C7`–`C10`,
  `C18`, `C19`, `C30`). 45 unit tests; `fmt` + `clippy -D warnings` clean on the pinned toolchain.
- **CP-2 cryptographic core (part 1)** in `vault-core`: Argon2id KDF with Unicode-**NFC** password
  normalization for cross-platform key stability (`C2`), a shared HKDF-SHA-256 helper, CSPRNG
  data-key generation (`C4`), and the **password-stanza envelope** — wrap/unwrap the data key via
  `HKDF → XChaCha20-Poly1305` with an ambiguous wrong-password error and the data key never stored
  in plaintext (`C5`). Adds the `unicode-normalization` dependency (MIT/Apache). 53 unit tests total.
- **CP-2 part 2 + vault round-trip** — XChaCha20-Poly1305 **STREAM** payload encryption (age
  construction: 64 KiB chunks, 11-byte-counter‖last-flag nonce, per-save `nonce_prefix` HKDF salt —
  `C1`), and the `Vault` orchestration (`create`/`open`/`save` + `search`/`get`) tying header +
  envelope + STREAM + HmacBlockStream + payload into a working encrypted `.vlt` round-trip. The
  **C18 "`strings` reveals nothing" property is now verified end-to-end**; body tamper → `BodyAuth`,
  wrong password → ambiguous `HeaderAuth`. (C19 inner-stream pass deferred; outer AEAD secures at
  rest.) 65 unit tests total; fmt + clippy clean.
- **`keys.txt` migration MVP — end to end.** A lenient importer in `vault-core`
  ([`import::parse_raw`](crates/vault-core/src/import.rs), UC-17): splits a messy file on blank
  lines / `---`, skips `#` comments, classifies each line as secret (provider prefix or Shannon
  entropy) vs label, and builds `Entry` values — shared by the CLI and the future desktop app. Plus
  a working **CLI** (`vault init` / `import --format raw` / `ls [--search]` / `get [--stdout]`):
  no-echo password prompt (`rpassword`, no secrets on argv — C29), atomic `0600` file writes,
  masked import review (C27), clipboard delivery via the OS tool over stdin (C27), terminal output
  sanitization (C30). A synthetic [`samples/keys.txt`](samples/keys.txt) fixture exercises it.
  Verified end-to-end on a real file: 9 messy entries imported, searchable, retrievable, and the
  encrypted `.vlt` leaks neither titles nor secrets (C18).
- **Clipboard auto-clear (C13 / UC-04).** `vault get` spawns a **detached holder** that wipes the
  clipboard after `--timeout` seconds (default 30) — but only if it still holds the delivered secret
  (clears-iff-unchanged, so it won't erase something you copied since). The secret reaches the holder
  over an inherited stdin pipe, never argv or environment (C29). Verified live on macOS.
- **`vault gen` (C26)** — CSPRNG password generator in `vault-core` (`gen::password`) using
  **rejection sampling** (no modulo bias): `--charset alnum|ascii`, `--length 8..256`, with the
  entropy in bits reported. Lets you rotate the weak passwords an import surfaces. (The diceware
  `words` mode is pending the bundled EFF wordlist.)
- **Entry management — `vault add` / `edit` / `rm`.** Completes the daily-use manager: `add NAME`
  (interactive; **Enter at the password prompt generates a strong one**), `edit NAME` (per-field,
  Enter keeps the current value, optional password rotation), `rm NAME` (confirm on a TTY). The core
  gains `Vault::entry_mut` and `Vault::remove`. You can now rotate a weak imported password in place.
- **CLI integration test + KDF-cost flags.** [`crates/vault-cli/tests/cli.rs`](crates/vault-cli/tests/cli.rs)
  drives the real binary end-to-end (init → import the sample → ls → get → wrong-password → rm → gen)
  and asserts the encrypted file leaks neither secrets nor titles (C18). `init` gains hidden
  `--kdf-m-cost/-t-cost/-p-cost` flags (advanced) so tests and slower machines can tune Argon2id.
- **`vault-tui` — the first app shell (UC-18).** A **ratatui** terminal UI over `vault-core`:
  unlock → **type-to-search** → `↑/↓` select → **Enter copies the secret to the clipboard**
  (model-blind, auto-clears via a background thread, clears-iff-unchanged), `Esc` to quit. Runs on
  the **alternate screen** so nothing a secret touches reaches terminal scrollback, and the secret
  is **never rendered** — only titles. Pure-Rust shell; all secret-handling stays in the core. This
  is the first "managed via the app" surface; egui/SwiftUI follow over the same core.
- **Memory hardening (C12 + C25).** New isolated-`unsafe` crate **`vault-sys`** — the *one* place
  `unsafe` lives (every other crate stays `#![forbid(unsafe_code)]`) — wraps `setrlimit`/`mlock`/
  `munlock` behind a safe, best-effort API. `vault-core::memory` now provides `harden_process()`
  (disables core dumps at startup, wired into the CLI and TUI — so a crash can't dump secrets to a
  core file), `ct_eq` (constant-time comparison, C25), and a `PageLock` guard that mlocks the
  transient decrypted-payload buffer off swap during open/save (C12, graceful degradation — warns
  and continues if locking is unavailable). *(C19's in-memory inner-stream protection — keeping
  Protected fields ChaCha20-encrypted in RAM until accessed — remains a scoped follow-up.)*
- **Weak-KDF warning + `vault upgrade-kdf` (C2).** Opening a vault whose Argon2id cost is below the
  recommended floor now prints a warning suggesting an upgrade (centralized in a shared `open_vault`
  helper). `vault upgrade-kdf [--kdf-m-cost/-t-cost/-p-cost]` re-wraps the password stanza under
  stronger parameters and does a full body-writing save (version bump per G0.3); the data key and
  salt are unchanged, so entries stay intact. Core gains `Vault::kdf_strength` and `Vault::change_kdf`.
- **`vault-gui` — the desktop window app (UC-18 P2).** A pure-Rust **egui/eframe** GUI over
  `vault-core`: a create/unlock screen, **drag-and-drop (or pick) a `keys.txt`** with a masked
  review dialog before import, **type-to-search**, a detail pane that shows the password **shadowed**
  with one-click **Copy** (model-blind — the secret is never rendered; clipboard auto-clears after
  30 s, clears-iff-unchanged — C13/C27), a **Reveal** toggle, and **Add / Edit / change-password /
  Delete** with an in-app strong-password generator. Persists through the same atomic `0600` save as
  the CLI; secrets stay in the core; the in-memory password buffer is zeroized on drop.
  [`scripts/bundle-macos.sh`](scripts/bundle-macos.sh) wraps the release binary in a double-clickable
  `Vault.app`. Run with `cargo run -p vault-gui` (or `open target/Vault.app`).
- **Inner-stream encryption of Protected fields — at rest AND in memory (C19, complete).** New
  [`format::inner_stream`](crates/vault-core/src/format/inner_stream.rs): every Protected field
  value (password, `otp_secret`, protected custom values) receives an **additional ChaCha20
  stream-cipher pass** keyed by the payload's 64-byte `inner_stream_key`, processed in document
  order through one advancing stream (KDBX-4 precedent), so inside the outer-AEAD-decrypted payload
  the secret bytes are **double-encrypted at rest** and the key is **regenerated every save**.
  *And in memory:* after a vault is opened, Protected fields stay **ChaCha20-encrypted in RAM**
  (`Protected` is now `Plain | Sealed{ct, Arc<SealKey>, offset}`) and are decrypted **only on access**
  via a seekable, **mlocked** session key — so a swap leak or partial heap disclosure of the
  decrypted payload doesn't directly expose password bytes (this is the in-memory-secrets weakness
  flagged in the KeePassXC audit). `Protected::expose()` now returns owned zeroizing plaintext;
  the CLI/TUI/GUI were updated accordingly. 7 new tests, including the C19 in-memory assertion (a
  loaded field's bytes are ciphertext until the accessor runs) and seek-equals-sequential-stream.
  Adds the audited `chacha20` crate (C3). The session still holds the key, so this does not defend
  against a full key-inclusive memory dump (KDBX 4 has the same property — see the C19 rationale).
- **Rollback detection — the untrusted-storage use case is now complete (C16 / UC-07).** A vault you
  park on Google Drive, a droplet, or git is already unreadable and tamper-evident (C1/C5/C9/C10/C18);
  this adds the last guarantee — a backend that serves an **older** copy is caught. New
  [`rollback`](crates/vault-core/src/rollback/mod.rs): an 8-byte little-endian **local anchor** kept
  *outside* the synced folder (`$XDG_DATA_HOME`/`~/Library/Application Support`/`%LOCALAPPDATA%` →
  `vault/<vault_id>.state`), advanced monotonically (`max`) under an advisory **flock** (new
  `vault-sys::flock_exclusive`) via atomic temp+rename. The CLI checks it on every open and advances
  it on every save: a regression **warns + prompts** on a TTY (default abort) and **exits 2** with no
  prompt non-interactively; `--allow-rollback` proceeds (anchor not lowered) and `--expect-min-version
  N` pins a floor for a freshly provisioned machine (trust-on-first-use mitigation). The desktop GUI
  shows a rollback warning banner and advances the anchor on open/save. New end-to-end guide
  [docs/guides/sync-to-untrusted-storage.md](docs/guides/sync-to-untrusted-storage.md). 6 new tests
  (core anchor unit tests + a CLI integration test covering regression→exit 2, `--allow-rollback`,
  TOFU, and `--expect-min-version`). `Vault::vault_id()` added.
- **Optional Padmé size-padding (UC-07 §3.2).** New [`pad`](crates/vault-core/src/pad.rs): a single
  encrypted blob still leaks its *length* (≈ entry count) to a backend; turning padding on rounds the
  plaintext payload up to a **Padmé** bucket (`⌊log₂log₂L⌋+1` significant length bits → `O(log log L)`
  leakage at `≤ ~12 %` overhead). Padding is appended **inside** the AEAD (after the `END` marker the
  parser already ignores), so it's encrypted, authenticated, and invisible. The policy is **sticky**
  (persisted in the inner header, default off) and toggled with **`vault pad on|off`** or the desktop
  app's **"Pad size"** checkbox; `Vault::padding()`/`set_padding()` added. 6 new tests (Padmé bucket
  math + bound, sticky round-trip, CLI toggle).
- **`vault tune` (C22).** New [`crypto::tune`](crates/vault-core/src/crypto/tune.rs): benchmarks
  Argon2id on the current machine and recommends `m`/`t`/`p` targeting the ~300 ms interactive-unlock
  budget — it probes at a baseline memory cost, linear-extrapolates `m` (Argon2 time is ~linear in
  `m`), clamps into the policy floor/ceiling, and re-measures so the reported time is real. Prints the
  recommendation to stdout (scriptable) with an `upgrade-kdf` apply hint. Unlocking commands now also
  print a `Deriving key (Argon2id)…` progress line so a slow unlock doesn't look hung (C22). 2 new
  tests.
- **Diceware passphrases (C26).** `vault gen --words N` now produces a CSPRNG passphrase (unbiased
  rejection sampling over the word list, joined by `-`), and the desktop app's editor gains a
  **"🔑 Passphrase"** button. Ships a verifiable **built-in 256-word list**
  ([`wordlist`](crates/vault-core/src/wordlist.rs), exactly `2^8` → 8 bits/word, guarded by a
  no-duplicates/format test) for zero-setup use; `--wordlist <file>` accepts a user-supplied list
  (e.g. the EFF large list, ~12.9 bits/word — plain or `dice⇥word` lines). Entropy is reported.
  `gen::passphrase()`/`passphrase_entropy_bits()` added. 4 new tests. *(The full EFF list isn't
  bundled — it can't be reproduced offline without fabricating it; download it and pass `--wordlist`.)*
- **Auto-lock in the desktop app (UC-06 / S-10).** The GUI no longer stays unlocked forever: it
  clears the decrypted vault from memory and returns to the unlock screen after an **idle timeout**
  (default 5 min, chosen from a top-bar **Auto-lock** menu: 1m/5m/15m/30m/Never, persisted to
  `~/.vault/config`) and **immediately when the window is minimized**. The idle timer keeps ticking
  while the app is idle (`request_repaint_after`). Closes the "decrypted vault sits in RAM
  indefinitely" gap for the long-lived shell (the one-shot CLI already exits after each command).
- **Project-scoped Rust toolchain** ([`scripts/setup-rust.sh`](scripts/setup-rust.sh),
  [`scripts/dev-env.sh`](scripts/dev-env.sh), [`.envrc`](.envrc)): the toolchain installs into
  `./.toolchain` (git-ignored) via rustup's `RUSTUP_HOME`/`CARGO_HOME` + `--no-modify-path` — never
  into `~/.rustup`, `~/.cargo`, or shell profiles. Reproducible, self-contained, and removable with
  `rm -rf .toolchain`. Documented in [CONTRIBUTING.md](CONTRIBUTING.md).

### Changed
- **Toolchain / MSRV bumped `1.82.0` → `1.96.0`** ([rust-toolchain.toml](rust-toolchain.toml),
  workspace `rust-version`). A deliberate, recorded bump to support the desktop GUI stack
  (eframe/egui/winit/wgpu), whose transitive dependencies require Rust-2024-edition crates
  (cargo ≥ 1.85). The security core (`vault-core`/`vault-cli`/`vault-tui`/`vault-sys`) remains
  **1.82-source-clean** — newer-only APIs are avoided (e.g. an explicit `#[allow]` over a
  `% == 0` rather than `u64::is_multiple_of`). The crypto crates stay pinned (C3); GUI deps
  (`eframe`/`egui`/`rfd`) are dependabot-guarded against churn.
- Intent **v1.4.0** is canonical (see the Security section). A parallel `main`-side Gate-0 pass
  (v1.3.0, C28–C31) was **reconciled into v1.4.0** during the spec-hardening merge: KDF ceiling is
  folded into `C2` (not a separate constraint), G0.3 is resolved as an `upgrade-kdf` full save (no
  `header_generation` field), and the C28–C34 numbering below is authoritative.
- Intent **v1.2.0**: extended `C27`'s forward constraint to UI surfaces (copy-not-display, no
  plaintext marshalled into an unzeroable managed-runtime heap) and clarified the GUI non-goal.
- Intent **v1.1.0**: fixed `C1`/`C8` XChaCha20 keystream reuse across saves via a per-body-write
  `nonce_prefix` HKDF salt (with conflict resolution `SC6`); fixed the SLSA provenance job in
  `release.yml`.

### Security (2026-06-10 spec-hardening pass — pre-implementation)
- Promoted the high-severity coverage gaps to enforced constraints: terminal output sanitization
  (`C28`), export/CSV-injection hardening (`C29`), parser robustness with `forbid(unsafe_code)` +
  CI fuzzing (`C30`), no secrets on argv (`C31`), atomic durable saves with locking (`C32`),
  clipboard concealment (`C33`), and reproducible/signed releases with provenance (`C34`).
- Folded a KDF parameter **ceiling** (anti-DoS, checked arithmetic) and **Unicode NFC**
  normalization of the master password into `C2`.
- Resolved spec self-contradictions: `C19` inner-stream key is regenerated per **save** (not per
  open) with an honest in-memory-protection rationale; `C5` documents the YubiKey
  device-at-save coupling with a graceful abort; `C12` scopes mlock to long-lived secrets with a
  once-per-process warning; `C16` documents the fresh-device trust-on-first-use limitation;
  `C20`'s acceptance test no longer passes a password on argv; `C27` states explicitly what
  model-blind delivery does and does not defend against.
- Constraint count 27 → 34; groups 10 → 11 (new `G11` — untrusted input/output robustness);
  satisfiability conflicts grew to 8 (`SC7` argv-vs-scriptability, `SC8` ceiling-vs-file-authoritative;
  `SC6` is the C1/C4 nonce_prefix binding from the keystream fix below). Intent version 1.3.0.

### Added (2026-06-10 — governance & release-trust follow-ups)
- `ADR-0003` (nonce_prefix payload-key salt) and `ADR-0004` (data-key-keyed HMACs,
  `master_seed` bound to body writes) — the ADRs GOVERNANCE requires for the v1.1.0/v1.4.0
  cryptography amendments.
- `release.yml` is now **fail-closed** per `C34`: the GitHub Release is created as a draft and
  flipped public only after cosign signing *and* SLSA provenance both succeed (attestation
  attached in the same finalize job).
- All GitHub Actions across the five workflows are **pinned by commit SHA** (Scorecard
  Pinned-Dependencies; Dependabot maintains the pins). Documented exemption: the SLSA generator
  must be referenced by version tag per slsa-verifier requirements.
- All 16 tech specs bumped to Draft v0.2 (pending acceptance review) reflecting the
  intent v1.3.0–v1.4.0 synchronization.

### Security (2026-06-10 — Gate 0 close-out, intent v1.4.0)
- `C9`/`C10` (G0.2): header and block HMAC keys now derive from the **data key**
  (`vault-header-hmac-v2` / `vault-block-hmac-v2`) — verifiable on hardware-only unlocks and
  stable across password rotation. Corollary fix: `master_seed` rotation is bound to
  **body-writing saves** (rotating it on a header-only save would have orphaned every stored
  block HMAC — a latent contradiction in SC6's original resolution). C9's error semantics are
  now two-stage: wrong password / tampered KDF params fail the stanza unwrap with one
  indistinguishable error; a header-HMAC failure after a valid unwrap is unambiguous tampering.
- `C2` (G0.3): `vault upgrade-kdf` is a full body-writing save (version bump, fresh
  `master_seed`/`nonce_prefix`, body re-encrypted) — a sync backend can no longer serve the
  pre-upgrade weak-KDF file undetected.
- `C13` (G0.6): the clipboard clear-timer is a **detached helper process** (a thread cannot
  outlive a one-shot CLI) with clear-iff-unchanged semantics and constant-time comparison.
- `C5` (G0.7): YubiKey challenge stored per-stanza (`extra = {slot, challenge}`), refreshed on
  device-present body-writing saves; graceful staleness with a loud warning is the default,
  `yubikey_strict` / `--strict-yubikey` opts into abort-on-absent (supersedes the v1.3.0
  strict-abort wording; resolves the C5↔UC-09 contradiction).
- `C21`/`C27` (G0.8): frozen exit-code map 0–9 (rollback keeps 2; clap usage moves to 8);
  new `vault stanzas list|add|remove` commands; headless `vault get` without `--stdout`
  refuses with exit 7 — never a silent stdout fallback.
- CI now installs the `rust-toolchain.toml`-pinned toolchain in every job (was `@stable` —
  a reproducibility leak vs `C34`); fuzz jobs keep nightly by documented exemption.

### Security (2026-06-10 — C1 keystream-reuse fix, intent v1.1.0)
- `C1`/`C8`: the empty-HKDF-salt deviation from age allowed XChaCha20 **keystream reuse across
  saves** (constant data key + counter nonces restarting at 0 ⇒ a history-keeping sync backend
  could XOR successive versions to recover plaintext diffs). Fixed with a per-body-write 16-byte
  `nonce_prefix` as the HKDF salt for the payload key, restoring age's construction; `SC6` binds
  salt rotation to body writes so `C4`'s O(1) password rotation is preserved.
- `release.yml`: SLSA provenance subjects were empty (matrix job outputs overwrote each other);
  a dedicated `hashes` job now computes the combined subjects.

### Added (product & design layer)
- `docs/PRD.md` (16 use cases, personas, success metrics) and `docs/specs/` — one tech spec per
  use case with alternatives, constraint compliance maps, and test plans.
- `ROADMAP.md` rewritten as dependency order: Gate 0 intent decisions, critical path CP-1..CP-7,
  parallel-safe sidequests, two-lane split.
- `cowork.yaml` + `CLAUDE.md`: two-maintainer/two-agent collaboration protocol (AG1–AG10).

### Notes
- This project is **pre-alpha**. No functional release exists yet; do not store real secrets.

[Unreleased]: https://github.com/leocelis/vault/commits/main
