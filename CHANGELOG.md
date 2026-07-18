# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Sealed file storage (UC-23 / S-22, C61–C66):** `.vltf` containers — `blindkey seal` / `open` /
  `peek` (incl. `seal -` pipe mode, `--append` merge), `--vault FILE.vltf` stanza
  enroll/remove/upgrade-kdf/rotate-data-key + keyfile/YubiKey/FIDO2/TPM unlock; GUI drag-and-drop
  with byte progress/cancel and optional keyfile 2FA at seal time; TUI parity; release throughput
  bench in `just audit-ready`; spec **Accepted v1.0**. Spec:
  [docs/specs/UC-23-sealed-file-storage.md](docs/specs/UC-23-sealed-file-storage.md).
- **KDF floor write policy (C2):** hard-reject below-floor Argon2id on `blindkey init` and
  `blindkey upgrade-kdf`; warn-only on open/import. Escape hatch: `blindkey init --allow-weak-kdf`.
  Research: [research/kdf_floor_policy_research.md](research/kdf_floor_policy_research.md).
- **Sync / fleet provisioning (C16):** expanded
  [guides/sync-to-untrusted-storage.md](docs/guides/sync-to-untrusted-storage.md) with
  `--expect-min-version`, anchor lookup, and headless fleet script; global flags in
  [docs/CLI.md](docs/CLI.md); enterprise cross-link.
  Research: [research/sync_provisioning_research.md](research/sync_provisioning_research.md).
- **YubiKey strict default (C5):** new 2FA enrollments persist `yubikey_strict=true`; saves
  refresh the composite stanza when the key is present; strict abort / graceful warning when absent.
  Flags: `--graceful-yubikey`, `--strict-yubikey`, `--allow-stale-yubikey`.
  Research: [research/yubikey_strict_default_research.md](research/yubikey_strict_default_research.md).
- **Agent broker scaffold (S-13 / C27):** `blindkey-agent` crate + `blindkey agent` CLI (handles,
  Unix-socket broker, TTY approval, env injection, status-only IPC). ADR-0006.
  Guide: [docs/AGENT_BROKER.md](docs/AGENT_BROKER.md).
  Research: [research/agent_broker_research.md](research/agent_broker_research.md).

### Changed
- **Governance docs flattened to OSS convention:** MAINTAINERS.md is a flat handle list;
  decision tiers in GOVERNANCE.md phrase authority as **code-owner sign-off**
  (path-scoped via [CODEOWNERS](.github/CODEOWNERS)), not person-rank labels.
- **Docs/comments hygiene:** internal work-tracking references removed from public
  research notes, ADR metadata, and code comments; constraint-count references updated
  to the current intent (66 constraints, v1.8.0).
- **CI hardened for OSS-readiness (found in repo audit, 2026-07-17):** added `macos-latest` to
  the required matrix and an experimental non-blocking `windows-latest` job (blindkey-sys is
  `cfg(not(unix))`-safe but unverified on Windows in CI until now); added `audit` job running
  `cargo audit` + `cargo deny check` + `cargo vet`; added `reproducible` job running
  `scripts/reproducible-build.sh`. Previously CI only ran fmt/clippy/test on `ubuntu-latest`,
  so the macOS binary Blindkey ships and the supply-chain/reproducibility claims in SECURITY.md and
  docs/VERIFYING_RELEASES.md were never actually checked by CI.
- **Dependabot enabled** for `cargo` and `github-actions` ecosystems (weekly).

### Fixed
- Root `LICENSE` pointer file's prose content replaced with the verbatim MIT text (was
  free-form prose that GitHub's license detector read as "Other" instead of resolving the
  dual MIT/Apache-2.0 grant). The file itself could not simply be deleted — constraint C24
  (`crates/blindkey-cli/tests/constraint_policy.rs`) asserts `LICENSE` exists alongside
  `LICENSE-MIT`/`LICENSE-APACHE`; deleting it was reverted after the constraint test caught it.
- README: constraint count corrected 60 → 66 (was inconsistent with the same page's own "66
  constraints" claim two sections up, and with `blindkey_intent.yaml` v1.8.0).
- README quickstart: `blindkey import ... samples/keys.txt` failed for anyone who installed the
  binary without cloning the repo (the sample file only exists in-tree); quickstart now creates
  the sample inline first.
- Fixed 3 broken relative doc links: `docs/adr/0006-agent-broker-scaffold.md` →
  `research/agent_broker_research.md` (wrong `../` depth), `docs/specs/UC-19-omni-search.md` →
  `vault.rs:381` (not a resolvable path; now `vault.rs#L381`), `docs/guides/enterprise-deployment.md`
  → `docs/specs/UC-05-...md` (missing `../`).
- `docs/CRATES_IO_TRUSTED_PUBLISHING.md` now documents the crates.io name collision blocking
  publication (see Known limitations below) instead of implying `cargo install blindkey-cli` works.

### Known limitations (surfaced by audit, unresolved — need a maintainer decision)
- **crates.io name collision:** `blindkey`, `blindkey-cli`, and `blindkey-core` are taken by unrelated
  published crates. `cargo install blindkey-cli` (promised in README/SECURITY.md) cannot work under
  the current names. Blocks publishing until the project is renamed.
- **No signed/notarized release artifacts.** The `v0.1.0-alpha.3` macOS binary is unsigned and
  un-notarized (`scripts/bundle-macos.sh` says so explicitly) — Gatekeeper will quarantine it on
  first run. No `v1.0.0` git tag or GitHub Release exists yet despite `Cargo.toml`/this
  CHANGELOG saying 1.0.0 shipped 2026-06-26.
- **No branch protection on `main`** and no OpenSSF Scorecard/Best-Practices badge — both are
  free, low-effort trust signals evaluators of security tools commonly check for.

## [1.0.0] - 2026-06-26

First **stable** release — format v1 frozen, CP-7 quality gate, post-1.0 user copy.

### Added
- **Format v1 freeze** ([ADR-0005](docs/adr/0005-format-v1-freeze.md)): `format_version = 1` declared
  stable; research in [research/format_freeze_research.md](research/format_freeze_research.md).
- **v1.0.0** workspace version bump; release prep per [docs/RELEASE.md](docs/RELEASE.md).

### Changed
- README, SECURITY, PRD, FILE_FORMAT: **stable format v1** + **v1.0.0** (drop pre-1.0 / pre-alpha banner language).
- CLI `PRE_RELEASE_NOTICE` and GUI audit banner: third-party audit honesty without pre-1.0 label.
- Public OSS launch (2026-06-25): repository visibility public, CI badge restored, GHA cache.
- Documentation sweep: drift fixes, spec status headers, expanded `docs/README.md` hub,
  `ARCHITECTURE.md` adds `blindkey-clip`, `AUDIT_READINESS.md` post-launch checklist.

## [0.1.0-alpha.3] - 2026-06-25

Pre-launch honesty sweep — CP-5 closed, docs aligned, minimal free CI.

### Added
- `blindkey stanzas list|add|remove` (C21); headless clipboard refusal **exit 7** (C27).
- `docs/README.md` documentation hub; GitHub Actions CI (`just check` equivalent, free tier).
- Integration tests: `c21_stanzas_list_after_init`, `c27_headless_get_exits_7` (Linux).

### Fixed
- Clap help no longer marks implemented commands as “not yet implemented”.
- `CONSTRAINT_INDEX.md` C21/C27 labels and evidence; enterprise/release doc contradictions removed.
- `MAINTAINERS.md`, `setup-rust.sh`, `THIRD_PARTY_AUDIT.md` stale references.

## [0.1.0-alpha.2] - 2026-06-25

Open-source launch candidate — documentation polish, no GitHub Actions (local quality gate only),
first GitHub Release with checksums.

### Added
- `SUPPORT.md` — community support paths (Discussions, issues, security).
- README: install/docs/community sections; issue template links to Discussions.

### Changed
- **No GitHub Actions** (from alpha.1 follow-up): maintainer-local releases per `docs/RELEASE.md`.
- `docs/INSTALL.md` — accurate install paths (git, releases, crates.io when published).
- Public-readiness checklist in `docs/AUDIT_READINESS.md`.

## [0.1.0-alpha.1] - 2026-06-22

First **pre-alpha** tagged release — functional CLI + desktop app; on-disk format and API may
still change before `1.0.0`. Not independently audited.

### Known gaps (pre-1.0)
- `blindkey stanzas list|add|remove` not yet implemented (C21).
- Headless clipboard refusal exit 7 not yet wired (C27).
- Live libfido2/TPM device integration deferred (optional M7).

### Changed
- **ROADMAP:** v1.0 release status cross-check (2026-06-22); CP-1–CP-4/CP-7 marked complete;
  CP-5 🟡 (stanzas + exit 7); CP-6 coded but untagged.

### Added
- **C14/C15/C33 close-out:** `blindkey-clip` arboard concealment (C33); FIDO2 mock enroll/unlock
  (C14); TPM CLI `--help` + PCR mock (C15); sweep now 60/60 PASS.
- **CP-7 review fixes:** C28 preserves `\n`/`\t`, sanitizes `get --stdout`, ls/get integration tests;
  C13 `clipboard.rs` clear-iff-unchanged unit tests + hold-clipboard integration; tighter sweep
  row assertions; C29 labeled JSON-only (v1).
- **CP-7 IVD sweep:** full C1–C60 PASS/NEEDS_REVIEW table in `docs/CONSTRAINT_INDEX.md`
  (57 PASS, 3 NEEDS_REVIEW); `audit-readiness.sh` runs workspace tests + fmt check;
  C28 terminal sanitize module + named tests; C29 export JSON test; constraint index tests.
- **CP-6 distribution trust:** reproducible release env in `release.yml`, in-pipeline cosign
  verify, vendor tarball, crates.io Trusted Publishing job, `just reproduce`, release docs.
- **`blindkey lock` (CP-5):** clears clipboard and documents per-process CLI session model (UC-06 §3.4).
- **`blindkey export --format json` (S-6 / UC-05):** full-vault plaintext JSON to stdout with frozen
  warning, TTY confirmation or `--yes`, strict serde_json encoding (C29), integration tests.
- **Audit gap closure:** `BLINDKEY_PASSWORD_FILE`, `--password-fd`/`--password-stdin`, `cargo auditable`
  + CycloneDX in `release.yml`, C54 a11y label tests + accessibility guide, third-party audit
  doc, research gap headers synced to ADDRESSED status.
- **OSS readiness audit fixes:** fuzz CI gates PRs, VERIFYING_RELEASES/SECURITY/cowork aligned to
  CP-7 quality gate, research doc historical banners, CLI `BLINDKEY_VAULT_PATH` parity, workspace
  `readme`, CONSTRAINT_INDEX methodology notes.
- **Constraint coverage gaps closed (C3, C4, C6, C14, C15, C17, C23, C24):** dedicated tests in
  `constraint_gaps.rs`, `constraint_policy.rs`, `constraint_hardware.rs`; FIDO2 salt/HKDF helpers
  and TPM policy strings in `blindkey-hardware`.
- **OSS readiness sweep:** aligned docs to functional pre-1.0 status, 60 constraints (v1.7.0),
  distributed test index (`docs/CONSTRAINT_INDEX.md`), architecture diagram includes TUI/GUI,
  release builds scope to `blindkey-cli`, quality-gate terminology, root `LICENSE` pointer.
- **UC-22 enterprise readiness (C55–C60):** `scripts/audit-readiness.sh` + `just audit-ready`,
  `docs/AUDIT_READINESS.md`, `docs/ENTERPRISE_POSTURE.md`, `docs/guides/enterprise-deployment.md`,
  GUI env vars (`BLINDKEY_VAULT_PATH`, `BLINDKEY_CONFIG_DIR`, `BLINDKEY_LOCK_ON_BLUR`), C38 release-only
  bench, C59 N=5000 / 200 ms search bench. Spec
  [UC-22](docs/specs/UC-22-enterprise-readiness.md); intent v1.7.0.
- **UC-21 desktop gaps closure (C46–C54):** time-boxed reveal (15s), optional lock-on-blur,
  keyfile 2FA enroll/unlock GUI, pre-1.0 banner, configurable clipboard timeout, virtualize
  threshold 100, metadata-only search hint, password field labels. Spec
  [UC-21](docs/specs/UC-21-desktop-gaps-closure.md); intent v1.6.0.
- **UC-20 desktop GUI hardening (implemented):** glow renderer pin (C41), fuzzy search cache
  (C42), entry-list virtualization above 500 rows (C43), reactive-repaint invariants (C40),
  password-field masking audit (C44), thin-shell constraint tests (C45). New modules
  `search_cache.rs`, `list_virtualize.rs`; tests in `blindkey-gui/tests/uc20_constraints.rs`.
- **Intent v1.5.0:** UC-20 desktop GUI constraints **C40–C45** (G13) — reactive repaint,
  glow renderer pin, search cache, list virtualization, password masking, thin-shell boundary.
  Spec: [docs/specs/UC-20-desktop-gui-hardening.md](docs/specs/UC-20-desktop-gui-hardening.md).
- **CLI import/search hardening:** piped `import` without `--yes` exits **8** (UC-05/UC-17).
  Pre-1.0 audit notice on init/import; automatic `vault.vlt.bak` on init and before import
  overwrites. `blindkey find` no-match explains C35 searchable scope. `./scripts/install.sh` +
  updated [docs/INSTALL.md](docs/INSTALL.md) and [docs/CLI.md](docs/CLI.md).
- **Fuzzy keyboard-first omni-search (UC-19, CLI + GUI).** Type a few characters — `gh`, `awsprod`,
  a typo like `githb` — and the right entry rises to the top instantly; Enter copies the password to
  the (auto-clearing, model-blind) clipboard. fzf-quality scoring via `nucleo-matcher` (offline,
  Unicode-correct, returns highlight indices) behind a small swappable `vault_core::search`
  trait. **Searches metadata only — title, username, url, tags, never secret values (C35)** — so the
  matcher can't leak a secret it never sees; the GUI tints the matched characters. Usage history
  (**frecency**, zoxide tiers) nudges the entries you reach for to the top without overpowering match
  quality; it is stored as **ciphertext inside the encrypted payload, never a plaintext index on
  disk (C36)**. The query buffer is wiped on lock and never logged (**C37**); matching is synchronous
  with no debounce and stays well under 100 ms at 2000 entries (**C38**); selection delivers through
  the existing model-blind clipboard path (**C39**). New `blindkey find [QUERY]` (`--stdout` lists ranked
  titles, scriptable); GUI omni-bar with ⌘K/Ctrl-K focus and Ctrl-N/Ctrl-P navigation. New
  `vault_core::search` + `vault_core::frecency`; `Blindkey::find` / `record_use`. New intent group **G12**
  (constraints **C35–C39**). Built via the research→extract→spec→PRD→implement→validate cycle
  ([docs/specs/UC-19](docs/specs/UC-19-omni-search.md)). +18 tests (core 126, CLI 9).
- Open-source project scaffolding: governance, security policy, CI/security automation,
  documentation skeleton, and the `blindkey-core` / `blindkey-cli` / `blindkey-hardware` workspace.
- Intent specification with 34 constraints across 11 groups ([blindkey_intent.yaml](blindkey_intent.yaml))
  *(historical — now **60 constraints / 15 groups**, intent v1.7.0)*,
  including AI-era hardening (CSPRNG generation `C26`, model-blind delivery `C27`).
- Research foundation: security spec, AI-era offensive-LLM threat landscape, a security
  coverage-gap analysis, and a UI-architecture study ([research/](research/)).
- Product & design layer: a PRD with 18 major use cases ([docs/PRD.md](docs/PRD.md)), a tech spec
  per use case ([docs/specs/](docs/specs/README.md)), a dependency-ordered roadmap (critical path +
  sidequests), and a two-maintainer co-work protocol ([cowork.yaml](cowork.yaml)).
- UI direction (post-v1): shared Rust `blindkey-core` + thin per-platform shells over a stable FFI
  (Signal/UniFFI pattern); `ratatui` → `egui` → SwiftUI; copy-not-display delivery — `UC-18`.
- Quick-capture import of an unstructured secrets file with masked interactive review — `UC-17`.
- **CP-1 file-format core** implemented in `blindkey-core`: hardened, bounded header / stanza /
  HmacBlockStream parsers; the bounded TLV **entry/payload model** (`Entry`, `Payload`, and a
  zeroizing/redacted/constant-time `Protected` type — the C18/C19 structure, inner-stream
  encryption deferred to the crypto segment); Argon2id floor+ceiling validation; `data_key`-keyed
  integrity; and **four** fuzz targets wired to the real parsers (constraints `C2`, `C5`, `C7`–`C10`,
  `C18`, `C19`, `C30`). 45 unit tests; `fmt` + `clippy -D warnings` clean on the pinned toolchain.
- **CP-2 cryptographic core (part 1)** in `blindkey-core`: Argon2id KDF with Unicode-**NFC** password
  normalization for cross-platform key stability (`C2`), a shared HKDF-SHA-256 helper, CSPRNG
  data-key generation (`C4`), and the **password-stanza envelope** — wrap/unwrap the data key via
  `HKDF → XChaCha20-Poly1305` with an ambiguous wrong-password error and the data key never stored
  in plaintext (`C5`). Adds the `unicode-normalization` dependency (MIT/Apache). 53 unit tests total.
- **CP-2 part 2 + vault round-trip** — XChaCha20-Poly1305 **STREAM** payload encryption (age
  construction: 64 KiB chunks, 11-byte-counter‖last-flag nonce, per-save `nonce_prefix` HKDF salt —
  `C1`), and the `Blindkey` orchestration (`create`/`open`/`save` + `search`/`get`) tying header +
  envelope + STREAM + HmacBlockStream + payload into a working encrypted `.vlt` round-trip. The
  **C18 "`strings` reveals nothing" property is now verified end-to-end**; body tamper → `BodyAuth`,
  wrong password → ambiguous `HeaderAuth`. (C19 inner-stream pass deferred; outer AEAD secures at
  rest.) 65 unit tests total; fmt + clippy clean.
- **`keys.txt` migration MVP — end to end.** A lenient importer in `blindkey-core`
  ([`import::parse_raw`](crates/blindkey-core/src/import.rs), UC-17): splits a messy file on blank
  lines / `---`, skips `#` comments, classifies each line as secret (provider prefix or Shannon
  entropy) vs label, and builds `Entry` values — shared by the CLI and the future desktop app. Plus
  a working **CLI** (`blindkey init` / `import --format raw` / `ls [--search]` / `get [--stdout]`):
  no-echo password prompt (`rpassword`, no secrets on argv — C29), atomic `0600` file writes,
  masked import review (C27), clipboard delivery via the OS tool over stdin (C27), terminal output
  sanitization (C30). A synthetic [`samples/keys.txt`](samples/keys.txt) fixture exercises it.
  Verified end-to-end on a real file: 9 messy entries imported, searchable, retrievable, and the
  encrypted `.vlt` leaks neither titles nor secrets (C18).
- **Clipboard auto-clear (C13 / UC-04).** `blindkey get` spawns a **detached holder** that wipes the
  clipboard after `--timeout` seconds (default 30) — but only if it still holds the delivered secret
  (clears-iff-unchanged, so it won't erase something you copied since). The secret reaches the holder
  over an inherited stdin pipe, never argv or environment (C29). Verified live on macOS.
- **`blindkey gen` (C26)** — CSPRNG password generator in `blindkey-core` (`gen::password`) using
  **rejection sampling** (no modulo bias): `--charset alnum|ascii`, `--length 8..256`, with the
  entropy in bits reported. Lets you rotate the weak passwords an import surfaces. (The diceware
  `words` mode is pending the bundled EFF wordlist.)
- **Entry management — `blindkey add` / `edit` / `rm`.** Completes the daily-use manager: `add NAME`
  (interactive; **Enter at the password prompt generates a strong one**), `edit NAME` (per-field,
  Enter keeps the current value, optional password rotation), `rm NAME` (confirm on a TTY). The core
  gains `Blindkey::entry_mut` and `Blindkey::remove`. You can now rotate a weak imported password in place.
- **CLI integration test + KDF-cost flags.** [`crates/blindkey-cli/tests/cli.rs`](crates/blindkey-cli/tests/cli.rs)
  drives the real binary end-to-end (init → import the sample → ls → get → wrong-password → rm → gen)
  and asserts the encrypted file leaks neither secrets nor titles (C18). `init` gains hidden
  `--kdf-m-cost/-t-cost/-p-cost` flags (advanced) so tests and slower machines can tune Argon2id.
- **`blindkey-tui` — the first app shell (UC-18).** A **ratatui** terminal UI over `blindkey-core`:
  unlock → **type-to-search** → `↑/↓` select → **Enter copies the secret to the clipboard**
  (model-blind, auto-clears via a background thread, clears-iff-unchanged), `Esc` to quit. Runs on
  the **alternate screen** so nothing a secret touches reaches terminal scrollback, and the secret
  is **never rendered** — only titles. Pure-Rust shell; all secret-handling stays in the core. This
  is the first "managed via the app" surface; egui/SwiftUI follow over the same core.
- **Memory hardening (C12 + C25).** New isolated-`unsafe` crate **`blindkey-sys`** — the *one* place
  `unsafe` lives (every other crate stays `#![forbid(unsafe_code)]`) — wraps `setrlimit`/`mlock`/
  `munlock` behind a safe, best-effort API. `blindkey-core::memory` now provides `harden_process()`
  (disables core dumps at startup, wired into the CLI and TUI — so a crash can't dump secrets to a
  core file), `ct_eq` (constant-time comparison, C25), and a `PageLock` guard that mlocks the
  transient decrypted-payload buffer off swap during open/save (C12, graceful degradation — warns
  and continues if locking is unavailable). *(C19's in-memory inner-stream protection — keeping
  Protected fields ChaCha20-encrypted in RAM until accessed — remains a scoped follow-up.)*
- **Weak-KDF warning + `blindkey upgrade-kdf` (C2).** Opening a vault whose Argon2id cost is below the
  recommended floor now prints a warning suggesting an upgrade (centralized in a shared `open_vault`
  helper). `blindkey upgrade-kdf [--kdf-m-cost/-t-cost/-p-cost]` re-wraps the password stanza under
  stronger parameters and does a full body-writing save (version bump per G0.3); the data key and
  salt are unchanged, so entries stay intact. Core gains `Blindkey::kdf_strength` and `Blindkey::change_kdf`.
- **`blindkey-gui` — the desktop window app (UC-18 P2).** A pure-Rust **egui/eframe** GUI over
  `blindkey-core`: a create/unlock screen, **drag-and-drop (or pick) a `keys.txt`** with a masked
  review dialog before import, **type-to-search**, a detail pane that shows the password **shadowed**
  with one-click **Copy** (model-blind — the secret is never rendered; clipboard auto-clears after
  30 s, clears-iff-unchanged — C13/C27), a **Reveal** toggle, and **Add / Edit / change-password /
  Delete** with an in-app strong-password generator. Persists through the same atomic `0600` save as
  the CLI; secrets stay in the core; the in-memory password buffer is zeroized on drop.
  [`scripts/bundle-macos.sh`](scripts/bundle-macos.sh) wraps the release binary in a double-clickable
  `Blindkey.app`. Run with `cargo run -p blindkey-gui` (or `open target/Blindkey.app`).
- **Inner-stream encryption of Protected fields — at rest AND in memory (C19, complete).** New
  [`format::inner_stream`](crates/blindkey-core/src/format/inner_stream.rs): every Protected field
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
  [`rollback`](crates/blindkey-core/src/rollback/mod.rs): an 8-byte little-endian **local anchor** kept
  *outside* the synced folder (`$XDG_DATA_HOME`/`~/Library/Application Support`/`%LOCALAPPDATA%` →
  `vault/<vault_id>.state`), advanced monotonically (`max`) under an advisory **flock** (new
  `blindkey-sys::flock_exclusive`) via atomic temp+rename. The CLI checks it on every open and advances
  it on every save: a regression **warns + prompts** on a TTY (default abort) and **exits 2** with no
  prompt non-interactively; `--allow-rollback` proceeds (anchor not lowered) and `--expect-min-version
  N` pins a floor for a freshly provisioned machine (trust-on-first-use mitigation). The desktop GUI
  shows a rollback warning banner and advances the anchor on open/save. New end-to-end guide
  [docs/guides/sync-to-untrusted-storage.md](docs/guides/sync-to-untrusted-storage.md). 6 new tests
  (core anchor unit tests + a CLI integration test covering regression→exit 2, `--allow-rollback`,
  TOFU, and `--expect-min-version`). `Blindkey::vault_id()` added.
- **Optional Padmé size-padding (UC-07 §3.2).** New [`pad`](crates/blindkey-core/src/pad.rs): a single
  encrypted blob still leaks its *length* (≈ entry count) to a backend; turning padding on rounds the
  plaintext payload up to a **Padmé** bucket (`⌊log₂log₂L⌋+1` significant length bits → `O(log log L)`
  leakage at `≤ ~12 %` overhead). Padding is appended **inside** the AEAD (after the `END` marker the
  parser already ignores), so it's encrypted, authenticated, and invisible. The policy is **sticky**
  (persisted in the inner header, default off) and toggled with **`blindkey pad on|off`** or the desktop
  app's **"Pad size"** checkbox; `Blindkey::padding()`/`set_padding()` added. 6 new tests (Padmé bucket
  math + bound, sticky round-trip, CLI toggle).
- **`blindkey tune` (C22).** New [`crypto::tune`](crates/blindkey-core/src/crypto/tune.rs): benchmarks
  Argon2id on the current machine and recommends `m`/`t`/`p` targeting the ~300 ms interactive-unlock
  budget — it probes at a baseline memory cost, linear-extrapolates `m` (Argon2 time is ~linear in
  `m`), clamps into the policy floor/ceiling, and re-measures so the reported time is real. Prints the
  recommendation to stdout (scriptable) with an `upgrade-kdf` apply hint. Unlocking commands now also
  print a `Deriving key (Argon2id)…` progress line so a slow unlock doesn't look hung (C22). 2 new
  tests.
- **Diceware passphrases (C26).** `blindkey gen --words N` now produces a CSPRNG passphrase (unbiased
  rejection sampling over the word list, joined by `-`), and the desktop app's editor gains a
  **"🔑 Passphrase"** button. Ships a verifiable **built-in 256-word list**
  ([`wordlist`](crates/blindkey-core/src/wordlist.rs), exactly `2^8` → 8 bits/word, guarded by a
  no-duplicates/format test) for zero-setup use; `--wordlist <file>` accepts a user-supplied list
  (e.g. the EFF large list, ~12.9 bits/word — plain or `dice⇥word` lines). Entropy is reported.
  `gen::passphrase()`/`passphrase_entropy_bits()` added. 4 new tests. *(The full EFF list isn't
  bundled — it can't be reproduced offline without fabricating it; download it and pass `--wordlist`.)*
- **2FA / TOTP codes (RFC 6238).** Blindkey can now stand in for an authenticator app. New
  [`totp`](crates/blindkey-core/src/totp.rs) generates the current 6-digit code from an entry's
  `otp_secret` (HMAC-SHA-1, 30 s, base32 secret — the de-facto standard; verified against the **RFC
  6238 test vectors**). `blindkey otp <name>` copies the code (auto-clears when it rolls over) or
  `--stdout` prints it; `add`/`edit` prompt for an optional 2FA secret. The desktop app shows a
  **live code with a seconds-left countdown** in the entry detail (it refreshes on the 1 s repaint
  timer) and a "2FA secret" field in the editor. Adds the audited `sha1` crate (used **only** for
  TOTP, never at rest). Also made the CLI master-password prompt read a single line so `add`/`edit`
  are scriptable. 5 new tests.
- **Master-password strength gate (root-of-trust hardening).** A weak master password defeats every
  other layer (it faces offline brute force), so `blindkey init` now **estimates its strength** and, if
  it's below ~60 bits (`audit::WEAK_MASTER_BITS`), warns loudly and — on a terminal — requires
  confirmation; `--allow-weak-password` skips it for scripted setup (non-interactive init warns but
  proceeds). The **desktop create screen** enforces the same gate: a weak password is refused unless
  you tick **"⚠ Create anyway"** below the live strength meter. Shared estimator
  (`audit::password_entropy_bits`) keeps CLI and GUI consistent.
- **Reproducible-build verification (C24/C34).** [`scripts/reproducible-build.sh`](scripts/reproducible-build.sh)
  builds the `blindkey` CLI binary **twice with deterministic flags** (`SOURCE_DATE_EPOCH`,
  `--remap-path-prefix`, `CARGO_INCREMENTAL=0`, `--locked`; the release profile already pins
  `codegen-units=1` + `strip`) and asserts the two are **byte-for-byte identical** — so anyone can
  rebuild from source and confirm a published binary matches it (defeating a tampered-binary
  supply-chain attack). Verified reproducible locally; a CI job enforces it on every push.
- **`unsafe`-isolation CI guard (C25).** [`scripts/check-unsafe-isolation.sh`](scripts/check-unsafe-isolation.sh)
  (+ a CI job) asserts that **only `blindkey-sys` contains `unsafe`** and every other crate declares
  `#![forbid(unsafe_code)]` — belt-and-braces that pins the attribute in place so it can't be
  silently removed.
- **Hostile-file robustness hardening (UC-10 / C30).** A malicious `.vlt` from an untrusted sync
  backend is the #1 untrusted-input path, so the guarantee that *parsing it can't be exploited* is
  now property-tested in the normal suite ([`tests/robustness.rs`](crates/blindkey-core/tests/robustness.rs)):
  over thousands of random inputs, every public parser (`Header`/`Payload`/`stanza`/`Blindkey::open`)
  is **panic-free on arbitrary bytes**, a real vault always **round-trips and leaks no plaintext**
  (C18), a wrong password always fails, and a **single-byte flip anywhere is always detected**
  (C9/C10/C1 — never decrypts to something else). Also extended the continuous fuzzer with a full
  **`vault_open`** target (plus the previously-unlisted `payload_parse`) and broadened its path
  triggers to the whole open path.
- **Password-health audit (`blindkey audit` + GUI 🩺).** New offline [`audit`](crates/blindkey-core/src/audit.rs)
  flags **weak** (low-entropy), **reused** (same password across entries), **stale** (not changed in
  over a year), and **expiring/expired** credentials — entirely locally (no network, C23), reporting
  entries **by title only, never by secret**. Reuse detection groups by a **salted, per-call,
  transient** SHA-256 (so the digests aren't a plain hash of the password). `blindkey audit` prints the
  report; the desktop app adds a **🩺 Audit** button with a results panel. 3 new tests.
- **Keyfile 2FA — hardware-free second factor (UC-09, CLI).** `blindkey enroll keyfile <PATH>` turns
  the master password into a **required-both** second factor with no hardware: the data key is
  re-wrapped under `HKDF(Argon2id(password) ‖ SHA-256(keyfile))` in a composite `PW_KEYFILE` stanza,
  so the password **alone no longer unlocks** — the keyfile's bytes are needed too. Enrollment
  generates a fresh 32-byte random keyfile at `<PATH>` (mode `0600`) if the file doesn't exist, or
  adopts an existing file's bytes; unlock with `vault --keyfile <PATH> <cmd>`. Same anti-lockout as
  the hardware path: a one-time **recovery code** opens via `vault --recovery <cmd>` if the keyfile is
  lost. Keep the keyfile on a **separate device** (USB stick) from the vault — co-locating them
  defeats the factor. Reuses the composite-stanza machinery, so it is **fully unit- and
  integration-tested without any hardware** (the gap the YubiKey path leaves for CI). New
  `Blindkey::open_keyfile` / `enroll_keyfile_2fa` / `requires_keyfile`; `--keyfile` global CLI flag.
- **YubiKey 2FA — hardware second factor (UC-09, CLI).** `blindkey enroll yubikey` turns the master
  password into a **required-both** second factor: the data key is re-wrapped under
  `HKDF(Argon2id(password) ‖ YubiKey-HMAC-SHA1-response)` in a composite `PW_YUBIKEY` stanza, so the
  password **alone no longer unlocks** — the key must be tapped too. Anti-lockout: enrollment prints
  a one-time high-entropy **recovery code** (a separate stanza); `vault --recovery <cmd>` unlocks
  without the key if it's lost. The product owns enrollment (it programs the key's slot 2 via
  `ykman` and computes responses — no manual setup), driven as a subprocess like the clipboard tools
  (so no FFI, no `unsafe`, no new build deps; needs `ykman` at runtime only when you opt in). A fixed
  per-enrollment challenge means you tap on **unlock only**, not on every save. Works on older
  YubiKeys (4/NEO) that lack FIDO2. New `blindkey-hardware::yubikey`, `Blindkey::open_2fa` /
  `enroll_yubikey_2fa` / `requires_yubikey`, `Error::Hardware`. Fully unit-tested with a mock key
  response (the physical tap is verified manually). *(Desktop-app enrollment + the UC-09 AND-model
  intent amendment land next.)*
- **Cross-desktop CI (works on any desktop).** The build+test matrix now covers **Linux, macOS,
  and Windows including the egui GUI**: the Linux jobs install the windowing/dialog system libs
  (`libgtk-3-dev`, `libxcb-*`, `libxkbcommon-dev`), and the CLI integration tests sandbox the
  rollback anchor on Windows too (`LOCALAPPDATA`). Repaired the jobs the 1.82→1.96 toolchain bump
  broke: dropped the obsolete `MSRV 1.82` check (the lockfile now needs Rust-2024 deps) and scoped
  the static-musl build to `blindkey-cli` (the GUI links native windowing libraries and isn't a musl
  target).
- **Keyboard-first GUI + polish.** The desktop app is now fully drivable from the keyboard:
  **↑/↓** move the selection and **Enter copies** the selected password (type-to-search → Enter,
  like the TUI). The create screen shows a live **password-strength meter** (entropy estimate +
  weak/fair/good/strong, color-coded) so users don't pick a weak master password. The status bar
  surfaces the shortcuts.
- **Auto-lock in the desktop app (UC-06 / S-10).** The GUI no longer stays unlocked forever: it
  clears the decrypted vault from memory and returns to the unlock screen after an **idle timeout**
  (default 5 min, chosen from a top-bar **Auto-lock** menu: 1m/5m/15m/30m/Never, persisted to
  `~/.blindkey/config`) and **immediately when the window is minimized**. The idle timer keeps ticking
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
  (cargo ≥ 1.85). The security core (`blindkey-core`/`blindkey-cli`/`blindkey-tui`/`blindkey-sys`) remains
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
- `C2` (G0.3): `blindkey upgrade-kdf` is a full body-writing save (version bump, fresh
  `master_seed`/`nonce_prefix`, body re-encrypted) — a sync backend can no longer serve the
  pre-upgrade weak-KDF file undetected.
- `C13` (G0.6): the clipboard clear-timer is a **detached helper process** (a thread cannot
  outlive a one-shot CLI) with clear-iff-unchanged semantics and constant-time comparison.
- `C5` (G0.7): YubiKey challenge stored per-stanza (`extra = {slot, challenge}`), refreshed on
  device-present body-writing saves; graceful staleness with a loud warning is the default,
  `yubikey_strict` / `--strict-yubikey` opts into abort-on-absent (supersedes the v1.3.0
  strict-abort wording; resolves the C5↔UC-09 contradiction).
- `C21`/`C27` (G0.8): frozen exit-code map 0–9 (rollback keeps 2; clap usage moves to 8);
  new `blindkey stanzas list|add|remove` commands; headless `blindkey get` without `--stdout`
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
- Blindkey is **functional pre-1.0** — CLI and desktop app work; keep your own backup of secrets until 1.0.

[Unreleased]: https://github.com/leocelis/blindkey/compare/v1.0.0...main
[1.0.0]: https://github.com/leocelis/blindkey/compare/v0.1.0-alpha.3...v1.0.0
[0.1.0-alpha.3]: https://github.com/leocelis/blindkey/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/leocelis/blindkey/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/leocelis/blindkey/releases/tag/v0.1.0-alpha.1
