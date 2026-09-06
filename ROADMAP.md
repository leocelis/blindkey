# Roadmap

No dates, no timeline — **dependency order only**. Two kinds of work:

- **Critical path (CP)** — strictly ordered; each node blocks the next. This is the spine of v1.0.
- **Sidequests (S)** — parallel-safe utilities. Each lists what unblocks it; once unblocked, it can
  be built independently of the critical path without touching the same files.

This split exists so two maintainers (and their agents) can work **in parallel without collisions**
— see [`cowork.yaml`](cowork.yaml) for the working protocol and
[`docs/specs/`](docs/specs/README.md) for the design of every item below. Legacy milestone tags
(M2…M10) are kept in parentheses because the PRD and specs reference them.

Done so far: research & intent (M0 ✅), OSS scaffolding (M1 ✅), PRD + 16 tech specs ✅,
spec-hardening Part 1 — intent v1.3.0: `C28`–`C34` promoted, KDF ceiling + Unicode NFC folded
into `C2`, spec self-contradictions resolved ✅, Gate 0 close-out — intent v1.4.0: G0.2/G0.3/
G0.6/G0.7/G0.8 amended (HMAC re-keying, full-save KDF upgrades, clipboard helper, YubiKey
staleness, exit codes) ✅.

---

## v1.0 release status *(cross-check 2026-06-25)*

**Is Blindkey v1 ready?** **Yes — `1.0.0` release prepared** (2026-06-26): CP-7 green, format v1 frozen,
CP-5/CP-6 closed. Maintainer: signed tag + GitHub Release per [RELEASE.md](docs/RELEASE.md).

| Gate | Status | Notes |
|------|--------|-------|
| CP-1 · format core | ✅ | Parser/fuzz/TLV model shipped |
| CP-2 · crypto core | ✅ | STREAM, KDF, envelope |
| CP-3 · memory hardening | ✅ | mlock, zeroize, RLIMIT_CORE |
| CP-4 · read/write API | ✅ | Atomic save, rollback anchor, GUI/TUI on core |
| CP-5 · CLI core loop | ✅ | stanzas + exit 7 (C21/C27) |
| CP-6 · distribution | ✅ | **`v1.0.0`** (repo prep) + prior **`v0.1.0-alpha.3`** release |
| CP-7 · quality gate | ✅ | `just audit-ready` + CI on push |

**To ship `1.0.0` (per [RELEASE.md](docs/RELEASE.md)):**

1. ~~**Format freeze**~~ — ✅ **Done 2026-06-26** ([ADR-0005](docs/adr/0005-format-v1-freeze.md)).
2. ~~**Repo prep**~~ — ✅ workspace `1.0.0`, CHANGELOG, post-1.0 copy (2026-06-26). **Requires release-signing access** (see [docs/RELEASE.md](docs/RELEASE.md)): signed tag + GitHub Release.
3. ~~Gate 0 intent amendments~~ — ✅ (ADR-0003, ADR-0004, intent v1.4.0).

**Explicitly not required for v1.0:** third-party audit ([THIRD_PARTY_AUDIT.md](docs/THIRD_PARTY_AUDIT.md)), live libfido2/TPM FFI (S-8a/S-8c, optional), SwiftUI shell (post-v1).

---

## Gate 0 — Intent decisions before any crypto/format code

Spec-writing surfaced issues that must be resolved as **intent amendments first** (both
maintainers, per [GOVERNANCE](GOVERNANCE.md) two-maintainer rule). Small, but they gate everything:

| # | Decision | Found in | Proposed resolution |
|---|----------|----------|---------------------|
| G0.1 | **C1 keystream reuse across re-saves** — same data key + deterministic nonces ⇒ XOR of two saved versions leaks plaintext diffs | [UC-07 §7](docs/specs/UC-07-untrusted-storage-sync.md) | ✅ Amended + verified · ADR-0003 Accepted |
| G0.2 | **C9/C10 HMAC key source** — header/block HMACs keyed from Argon2id `master_key`, which a hardware-only unlock never derives; corollary: rotating `master_seed` on a header-only save would orphan the stored block HMACs | [UC-10 §7](docs/specs/UC-10-hostile-file-parsing.md) | ✅ Amended + verified · ADR-0004 Accepted |
| G0.3 | **`upgrade-kdf` rollback blind spot** — header-only ops don't bump `vault_version`; backend can serve the weaker-KDF file undetected | [UC-11 §7](docs/specs/UC-11-kdf-calibration.md) | ✅ Amended + verified |
| G0.4 | **Promote C28+ candidates** from the [gaps doc](research/security_coverage_gaps.md) | [gaps doc](research/security_coverage_gaps.md) | ✅ Done · CONSTRAINT_INDEX 60/60 |
| G0.5 | **SLSA provenance subjects** — matrix job outputs overwrote each other | [UC-13 §3.2](docs/specs/UC-13-verifiable-releases.md) | ✅ Fixed — `reproducible-build.sh` canonical |
| G0.6 | **C13 thread → helper process** — clear-timer "thread" can't outlive a one-shot CLI | [UC-04 §7](docs/specs/UC-04-model-blind-retrieval.md) | ✅ Amended + verified |
| G0.7 | **C5 strict-abort vs UC-09 graceful staleness** — intent (v1.3.0) mandated abort-on-absent-YubiKey; UC-09 specced stored-challenge graceful staleness | [UC-09 §7](docs/specs/UC-09-hardware-factors.md) | ✅ Amended + verified |
| G0.8 | **Stable exit codes + headless clipboard rule + `blindkey stanzas`** — specs disagreed on exit codes (UC-04/05/06/08); no enrollment command existed; headless `get` behavior was spec-only | [UC-10 §7](docs/specs/UC-10-hostile-file-parsing.md), [UC-04 §7](docs/specs/UC-04-model-blind-retrieval.md) | ✅ Amended + verified |

---

## Critical path

Each node lists its constraints, spec, and **the interface it freezes** — the contract the other
lane can build against from that point on.

### CP-1 · File format core *(M2)* ✅
`C7 C8 C9 C10 C30` · specs [UC-03](docs/specs/UC-03-store-secret.md), [UC-10](docs/specs/UC-10-hostile-file-parsing.md)
- Header parse/serialize (magic, version, KDF params, stanza records; bounded reads, length caps)
- Bounded **TLV entry/payload model** (tag bit 0x8000 = Protected)
- HmacBlockStream framing; 10-step verification pipeline order
- Fuzz targets live: `header_parse`, `stanza_parse`, `block_stream`
- **Freezes:** on-disk byte layout · `Header`/`Entry`/`Stanza` types · `blindkey-core::format` API

### CP-2 · Cryptographic core *(M3)* ✅
`C1 C2 C3 C4 C5 C6` (as amended by Gate 0) · specs [UC-01](docs/specs/UC-01-install-and-init.md), [UC-11](docs/specs/UC-11-kdf-calibration.md)
- Argon2id (floor **and** ceiling) → HKDF; XChaCha20-Poly1305 STREAM (64 KiB chunks)
- Data-key generation; password-stanza wrap/unwrap; envelope open (any-of-N)
- **Freezes:** `blindkey-core::crypto` API · `Blindkey::open`/`Blindkey::save` signatures

### CP-3 · Memory & runtime hardening *(M4)* ✅
`C11 C12 C25` · spec [UC-14](docs/specs/UC-14-runtime-hardening.md)
- Type layer (zeroize/secrecy, Debug redaction) · page layer (mlock, `memfd_secret` probe)
- Process layer (RLIMIT_CORE=0, dumpable-off) · constant-time comparisons table
- **Freezes:** `blindkey-core::memory` secret types used by every later component

### CP-4 · Blindkey read/write, rollback, atomic saves *(M5)* ✅
`C4 C16 C17 C32` · specs [UC-07](docs/specs/UC-07-untrusted-storage-sync.md), [UC-01 §atomic](docs/specs/UC-01-install-and-init.md)
- Open pipeline wired end-to-end; atomic temp+rename+fsync saves; file locking
- Rollback anchor (per-`vault_id` u64, LocalAppData/XDG, flock + re-read) · `--allow-rollback` · exit 2
- **API must be UI-agnostic *and* FFI-ready** ([UC-18 §3.2](docs/specs/UC-18-native-ui.md)): returns
  structured data + secret-handles, performs delivery in-core, never prints. This is the only
  UI-related work that lands in v1 — it unblocks every future shell (TUI/egui/SwiftUI) on one core.
- **Freezes:** the full `blindkey-core` public API (v0 API freeze — the big sync point)

### CP-5 · CLI core loop *(M6)* ✅
`C20 C21 C22 C27` · specs [UC-01](docs/specs/UC-01-install-and-init.md), [UC-04](docs/specs/UC-04-model-blind-retrieval.md), [UC-06](docs/specs/UC-06-entry-management.md)
- Shipped: full surface including `blindkey stanzas list/add/remove`, headless **exit 7** (C27)
- Non-TTY matrix wired; no secrets on argv
- **Freezes:** CLI surface & exit codes (scripts can rely on them)

### CP-6 · Distribution & trust *(M8)* ✅
`C3 C23 C24 C34` · spec [UC-13](docs/specs/UC-13-verifiable-releases.md)
- Maintainer-local releases: reproducible build script, SHA-256 checksums, GitHub Releases
- Optional GPG-signed tags; cosign/SLSA deferred
- crates.io manual publish ([docs/CRATES_IO_TRUSTED_PUBLISHING.md](docs/CRATES_IO_TRUSTED_PUBLISHING.md))

### CP-7 · Full IVD sweep → release quality gate ✅ *(M10)*
- **Sweep complete 2026-06-22:** 60 PASS · 0 NEEDS_REVIEW — [`docs/CONSTRAINT_INDEX.md`](docs/CONSTRAINT_INDEX.md)
- `just audit-ready` green (workspace tests + fmt + release benches + clippy)
- **`1.0.0` tag:** CP-5 gaps closed + format freeze declared + first CP-6 release run ([RELEASE.md](docs/RELEASE.md))

---

## Sidequests (parallel-safe)

| ID | Sidequest | Spec | Unblocked by | Notes |
|----|-----------|------|--------------|-------|
| S-1 | 🟡 **Clipboard delivery crate** (`blindkey-clip`: C13/C33 concealment + fallback) | [UC-04](docs/specs/UC-04-model-blind-retrieval.md) | nothing | Core shipped; UC-04 detached X11 selection-owner helper still optional polish |
| S-2 | **`blindkey gen`** — rejection sampling, charsets, EFF wordlist embedding, chi-square test harness | [UC-02](docs/specs/UC-02-csprng-generation.md) | nothing | Pure function + CLI glue later |
| S-3 | **zxcvbn entropy warning** (60-bit floor, warn-don't-block) | [UC-02](docs/specs/UC-02-csprng-generation.md) | nothing | Wraps the zxcvbn crate |
| S-4 | ✅ **`blindkey tune`** — Argon2id benchmark + recommend m/t/p (~300 ms) | [UC-11](docs/specs/UC-11-kdf-calibration.md) | CP-2 (kdf fn) | **DONE** (C22): probe + linear-extrapolate `m`, clamp to policy, re-measure; unlock progress line |
| S-5 | **Import parsers** — txt, JSON, Bitwarden JSON, KeePassXC CSV (+ M9: kdbx via `keepass`, pass via gpg subprocess) | [UC-12](docs/specs/UC-12-migration-import.md) | CP-1 (Entry model) | Each format = one PR; fuzz each parser |
| S-6 | ✅ **`blindkey export` + `--stdout` plumbing** — JSON export, warnings, non-TTY matrix, unlock channels | [UC-05](docs/specs/UC-05-script-and-ci-output.md) | CP-5 partially | Done |
| S-7 | **`blindkey merge`** — UUID union, `modified_at` tiebreak, masked diffs (8-bullet Protected) | [UC-08](docs/specs/UC-08-conflict-merge.md) | CP-4 | Needs read/write API |
| S-8a | **FIDO2 stanza** (libfido2 raw CTAP2) | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 (stanza API) | Optional for v1 (M7) |
| S-8b | 🟡 **YubiKey CR stanza** | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | **CLI DONE** (`blindkey enroll yubikey`): composite **AND** 2FA (password + key both required) + one-time recovery code; HMAC-SHA1 slot-2 via `ykman` subprocess (no FFI). Pending: GUI enrollment + the UC-09 AND-model intent amendment |
| S-8c | **TPM stanza** (PCR 7, re-enroll flow) | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | Optional |
| S-8d | **macOS SE / Windows DPAPI stanzas** | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | Optional |
| S-9 | **Disclosure ops** — publish age intake key, triage runbook, severity modifier table | [UC-15](docs/specs/UC-15-vulnerability-reporting.md) | nothing | Process work, zero code |
| S-10 | 🟡 **Auto-lock & config** — `~/.vault.toml` schema, idle timer | [UC-06](docs/specs/UC-06-entry-management.md) | CP-3 | **GUI idle auto-lock + lock-on-minimize DONE** (configurable timeout in `~/.blindkey/config`). Pending: full `~/.vault.toml` + CLI-session auto-lock |
| S-11 | **Fuzz corpus & CI fuzz budget** — seed corpora from real vault files, OSS-Fuzz application | [UC-10](docs/specs/UC-10-hostile-file-parsing.md) | CP-1 | Grows with every parser |
| S-12 | ✅ **Padmé padding** (PURBs) — optional size-leak reduction, **default off** | [UC-07 §3.2](docs/specs/UC-07-untrusted-storage-sync.md) · [guide](docs/guides/size-padding-padme.md) | CP-4 | **DONE**; v2 default-on deferred |
| S-13 | 🟡 **Agent interface** — handle broker, `blindkey agent`, OS approval gate | [UC-16](docs/specs/UC-16-agent-interface-future.md) | post-v1 MCP | **SCAFFOLD** (`blindkey-agent` + `blindkey agent`); status-only IPC (C27) |
| S-24 | ✅ **MCP server** — `blindkey mcp` (JSON-RPC/stdio) exposes the broker to Claude Code/Cursor as status-only tools | [UC-24](docs/specs/UC-24-mcp-broker.md) | S-13 | **DONE** — protocol + `list_handles` (metadata) + `use_handle` (status-only) shipped; headless delivery via companion-broker delegation (`BrokerProxyExecutor`), verified end-to-end. Remaining: live verification against a specific MCP client (HITL) |
| S-14 | **User guide & website docs** | all specs | CP-5 | Quickstart, sync guide, threat-model-for-humans |
| S-15 | ✅ **Quick-capture `import --format raw`** — lenient parser, entropy/prefix classifier, masked interactive review | [UC-17](docs/specs/UC-17-quick-capture-raw-import.md) | CP-1 (Entry model) | Shipped |
| S-16 | ✅ **`ratatui` TUI** — search → deliver loop, alt-screen reveal hygiene | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API | **DONE** (`blindkey-tui`); first UI, pure Rust, C20-exact |
| S-17 | ✅ **`egui` window** — pure-Rust GUI shell | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API | **DONE** (`blindkey-gui`): create/unlock, drop-a-`keys.txt` import, search, shadowed copy, edit/change/delete; `scripts/bundle-macos.sh` → `Blindkey.app`. Needed the 1.82→1.96 toolchain bump |
| S-19 | ✅ **Desktop GUI hardening** — glow pin, search cache, list virtualization, C40–C45 | [UC-20](docs/specs/UC-20-desktop-gui-hardening.md) | S-17 | Perf + presentation security on weak hardware |
| S-20 | ✅ **Desktop gaps closure** — reveal timeout, keyfile GUI, pre-1.0 banner, C46–C54 | [UC-21](docs/specs/UC-21-desktop-gaps-closure.md) | S-19 | Session hygiene + 2FA GUI parity |
| S-21 | ✅ **Fleet deploy & quality gate** — env paths, release benches, C55–C60 | [UC-22](docs/specs/UC-22-enterprise-readiness.md) | S-20 | CP-7 automated gate |
| S-18 | **SwiftUI macOS shell via `uniffi`** — Touch ID + Secure Enclave (C5), native menus | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API + S-8d (keychain stanza) | **post-v1**; needs the SEP-API spike + ADR |
| S-22 | ✅ **Sealed file storage** — `blindkey seal/open/peek`: any file/folder → one `.vltf` blob for untrusted clouds; zero plaintext metadata, Padmé default-on, streaming bounded-memory, fail-closed extraction | [UC-23](docs/specs/UC-23-sealed-file-storage.md) | v1.0 core + C61–C66 | **Shipped** (July 2026). CLI + GUI/TUI + stanza parity on `.vltf`. |
| S-23 | ✅ **Local encrypted volume (live mount)** — PGP Disk / VeraCrypt-class `.vltd` workspace; MSV AEAD blocks + FUSE; CLI + macOS GUI; **not** cloud live-sync | [UC-25](docs/specs/UC-25-local-encrypted-volume.md) | C67–C74 | **Shipped** (July 2026): `blindkey-core::volume` (AEAD blocks, Kcom, HMAC-SHA-256 Merkle, local anchor, Padmé) + `blindkey volume` CLI verbs + Linux `blindkey-fuse` + GUI Create/Mount/Eject + fuzz + joint-satisfaction; C67–C74 PASS. **Remaining:** macOS FUSE provider (macFUSE/Fuse-T packaging; stub today) + harnessed 4K/sequential benches (honest: userspace FUSE loses to dm-crypt). |
| S-25 | ✅ **Desktop UI IA & usability** — fonts/legibility gate, Credentials \| Workspace modes, mount honesty, WCAG AA chrome | [UC-26](docs/specs/UC-26-desktop-ui-information-architecture.md) | S-17 + S-20 + S-23 | **Shipped** (2026-07-29): `default_fonts` + AA theme; `GuiMode` Credentials\|Workspace; Seal secondary; mount honesty (C79); Advanced progressive disclosure; first-run/next-beat; C75–C81 PASS via `uc26_constraints.rs`. *(Note: S-24 remains MCP broker — do not renumber.)* |
| S-26 | ✅ **Desktop UI visual craft** — form card, Spacing tokens, accent primary, trust-copy hygiene, Settings overflow | [UC-27](docs/specs/UC-27-desktop-ui-visual-craft.md) | S-25 | **Shipped** (2026-07-29): `apply_craft_style` + `FORM_WIDTH` card; accent Create/Unlock/Add; Settings window; Workspace/Seal accents; C82–C87 PASS via `uc27_constraints.rs`. *(Note: S-24 = MCP; S-25 = UC-26.)* |
| S-27 | ✅ **Desktop UI component kit & surfaces** — `surface_card`, quiet/text buttons, Settings boxed-list rows, vertical balance, list/search contracts | [UC-28](docs/specs/UC-28-desktop-ui-component-kit.md) | S-26 | **Shipped** (2026-07-30): UC-28 Implemented v1.0; intent G20 C88–C93 PASS (`uc28_constraints.rs`). No locked-state rail; no toolkit swap. *(Note: S-24 = MCP — do not renumber.)* |
| S-28 | ✅ **Desktop UI contrast, typography & polarity** — force Dark theme, WCAG AA tokens, NIST type scale, white primary ink | [UC-29](docs/specs/UC-29-desktop-ui-contrast-typography.md) | S-27 | **Shipped** (2026-07-30): UC-29 Implemented v1.0; intent G21 C94–C98 PASS (`uc29_constraints.rs`). Fixes light-canvas / dark-card polarity collision. *(Note: S-24 = MCP — do not renumber.)* |
| S-29 | ✅ **Volume working copy (Blindfolder)** — checkout `.vltd` from a sync folder to a local non-sync path, open that copy as a folder, atomic checkin; refuse live mount of the sync path (C73) | [UC-30](docs/specs/UC-30-volume-working-copy.md) · [ADR-0011](docs/adr/0011-volume-working-copy-checkout.md) | S-23 | **DONE** (2026-09-06): core+CLI+GUI Blindfolder + MaterializedMount + residuals. Optional macOS live FUSE: user macFUSE + `--features macos-fuse` (ADR-0010; no bundled Fuse-T). |

### S-25 delivery checklist (UC-26)

| Seg | Work | Status |
|-----|------|--------|
| A0 | `default_fonts` + AA `theme.rs` | ✅ |
| A1 | `GuiMode` + status chrome; Volume out of Credentials toolbar | ✅ |
| A2 | First-run / next-beat / About trust / show-hide / microcopy | ✅ |
| A3 | Workspace home + unlock honesty | ✅ |
| A4 | Advanced disclosure + confirm-match / cancel / closure | ✅ |
| A5 | `uc26_constraints.rs` T1–T12 | ✅ |
| A6 | Intent G18 C75–C81 + CONSTRAINT_INDEX | ✅ |

### S-26 delivery checklist (UC-27)

| Seg | Work | Status |
|-----|------|--------|
| B0 | Tokens + Spacing + field fill/stroke in `theme.rs` | ✅ |
| B1 | Locked unlock/create rewrite (CRAFT-01…06, 10, 13, 15) | ✅ |
| B2 | Unlocked Settings overflow + Add accent (CRAFT-07, 11, 14) | ✅ |
| B3 | Volume + Seal + Workspace home accent/width (CRAFT-08, 09, 12) | ✅ |
| B4 | `uc27_constraints.rs` + GUI suites + clippy | ✅ |
| B5 | Intent G19 C82–C87 + CONSTRAINT_INDEX + Implemented | ✅ |

### S-27 delivery checklist (UC-28)

| Seg | Work | Status |
|-----|------|--------|
| C0 | Tokens `AA_CARD_*` / radii / `ROW_HEIGHT_LIST` / `HEADER_HEIGHT` | ✅ |
| C1 | `surface_card` + locked wrap + vertical balance | ✅ |
| C2 | `quiet_button` / `text_button` + Cancel→Affirm + Esc/Return (main/volume/seal) | ✅ |
| C3 | Settings boxed-list rows | ✅ |
| C4 | Hover quiet + full-row list + `focus_search` + header quiet | ✅ |
| C5 | `uc28_constraints.rs` + suites + clippy | ✅ |
| C6 | Intent G20 C88–C93 + Implemented | ✅ |

### S-28 delivery checklist (UC-29)

| Seg | Work | Status |
|-----|------|--------|
| D0 | Research + measured WCAG/NIST ratios | ✅ |
| D1 | Force Dark + `*_of(Dark)` + type scale | ✅ |
| D2 | Token retune + white primary + muted captions | ✅ |
| D3 | `uc29_constraints.rs` + suites | ✅ |
| D4 | Intent G21 C94–C98 + docs | ✅ |

---

### S-23 delivery plan (UC-25)

Local encrypted workspace volume: create → mount → edit → umount. Sibling to shipped
[UC-23](docs/specs/UC-23-sealed-file-storage.md) sealed archives (cloud); this track is
**local-only** (no live RW + cloud sync). Spec: [UC-25 Accepted v0.5](docs/specs/UC-25-local-encrypted-volume.md).
Constraints: **C67–C74** (G17) in [`blindkey_intent.yaml`](blindkey_intent.yaml) **v1.9.1**
(FORWARD until ship). Research:
[encrypted_volume_mount_research.md](research/encrypted_volume_mount_research.md),
[encrypted_volume_maximum_security_research.md](research/encrypted_volume_maximum_security_research.md).

| Phase | Work | Done when |
|-------|------|-----------|
| **Gate-0** | Accept UC-25; ADR freeze magic `VLTD` / `.vltd`; confirm merkle (HMAC-SHA-256 rec) + mount crate vs feature | Spec **Accepted 2026-07-21**; magic **[ADR-0007](docs/adr/0007-volume-magic-vltd.md)**; remaining ADRs before A2+ |
| **A1–A4** | ✅ `blindkey-core::volume`: magic/kind → create/open/Kcom/dual header/Padmé → block store + virtual FS + Merkle + local anchor → fuzz + `uc25_joint_satisfaction` | **Done** — C67–C71, C74 core green; sealed `.vltf` regression (C61) still PASS |
| **B1–B2** | ✅ CLI `volume create\|mount\|umount\|resize\|status\|trust-anchor` + `peek` magic dispatch on `.vltd`; Linux FUSE via `blindkey-fuse` ([ADR-0009](docs/adr/0009-volume-mount-blindkey-fuse.md)) | **Done (Linux)** — verbs + adapter build-green; no network on mount path (C23/C72); mount smoke on Linux CI |
| **C1–C2** | macOS userspace provider (macFUSE FSKit / Fuse-T — [ADR-0010](docs/adr/0010-volume-macos-mount-matrix.md)); ✅ GUI Create/Mount/Eject + residual-risk banner + Seal CTA (thin shell over core) | GUI shell **done** (C72/C73 UX); macOS FUSE provider (non-stub) = remaining packaging lane |
| **D** | ✅ Docs (`FILE_FORMAT`, `CRYPTO`, `CLI`, `THREAT_MODEL`, `ARCHITECTURE`, `CONSTRAINT_INDEX`); benches note (honest FUSE vs dm-crypt, [UC-25 §12.1](docs/specs/UC-25-local-encrypted-volume.md)); C67–C74 → PASS | **Done** — spec → Implemented; harnessed 4K/sequential benches follow with the FUSE lane |

**Non-goals (v1):** VeraCrypt format compat; naked AES-XTS/XCB; cipher cascades; PD/ORAM;
GPL cryptsetup in core; `hdiutil` as crypto core; Windows mount (WinFsp later).

---

## Suggested parallel lanes

Per [CODEOWNERS](.github/CODEOWNERS), `blindkey-core` changes need the code owner's review; the split
below keeps review load natural. Lanes are a default, not a law — swap via the claim protocol in
[`cowork.yaml`](cowork.yaml).

- **Lane A (code owner):** Gate 0 amendments → CP-1 → CP-2 → CP-3 → CP-4 (the security boundary).
- **Lane B:** S-1, S-2, S-3, S-9 immediately (zero dependencies); then S-4/S-5 as CP-1/CP-2 freeze
  interfaces; then CP-5 CLI against the frozen core API; S-6/S-7/S-10 behind it.
- **Sync points:** ① Gate 0 amendments ✅ · ② CP-1 format freeze ✅ ([ADR-0005](docs/adr/0005-format-v1-freeze.md)) · ③ CP-4 core API freeze ✅ · ④ CP-7 gate ✅ · ⑤ **First signed tag** (CP-6 run).

---

## Hardening backlog (post-C60 — candidate constraints) *(M9)*

Remaining findings from [research/security_coverage_gaps.md](research/security_coverage_gaps.md),
each to land via its own ADR per [GOVERNANCE.md](GOVERNANCE.md) (they change the unlock/deletion
model or add process machinery, so they get the two-maintainer + ADR treatment):

- ptrace / `PR_SET_DUMPABLE` live-memory hardening (gap B3; partially designed in UC-14)
- crypto-shredding semantics + `blindkey rotate-data-key` (gap C2)
- recovery-code stanza for all-factors-lost (gap C3)
- `cargo-vet`, dependency budget (gap D2; SBOM itself ships in CP-6)
- post-quantum posture statement / hybrid-PQ wrap reservation (gap E1; S-12 padding is adjacent)

## Out of scope for v1

Hosted cloud sync · browser extension · team/org vaults · **native SwiftUI shell** · any LLM/AI agent inside the trust
boundary (see [blindkey_intent.yaml](blindkey_intent.yaml) `non_goals` and `C27`). Pure-Rust TUI/GUI shells are **shipped** (pre-1.0 beta).

## Bigger vision (post-1.0, under discussion)

Blindkey's audience protects more than passwords — files, `.env`s, code, database URLs, and the
secrets their AI tools touch. Expanding from "credential vault" to "developer secret vault"
(file/blob encryption, secret injection into running apps without exposing plaintext to an agent)
is the north star, scoped deliberately *after* the credential core is solid at 1.0.
S-13 (agent interface) and **S-22 (sealed file storage, [UC-23](docs/specs/UC-23-sealed-file-storage.md)
— shipped: research → PRD → forward constraints C61–C66)** are the first concrete steps in that
direction. **S-23 (local encrypted volume / live mount, [UC-25](docs/specs/UC-25-local-encrypted-volume.md)
— Implemented v1.0: C67–C74 in intent **v1.9.1** now active; `blindkey-core::volume` + GUI
Create/Mount/Eject shipped, fuzz + joint-satisfaction green)** is the PGP Disk / VeraCrypt-class
workstation complement; the `blindkey volume` CLI verbs + userspace FUSE live-folder mount are the
remaining Phase-B/C lane (see S-23 delivery plan above).
