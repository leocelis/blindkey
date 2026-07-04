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

**Is Vault v1 ready?** **Yes — `1.0.0` release prepared** (2026-06-26): CP-7 green, format v1 frozen,
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
| G0.8 | **Stable exit codes + headless clipboard rule + `vault stanzas`** — specs disagreed on exit codes (UC-04/05/06/08); no enrollment command existed; headless `get` behavior was spec-only | [UC-10 §7](docs/specs/UC-10-hostile-file-parsing.md), [UC-04 §7](docs/specs/UC-04-model-blind-retrieval.md) | ✅ Amended + verified |

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
- **Freezes:** on-disk byte layout · `Header`/`Entry`/`Stanza` types · `vault-core::format` API

### CP-2 · Cryptographic core *(M3)* ✅
`C1 C2 C3 C4 C5 C6` (as amended by Gate 0) · specs [UC-01](docs/specs/UC-01-install-and-init.md), [UC-11](docs/specs/UC-11-kdf-calibration.md)
- Argon2id (floor **and** ceiling) → HKDF; XChaCha20-Poly1305 STREAM (64 KiB chunks)
- Data-key generation; password-stanza wrap/unwrap; envelope open (any-of-N)
- **Freezes:** `vault-core::crypto` API · `Vault::open`/`Vault::save` signatures

### CP-3 · Memory & runtime hardening *(M4)* ✅
`C11 C12 C25` · spec [UC-14](docs/specs/UC-14-runtime-hardening.md)
- Type layer (zeroize/secrecy, Debug redaction) · page layer (mlock, `memfd_secret` probe)
- Process layer (RLIMIT_CORE=0, dumpable-off) · constant-time comparisons table
- **Freezes:** `vault-core::memory` secret types used by every later component

### CP-4 · Vault read/write, rollback, atomic saves *(M5)* ✅
`C4 C16 C17 C32` · specs [UC-07](docs/specs/UC-07-untrusted-storage-sync.md), [UC-01 §atomic](docs/specs/UC-01-install-and-init.md)
- Open pipeline wired end-to-end; atomic temp+rename+fsync saves; file locking
- Rollback anchor (per-`vault_id` u64, LocalAppData/XDG, flock + re-read) · `--allow-rollback` · exit 2
- **API must be UI-agnostic *and* FFI-ready** ([UC-18 §3.2](docs/specs/UC-18-native-ui.md)): returns
  structured data + secret-handles, performs delivery in-core, never prints. This is the only
  UI-related work that lands in v1 — it unblocks every future shell (TUI/egui/SwiftUI) on one core.
- **Freezes:** the full `vault-core` public API (v0 API freeze — the big sync point)

### CP-5 · CLI core loop *(M6)* ✅
`C20 C21 C22 C27` · specs [UC-01](docs/specs/UC-01-install-and-init.md), [UC-04](docs/specs/UC-04-model-blind-retrieval.md), [UC-06](docs/specs/UC-06-entry-management.md)
- Shipped: full surface including `vault stanzas list/add/remove`, headless **exit 7** (C27)
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
| S-1 | 🟡 **Clipboard delivery crate** (`vault-clip`: C13/C33 concealment + fallback) | [UC-04](docs/specs/UC-04-model-blind-retrieval.md) | nothing | Core shipped; UC-04 detached X11 selection-owner helper still optional polish |
| S-2 | **`vault gen`** — rejection sampling, charsets, EFF wordlist embedding, chi-square test harness | [UC-02](docs/specs/UC-02-csprng-generation.md) | nothing | Pure function + CLI glue later |
| S-3 | **zxcvbn entropy warning** (60-bit floor, warn-don't-block) | [UC-02](docs/specs/UC-02-csprng-generation.md) | nothing | Wraps the zxcvbn crate |
| S-4 | ✅ **`vault tune`** — Argon2id benchmark + recommend m/t/p (~300 ms) | [UC-11](docs/specs/UC-11-kdf-calibration.md) | CP-2 (kdf fn) | **DONE** (C22): probe + linear-extrapolate `m`, clamp to policy, re-measure; unlock progress line |
| S-5 | **Import parsers** — txt, JSON, Bitwarden JSON, KeePassXC CSV (+ M9: kdbx via `keepass`, pass via gpg subprocess) | [UC-12](docs/specs/UC-12-migration-import.md) | CP-1 (Entry model) | Each format = one PR; fuzz each parser |
| S-6 | ✅ **`vault export` + `--stdout` plumbing** — JSON export, warnings, non-TTY matrix, unlock channels | [UC-05](docs/specs/UC-05-script-and-ci-output.md) | CP-5 partially | Done |
| S-7 | **`vault merge`** — UUID union, `modified_at` tiebreak, masked diffs (8-bullet Protected) | [UC-08](docs/specs/UC-08-conflict-merge.md) | CP-4 | Needs read/write API |
| S-8a | **FIDO2 stanza** (libfido2 raw CTAP2) | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 (stanza API) | Optional for v1 (M7) |
| S-8b | 🟡 **YubiKey CR stanza** | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | **CLI DONE** (`vault enroll yubikey`): composite **AND** 2FA (password + key both required) + one-time recovery code; HMAC-SHA1 slot-2 via `ykman` subprocess (no FFI). Pending: GUI enrollment + the UC-09 AND-model intent amendment |
| S-8c | **TPM stanza** (PCR 7, re-enroll flow) | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | Optional |
| S-8d | **macOS SE / Windows DPAPI stanzas** | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | Optional |
| S-9 | **Disclosure ops** — publish age intake key, triage runbook, severity modifier table | [UC-15](docs/specs/UC-15-vulnerability-reporting.md) | nothing | Process work, zero code |
| S-10 | 🟡 **Auto-lock & config** — `~/.vault.toml` schema, idle timer | [UC-06](docs/specs/UC-06-entry-management.md) | CP-3 | **GUI idle auto-lock + lock-on-minimize DONE** (configurable timeout in `~/.vault/config`). Pending: full `~/.vault.toml` + CLI-session auto-lock |
| S-11 | **Fuzz corpus & CI fuzz budget** — seed corpora from real vault files, OSS-Fuzz application | [UC-10](docs/specs/UC-10-hostile-file-parsing.md) | CP-1 | Grows with every parser |
| S-12 | ✅ **Padmé padding** (PURBs) — optional size-leak reduction, **default off** | [UC-07 §3.2](docs/specs/UC-07-untrusted-storage-sync.md) · [guide](docs/guides/size-padding-padme.md) | CP-4 | **DONE**; v2 default-on deferred |
| S-13 | 🟡 **Agent interface** — handle broker, `vault agent`, OS approval gate | [UC-16](docs/specs/UC-16-agent-interface-future.md) | post-v1 MCP | **SCAFFOLD** (`vault-agent` + `vault agent`); status-only IPC (C27) |
| S-14 | **User guide & website docs** | all specs | CP-5 | Quickstart, sync guide, threat-model-for-humans |
| S-15 | ✅ **Quick-capture `import --format raw`** — lenient parser, entropy/prefix classifier, masked interactive review | [UC-17](docs/specs/UC-17-quick-capture-raw-import.md) | CP-1 (Entry model) | Shipped |
| S-16 | ✅ **`ratatui` TUI** — search → deliver loop, alt-screen reveal hygiene | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API | **DONE** (`vault-tui`); first UI, pure Rust, C20-exact |
| S-17 | ✅ **`egui` window** — pure-Rust GUI shell | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API | **DONE** (`vault-gui`): create/unlock, drop-a-`keys.txt` import, search, shadowed copy, edit/change/delete; `scripts/bundle-macos.sh` → `Vault.app`. Needed the 1.82→1.96 toolchain bump |
| S-19 | ✅ **Desktop GUI hardening** — glow pin, search cache, list virtualization, C40–C45 | [UC-20](docs/specs/UC-20-desktop-gui-hardening.md) | S-17 | Perf + presentation security on weak hardware |
| S-20 | ✅ **Desktop gaps closure** — reveal timeout, keyfile GUI, pre-1.0 banner, C46–C54 | [UC-21](docs/specs/UC-21-desktop-gaps-closure.md) | S-19 | Session hygiene + 2FA GUI parity |
| S-21 | ✅ **Fleet deploy & quality gate** — env paths, release benches, C55–C60 | [UC-22](docs/specs/UC-22-enterprise-readiness.md) | S-20 | CP-7 automated gate |
| S-18 | **SwiftUI macOS shell via `uniffi`** — Touch ID + Secure Enclave (C5), native menus | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API + S-8d (keychain stanza) | **post-v1**; needs the SEP-API spike + ADR |
| S-22 | ✅ **Sealed file storage** — `vault seal/open/peek`: any file/folder → one `.vltf` blob for untrusted clouds; zero plaintext metadata, Padmé default-on, streaming bounded-memory, fail-closed extraction | [UC-23](docs/specs/UC-23-sealed-file-storage.md) | v1.0 core + C61–C66 | **Shipped** (July 2026). CLI + GUI/TUI + stanza parity on `.vltf`. |

---

## Suggested parallel lanes

Per [CODEOWNERS](.github/CODEOWNERS), `vault-core` changes need the code owner's review; the split
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
- crypto-shredding semantics + `vault rotate-data-key` (gap C2)
- recovery-code stanza for all-factors-lost (gap C3)
- `cargo-vet`, dependency budget (gap D2; SBOM itself ships in CP-6)
- post-quantum posture statement / hybrid-PQ wrap reservation (gap E1; S-12 padding is adjacent)

## Out of scope for v1

Hosted cloud sync · browser extension · team/org vaults · **native SwiftUI shell** · any LLM/AI agent inside the trust
boundary (see [vault_intent.yaml](vault_intent.yaml) `non_goals` and `C27`). Pure-Rust TUI/GUI shells are **shipped** (pre-1.0 beta).

## Bigger vision (post-1.0, under discussion)

Vault's audience protects more than passwords — files, `.env`s, code, database URLs, and the
secrets their AI tools touch. Expanding from "credential vault" to "developer secret vault"
(file/blob encryption, secret injection into running apps without exposing plaintext to an agent)
is the north star, scoped deliberately *after* the credential core is solid at 1.0.
S-13 (agent interface) and **S-22 (sealed file storage, [UC-23](docs/specs/UC-23-sealed-file-storage.md)
— now specced: research → patterns → PRD → forward constraints C61–C66 in intent v1.8.0 draft)**
are the first concrete steps in that direction.
