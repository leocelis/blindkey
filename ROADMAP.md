# Roadmap

No dates, no timeline — **dependency order only**. Two kinds of work:

- **Critical path (CP)** — strictly ordered; each node blocks the next. This is the spine of v1.0.
- **Sidequests (S)** — parallel-safe utilities. Each lists what unblocks it; once unblocked, it can
  be built independently of the critical path without touching the same files.

This split exists so two maintainers (and their agents) can work **in parallel without collisions**
— see [`cowork.yaml`](cowork.yaml) for the working protocol and
[`docs/specs/`](docs/specs/README.md) for the design of every item below. Legacy milestone tags
(M2…M10) are kept in parentheses because the PRD and specs reference them.

Done so far: research & intent (M0 ✅), OSS scaffolding (M1 ✅), PRD + 16 tech specs ✅.

---

## Gate 0 — Intent decisions before any crypto/format code

Spec-writing surfaced issues that must be resolved as **intent amendments first** (both
maintainers, per [GOVERNANCE](GOVERNANCE.md) two-maintainer rule). Small, but they gate everything:

| # | Decision | Found in | Proposed resolution |
|---|----------|----------|---------------------|
| G0.1 | **C1 keystream reuse across re-saves** — same data key + deterministic nonces ⇒ XOR of two saved versions leaks plaintext diffs | [UC-07 §7](docs/specs/UC-07-untrusted-storage-sync.md) | ✅ Amended (intent v1.1.0): per-body-write `nonce_prefix` HKDF salt + SC6 — pending second-maintainer review |
| G0.2 | **C9/C10 HMAC key source** — header/block HMACs keyed from Argon2id `master_key`, which a hardware-only unlock never derives | [UC-10 §7](docs/specs/UC-10-hostile-file-parsing.md) | ✅ Amended (intent v1.3.0): HMACs keyed from `data_key`; unwrap-vs-HMAC failures share one ambiguous error — pending second-maintainer review |
| G0.3 | **`upgrade-kdf` rollback blind spot** — header-only ops don't bump `vault_version`; backend can serve the weaker-KDF file undetected | [UC-11 §7](docs/specs/UC-11-kdf-calibration.md) | ✅ Amended (intent v1.3.0): new `header_generation` u64 in the header, +1 on every save incl. header-only; anchored locally beside `vault_version` (C8/C16) — preserves C4's O(1) rotation |
| G0.4 | **Promote C28+ candidates** — KDF ceiling (A1), no-secrets-on-argv (B1, drafted in UC-05), ANSI-safe output (A2) | [gaps doc](research/security_coverage_gaps.md) | ✅ Ratified (intent v1.3.0): **C28** KDF ceiling · **C29** no-argv · **C30** ANSI-safe · **C31** presentation-layer boundary; C20's own test de-argv'd; remaining candidates start at C32 |
| G0.5 | **`release.yml` provenance bug** — SLSA job reads `needs.build.outputs.hashes`; build job defines no outputs | [UC-13 §3.2](docs/specs/UC-13-verifiable-releases.md) | ✅ Fixed: dedicated `hashes` job computes combined SLSA subjects |
| G0.6 | **C13 thread → helper process** — clear-timer "thread" can't outlive a one-shot CLI | [UC-04 §7](docs/specs/UC-04-model-blind-retrieval.md) | ✅ Amended (intent v1.3.0): thread *or* detached holder process; secret via pipe/fd only (C29); clear-iff-unchanged |

---

## Critical path

Each node lists its constraints, spec, and **the interface it freezes** — the contract the other
lane can build against from that point on.

### CP-1 · File format core *(M2)*
`C7 C8 C9 C10` · specs [UC-03](docs/specs/UC-03-store-secret.md), [UC-10](docs/specs/UC-10-hostile-file-parsing.md)
- Header parse/serialize (magic, version, KDF params, stanza records; bounded reads, length caps)
- Includes the v1.3.0 layout additions: `header_generation` u64 (G0.3) and the `kind` entry tag
  0x000E (UC-17); KDF **ceiling** check (C28) wired into the verification pipeline
- Bounded **TLV entry/payload model** (tag bit 0x8000 = Protected)
- HmacBlockStream framing; 10-step verification pipeline order
- Fuzz targets live: `header_parse`, `stanza_parse`, `block_stream`
- **Freezes:** on-disk byte layout · `Header`/`Entry`/`Stanza` types · `vault-core::format` API

### CP-2 · Cryptographic core *(M3)*
`C1 C2 C3 C4 C5 C6` (as amended by Gate 0) · specs [UC-01](docs/specs/UC-01-install-and-init.md), [UC-11](docs/specs/UC-11-kdf-calibration.md)
- Argon2id (floor **and** ceiling) → HKDF; XChaCha20-Poly1305 STREAM (64 KiB chunks)
- Data-key generation; password-stanza wrap/unwrap; envelope open (any-of-N)
- **Freezes:** `vault-core::crypto` API · `Vault::open`/`Vault::save` signatures

### CP-3 · Memory & runtime hardening *(M4)*
`C11 C12 C25` · spec [UC-14](docs/specs/UC-14-runtime-hardening.md)
- Type layer (zeroize/secrecy, Debug redaction) · page layer (mlock, `memfd_secret` probe)
- Process layer (RLIMIT_CORE=0, dumpable-off) · constant-time comparisons table
- **Freezes:** `vault-core::memory` secret types used by every later component

### CP-4 · Vault read/write, rollback, atomic saves *(M5)*
`C4 C16 C17` · specs [UC-07](docs/specs/UC-07-untrusted-storage-sync.md), [UC-01 §atomic](docs/specs/UC-01-install-and-init.md)
- Open pipeline wired end-to-end; atomic temp+rename+fsync saves; file locking
- Rollback anchor (per-`vault_id` u64, LocalAppData/XDG, flock + re-read) · `--allow-rollback` · exit 2
- **API must be UI-agnostic *and* FFI-ready** ([UC-18 §3.2](docs/specs/UC-18-native-ui.md)): returns
  structured data + secret-handles, performs delivery in-core, never prints. This is the only
  UI-related work that lands in v1 — it unblocks every future shell (TUI/egui/SwiftUI) on one core.
- **Freezes:** the full `vault-core` public API (v0 API freeze — the big sync point)

### CP-5 · CLI core loop *(M6)*
`C20 C21 C22 C27ᵈᵉᶠᵃᵘˡᵗ` · specs [UC-01](docs/specs/UC-01-install-and-init.md), [UC-04](docs/specs/UC-04-model-blind-retrieval.md), [UC-06](docs/specs/UC-06-entry-management.md)
- `init` (≤5 prompts) · `add` · `get` (clipboard default) · `ls --search` · `edit` (field-by-field) · `rm` · `lock`
- Non-TTY behavior matrix; no secrets on argv; musl static build verified
- **Freezes:** CLI surface & exit codes (scripts can rely on them)

### CP-6 · Distribution & trust *(M8)*
`C24 C23 C3` · spec [UC-13](docs/specs/UC-13-verifiable-releases.md)
- Reproducible builds (`--locked`, remap-path-prefix) · cosign keyless · SLSA provenance (fixed per G0.5)
- `cargo auditable` embedded SBOM + CycloneDX sidecar · crates.io Trusted Publishing

### CP-7 · Full IVD audit → external audit → v1.0 *(M10)*
- IVD Rule 2 sweep: 27+ constraints, PASS/FAIL/NEEDS_REVIEW, `tests/constraint_coverage.rs` all green
- Independent third-party audit (format/parser, KDF, memory, hardware FFI, AI-era delivery) → **1.0.0**

---

## Sidequests (parallel-safe)

| ID | Sidequest | Spec | Unblocked by | Notes |
|----|-----------|------|--------------|-------|
| S-1 | **Clipboard-holder helper process** (X11/Wayland/macOS/Windows, history-suppression hints, clear-iff-unchanged) | [UC-04](docs/specs/UC-04-model-blind-retrieval.md) | nothing | Standalone binary/crate; the flagship's engine |
| S-2 | **`vault gen`** — rejection sampling, charsets, EFF wordlist embedding, chi-square test harness | [UC-02](docs/specs/UC-02-csprng-generation.md) | nothing | Pure function + CLI glue later |
| S-3 | **zxcvbn entropy warning** (60-bit floor, warn-don't-block) | [UC-02](docs/specs/UC-02-csprng-generation.md) | nothing | Wraps the zxcvbn crate |
| S-4 | **`vault tune`** — RFC 9106 memory-first proportional scaling, median-of-3 | [UC-11](docs/specs/UC-11-kdf-calibration.md) | CP-2 (kdf fn) | Benchmark harness can start against raw argon2 |
| S-5 | **Import parsers** — txt, JSON, Bitwarden JSON, KeePassXC CSV (+ M9: kdbx via `keepass`, pass via gpg subprocess) | [UC-12](docs/specs/UC-12-migration-import.md) | CP-1 (Entry model) | Each format = one PR; fuzz each parser |
| S-6 | **`vault export` + `--stdout` plumbing** — warning strings, non-TTY matrix, `--password-fd/stdin` | [UC-05](docs/specs/UC-05-script-and-ci-output.md) | CP-5 partially | Spec is final; warning text is frozen |
| S-7 | **`vault merge`** — UUID union, `modified_at` tiebreak, masked diffs (8-bullet Protected) | [UC-08](docs/specs/UC-08-conflict-merge.md) | CP-4 | Needs read/write API |
| S-8a | **FIDO2 stanza** (libfido2 raw CTAP2) | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 (stanza API) | Optional for v1 (M7) |
| S-8b | **YubiKey CR stanza** (+ graceful-staleness) | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | Optional |
| S-8c | **TPM stanza** (PCR 7, re-enroll flow) | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | Optional |
| S-8d | **macOS SE / Windows DPAPI stanzas** | [UC-09](docs/specs/UC-09-hardware-factors.md) | CP-2 | Optional |
| S-9 | **Disclosure ops** — publish age intake key, triage runbook, severity modifier table | [UC-15](docs/specs/UC-15-vulnerability-reporting.md) | nothing | Process work, zero code |
| S-10 | **Auto-lock & config** — `~/.vault.toml` schema, idle timer | [UC-06](docs/specs/UC-06-entry-management.md) | CP-3 | Small |
| S-11 | **Fuzz corpus & CI fuzz budget** — seed corpora from real vault files, OSS-Fuzz application | [UC-10](docs/specs/UC-10-hostile-file-parsing.md) | CP-1 | Grows with every parser |
| S-12 | **Padmé padding exploration** (PURBs) — size-leak reduction, default-off | [UC-07 §7](docs/specs/UC-07-untrusted-storage-sync.md) | CP-4 | v2 candidate, research-first |
| S-13 | **Agent interface exploration** — handle broker, `vault_use`, OS approval gate | [UC-16](docs/specs/UC-16-agent-interface-future.md) | post-v1 | DESIGN EXPLORATION; never returns plaintext to a model (C27) |
| S-14 | **User guide & website docs** | all specs | CP-5 | Quickstart, sync guide, threat-model-for-humans |
| S-15 | **Quick-capture `import --format raw`** — lenient parser, entropy/prefix classifier, masked interactive review | [UC-17](docs/specs/UC-17-quick-capture-raw-import.md) | CP-1 (Entry model) | The messy-`keys.txt` on-ramp; optional `kind` tag wants to land *in* CP-1 |
| S-16 | **`ratatui` TUI** — search → deliver loop, alt-screen reveal hygiene | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API | **post-v1**; first UI, pure Rust, C20-exact |
| S-17 | **`egui` window** — pure-Rust GUI shell | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API | **post-v1**; non-terminal users, still single-binary |
| S-18 | **SwiftUI macOS shell via `uniffi`** — Touch ID + Secure Enclave (C5), native menus | [UC-18](docs/specs/UC-18-native-ui.md) | CP-4 API + S-8d (keychain stanza) | **post-v1**; needs the SEP-API spike + ADR |

---

## Suggested parallel lanes

Per [CODEOWNERS](.github/CODEOWNERS), `vault-core` changes need the code owner's review; the split
below keeps review load natural. Lanes are a default, not a law — swap via the claim protocol in
[`cowork.yaml`](cowork.yaml).

- **Lane A (code owner):** Gate 0 amendments → CP-1 → CP-2 → CP-3 → CP-4 (the security boundary).
- **Lane B:** S-1, S-2, S-3, S-9 immediately (zero dependencies); then S-4/S-5 as CP-1/CP-2 freeze
  interfaces; then CP-5 CLI against the frozen core API; S-6/S-7/S-10 behind it.
- **Sync points:** ① Gate 0 sign-off (both) · ② CP-1 format freeze · ③ CP-4 core API freeze ·
  ④ CP-7 audit (both).

## Out of scope for v1

Hosted cloud sync · browser extension · team/org vaults · GUI · any LLM/AI agent inside the trust
boundary (see [vault_intent.yaml](vault_intent.yaml) `non_goals` and `C27`).

## Bigger vision (post-1.0, under discussion)

Vault's audience protects more than passwords — files, `.env`s, code, database URLs, and the
secrets their AI tools touch. Expanding from "credential vault" to "developer secret vault"
(file/blob encryption, secret injection into running apps without exposing plaintext to an agent)
is the north star, scoped deliberately *after* the credential core is audited and solid.
S-13 is the first concrete step in that direction.
