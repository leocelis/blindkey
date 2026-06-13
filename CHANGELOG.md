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
  HmacBlockStream parsers, Argon2id floor+ceiling validation, `data_key`-keyed integrity, and the
  three fuzz targets wired to the real parsers (constraints `C2`, `C5`, `C7`–`C10`, `C30`). 30 unit
  tests; `fmt` + `clippy -D warnings` clean on the pinned toolchain.

### Changed
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
