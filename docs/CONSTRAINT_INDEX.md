# Constraint test index (IVD Rule 3)

Canonical constraints: [`vault_intent.yaml`](../vault_intent.yaml) — **60 constraints**, **15 groups**, intent **v1.7.0**.

Tests are **distributed** across crate suites (not a single monolithic file). Run everything with:

```sh
just check          # fmt + clippy + cargo test --workspace
just audit-ready    # release search benches + workspace tests + fmt + clippy (C55)
```

## CP-7 IVD Rule 2 sweep (2026-06-18)

**Summary:** 60 PASS · 0 NEEDS_REVIEW · 0 FAIL

| ID | Title (short) | Status | Evidence |
|----|---------------|--------|----------|
| C1 | XChaCha20-Poly1305 STREAM payload | PASS | `vault-core/src/crypto/`, format round-trip tests |
| C2 | Argon2id KDF floor/ceiling + NFC | PASS | `crypto/kdf.rs` unit tests, open rejects hostile params |
| C3 | Supply-chain policy (audit/deny) | PASS | `constraint_gaps.rs` (`c3_*`), `just audit` |
| C4 | Constant data key + stanza re-wrap | PASS | `constraint_gaps.rs`, envelope tests |
| C5 | HKDF wrapping key derivation | PASS | `crypto/envelope.rs` unit tests |
| C6 | Hardware stanza HKDF recipe | PASS | `constraint_gaps.rs`, `vault-hardware` |
| C7 | Header parser bounds | PASS | `format/header.rs`, `robustness.rs`, fuzz |
| C8 | Plaintext header fields | PASS | format unit tests |
| C9 | Keyed header HMAC | PASS | `robustness.rs`, tamper tests |
| C10 | HmacBlockStream | PASS | block stream tests + fuzz |
| C11 | mlock / locked memory | PASS | `memory/` unit tests |
| C12 | Zeroize on drop | PASS | `memory/` + `vault-sys` |
| C13 | Timed clipboard clear (helper) | PASS | `vault-clip` + `clipboard.rs`, `cli.rs` hold-clipboard |
| C14 | FIDO2 PRF stanza (libfido2) | PASS | `fido2_mock.rs` enroll/unlock; salt/HKDF; libfido2 FFI M7 |
| C15 | TPM PCR-sealed stanza + re-enroll | PASS | `tpm_mock.rs`, `enroll-tpm`/`re-enroll-tpm` CLI + `--help` |
| C16 | Monotonic vault_version + rollback warn | PASS | `rollback/`, `vault.rs` tests |
| C17 | Single opaque blob on disk | PASS | `constraint_gaps.rs` (`c17_*`) |
| C18 | Zero plaintext in stanzas | PASS | `payload.rs`, vault tests |
| C19 | Zero plaintext in entries at rest | PASS | entry encryption tests |
| C20 | CLI exact command surface | PASS | `cli.rs` integration tests |
| C21 | Export security warning | PASS | `export.rs`, `cli.rs` export tests |
| C22 | `vault tune` KDF calibration | PASS | `crypto/tune.rs`, CLI tune tests |
| C23 | Zero network in CLI | PASS | `constraint_policy.rs` |
| C24 | OSS license + dependency policy | PASS | `constraint_policy.rs`, `deny.toml` |
| C25 | Constant-time secret compare | PASS | `memory/` + clipboard helper |
| C26 | CSPRNG generation | PASS | `gen.rs` unit tests |
| C27 | Model-blind retrieval (no plaintext to agent) | PASS | `cli.rs` get/clip paths |
| C28 | Terminal output sanitization | PASS | `terminal.rs` (`c28_*`), `cli.rs` ls/get integration |
| C29 | Export JSON injection hardening (v1 JSON only) | PASS | `export.rs` (`c29_*`), `cli.rs` export integration |
| C30 | Parser forbid(unsafe) + fuzz CI | PASS | `lib.rs`, fuzz harnesses, CI |
| C31 | No secrets on argv | PASS | `cli.rs` argv rejection tests |
| C32 | Atomic durable saves + flock | PASS | `vault.rs` save tests |
| C33 | Clipboard concealment hints | PASS | `vault-clip` arboard `exclude_from_history` (+ CLI fallback) |
| C34 | Reproducible builds + release checksums | PASS | CP-6: `reproducible-build.sh`, `docs/RELEASE.md` |
| C35 | Metadata-only omni-search | PASS | `search.rs`, CLI find tests |
| C36 | Frecency ranking | PASS | `frecency.rs` tests |
| C37 | Search cache invalidation | PASS | search + GUI cache tests |
| C38 | Search latency budget (release) | PASS | `latency_under_budget_at_scale` (C58 gated) |
| C39 | Prefix / fuzzy match | PASS | search unit tests |
| C40 | GUI reactive repaint invariants | PASS | `uc20_constraints.rs` |
| C41 | Glow renderer pin | PASS | `uc20_constraints.rs` |
| C42 | Fuzzy search cache | PASS | `uc20_constraints.rs` |
| C43 | List virtualization threshold | PASS | `uc20_constraints.rs`, `list_virtualize.rs` |
| C44 | Password field masking audit | PASS | `uc20_constraints.rs` |
| C45 | Thin GUI shell (no crypto in UI) | PASS | `uc20_constraints.rs` |
| C46 | Time-boxed password reveal (15s) | PASS | `uc21_constraints.rs` |
| C47 | Optional lock on blur | PASS | `uc21_constraints.rs` |
| C48 | Keyfile 2FA unlock GUI | PASS | `uc21_constraints.rs` |
| C49 | Keyfile 2FA enroll GUI | PASS | `uc21_constraints.rs` |
| C50 | Pre-1.0 security banner | PASS | `uc21_constraints.rs` |
| C51 | Configurable clipboard timeout (GUI) | PASS | `uc21_constraints.rs` |
| C52 | Virtualize lists above 100 rows | PASS | `uc21_constraints.rs`, `list_virtualize.rs` |
| C53 | Metadata-only search hint | PASS | `uc21_constraints.rs` |
| C54 | Password field a11y labels | PASS | `uc21_constraints.rs`; optional manual in `guides/accessibility.md` |
| C55 | `audit-readiness.sh` green | PASS | script + `just audit-ready` |
| C56 | `AUDIT_READINESS.md` scope doc | PASS | this file + SECURITY.md link |
| C57 | Enterprise env vars (GUI) | PASS | `uc22_constraints.rs`, `gui_config` |
| C58 | C38 bench release-only | PASS | `search.rs` debug early-return |
| C59 | N=5000 search under 200 ms | PASS | `latency_at_five_thousand` release test |
| C60 | Enterprise posture docs | PASS | `ENTERPRISE_POSTURE.md`, deployment guide |

**1.0.0 tag:** all 60 constraints PASS at automated gate; libfido2/TPM FFI optional M7; tag after first CP-6 release run.

## Where constraints are verified

| Constraints | Primary test location | Notes |
|-------------|----------------------|-------|
| C1–C3 | `crates/vault-core/src/crypto/`, `tests/constraint_gaps.rs` (`c3_*`) | Crypto + supply-chain policy |
| C4, C6 | `crates/vault-core/tests/constraint_gaps.rs`, `envelope/` unit tests | Data key + re-wrap |
| C7–C10, C30 | `crates/vault-core/src/format/`, `tests/robustness.rs`, `fuzz/` | Parser hardening |
| C11–C13, C25, C33 | `vault-clip/`, `vault-core/src/memory/`, CLI/GUI clipboard | Memory + delivery |
| C14, C15 | `vault-hardware` (`fido2_mock`, `tpm_mock`, `tpm_policy`), CLI TPM commands | FIDO2 recipe + TPM policy |
| C16, C32 | `crates/vault-core/src/rollback/`, `vault.rs` tests | Rollback + atomic save |
| C17 | `crates/vault-core/tests/constraint_gaps.rs` (`c17_*`) | Single opaque blob |
| C18–C19 | `crates/vault-core/src/format/payload.rs`, `vault.rs` | Zero plaintext |
| C20–C22 | `crates/vault-cli/tests/cli.rs`, `crypto/tune.rs` | CLI + KDF tune |
| C23, C24 | `crates/vault-cli/tests/constraint_policy.rs` | Zero network + OSS license |
| C26 | `crates/vault-core/src/gen.rs` | CSPRNG generator |
| C27–C31 | `crates/vault-cli/tests/cli.rs`, `terminal.rs`, `export.rs` | Model-blind + argv + sanitize |
| C34 | `scripts/reproducible-build.sh`, `scripts/publish-crates.sh`, `docs/RELEASE.md` | Release trust + crates.io |
| C35–C39 | `crates/vault-core/src/search.rs`, `frecency.rs`, CLI `find` tests | Omni-search |
| C40–C45 | `crates/vault-gui/tests/uc20_constraints.rs` | Desktop hardening |
| C46–C54 | `crates/vault-gui/tests/uc21_constraints.rs` | Session hygiene + keyfile GUI |
| C55–C60 | `crates/vault-gui/tests/uc22_constraints.rs`, `scripts/audit-readiness.sh` | Fleet deploy + quality gate |

## Manual review

- **C54** — automated label wiring in `uc21_constraints.rs`; optional VoiceOver/NVDA checklist in
  [`guides/accessibility.md`](guides/accessibility.md)

## Test methodology notes

- **C28 / C29 / C13** — named unit tests plus `cli.rs` integration for ls/get sanitize and hold-clipboard.
- **C40–C54** — `uc20`/`uc21` tests are **static wiring** checks (source grep), not live GUI oracles.
- **C34** — reproducible build via `scripts/reproducible-build.sh`; maintainer-local release per `docs/RELEASE.md`.

Contributors: when you satisfy a constraint, add or point to the test in your PR and update this table.
