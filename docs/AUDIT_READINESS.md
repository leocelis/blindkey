# Release Quality Gate (CP-7)

Vault is **functional pre-1.0**. This document describes the **automated quality gate** before the
`1.0.0` tag ([ROADMAP](../ROADMAP.md) CP-7) — not a substitute for careful review.

## What the gate checks

| Area | Artifacts | Constraints |
|------|-----------|-------------|
| File format & parsers | `docs/FILE_FORMAT.md`, `crates/vault-core/src/format/`, fuzz targets | C7–C10, C30 |
| KDF & crypto | `docs/CRYPTO.md`, `crates/vault-core/src/crypto/` | C1–C6 |
| Memory & runtime | `docs/specs/UC-14-runtime-hardening.md`, `vault-sys` | C11–C13, C25 |
| Envelope & 2FA | `docs/specs/UC-09-hardware-factors.md` | C5, C14–C15 |
| AI-era delivery | `docs/specs/UC-04-model-blind-retrieval.md` | C26–C27 |
| Desktop shell boundary | `docs/specs/UC-18-native-ui.md`, `crates/vault-gui/` | C40–C54, C45 |
| Supply chain | `docs/VERIFYING_RELEASES.md`, cosign/SLSA + `cargo auditable` SBOM in `release.yml` | C3, C34 |

Out of scope for v1: team vaults, cloud sync service, browser extension (intent `non_goals`).

## Run the gate

From repo root (project toolchain active):

```sh
just audit-ready
# or: ./scripts/audit-readiness.sh
```

Runs release search benchmarks (C38/C59), clippy, and supply-chain checks when tools are installed.

## IVD constraint index

Canonical constraints: [`vault_intent.yaml`](../vault_intent.yaml) (60 constraints, v1.7.0).

Test map: [`docs/CONSTRAINT_INDEX.md`](CONSTRAINT_INDEX.md) — distributed across crate suites.

## Threat model

[`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — residual risks contributors should not expect mitigated.

## Disclosure

[`SECURITY.md`](../SECURITY.md) · [`docs/specs/UC-15-vulnerability-reporting.md`](specs/UC-15-vulnerability-reporting.md)

## Optional third-party audit

[`docs/THIRD_PARTY_AUDIT.md`](THIRD_PARTY_AUDIT.md) — scope and checklist if commissioning external review.

## Terminology

- **`vault audit`** — password-health report command (weak/reused passwords), not this gate
- **Dependency audit** — `cargo audit` / `cargo deny` in CI (`.github/workflows/audit.yml`)
