# Third-Party Security Audit (Optional)

Vault v1.0 is gated on the **CP-7 release quality gate** (`just audit-ready` + IVD constraint
sweep), not on commissioning an external audit. A third-party review is **recommended** before
wide production adoption but remains optional.

## When to commission one

- Before marketing Vault as "audit-backed" or enterprise-grade
- After a major format or crypto change (new `format_version`, KDF swap, hardware FFI rewrite)
- When a customer or regulator requires independent attestation

## Scope (matches CP-7)

| Area | Artifacts |
|------|-----------|
| On-disk format & parsers | `docs/FILE_FORMAT.md`, `crates/vault-core/src/format/`, fuzz targets |
| KDF & crypto | `docs/CRYPTO.md`, `crates/vault-core/src/crypto/` |
| Memory & runtime | `docs/specs/UC-14-runtime-hardening.md`, `vault-sys` |
| Envelope & 2FA | `docs/specs/UC-09-hardware-factors.md`, `vault-hardware` |
| AI-era delivery | `docs/specs/UC-04-model-blind-retrieval.md` |
| Desktop shell boundary | `crates/vault-gui/` (no crypto in UI crate) |
| Supply chain | Signed releases, embedded SBOM (`cargo auditable`), `cargo audit`/`deny` |

Out of scope: cloud sync service, team vaults, browser extension (intent `non_goals`).

## Intake

Report findings via [SECURITY.md](../SECURITY.md) (GitHub Security Advisories). For embargoed
audit reports, contact maintainers through the same channel before public disclosure.

## Pre-audit checklist

1. `just audit-ready` exits 0 on the tagged commit
2. [`docs/CONSTRAINT_INDEX.md`](CONSTRAINT_INDEX.md) — all 60 constraints PASS or acknowledged
3. [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — residual risks documented
4. Fuzz targets run clean (`just fuzz-smoke` or CI fuzz job)
5. Release artifacts verifiable per [`VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md)

## Deliverables expected from auditors

- Written report with severity-rated findings
- Mapping of each finding to constraint ID or documented residual risk
- Re-test confirmation for fixes shipped before publication

## References

- KeePassXC / ANSSI precedent for password-manager audits
- [`docs/AUDIT_READINESS.md`](AUDIT_READINESS.md) — automated gate (not a substitute for human review)
