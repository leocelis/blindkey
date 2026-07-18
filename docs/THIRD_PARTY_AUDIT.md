# Third-Party Security Audit (Optional)

Blindkey v1.0 is gated on the **CP-7 release quality gate** (`just audit-ready` + IVD constraint
sweep), not on commissioning an external audit. A third-party review is **optional** before
wide production adoption.

**Project decision (2026-06-26):** maintainers declined commissioning an external firm audit;
trust posture is **semi-automatic gates** — CP-7 (`audit-ready`), 60 IVD constraints + tests,
`cargo audit`/`deny`, fuzz targets (C30), reproducible releases (C34). Do not market Blindkey as
"independently audited." See [AUDIT_READINESS.md](AUDIT_READINESS.md).

The RFP pack in [AUDIT_COMMISSION.md](AUDIT_COMMISSION.md) remains if policy changes later.

## When to commission one

- Before marketing Blindkey as "audit-backed" or enterprise-grade
- After a major format or crypto change (new `format_version`, KDF swap, hardware FFI rewrite)
- When a customer or regulator requires independent attestation

## Scope (matches CP-7)

| Area | Artifacts |
|------|-----------|
| On-disk format & parsers | `docs/FILE_FORMAT.md`, `crates/blindkey-core/src/format/`, fuzz targets |
| KDF & crypto | `docs/CRYPTO.md`, `crates/blindkey-core/src/crypto/` |
| Memory & runtime | `docs/specs/UC-14-runtime-hardening.md`, `blindkey-sys` |
| Envelope & 2FA | `docs/specs/UC-09-hardware-factors.md`, `blindkey-hardware` |
| AI-era delivery | `docs/specs/UC-04-model-blind-retrieval.md` |
| Desktop shell boundary | `crates/blindkey-gui/` (no crypto in UI crate) |
| Supply chain | Signed releases, embedded SBOM (`cargo auditable`), `cargo audit`/`deny` |

Out of scope: cloud sync service, team vaults, browser extension (intent `non_goals`).

## Intake

Report findings via [SECURITY.md](../SECURITY.md) (GitHub Security Advisories). For embargoed
audit reports, contact maintainers through the same channel before public disclosure.

## Pre-audit checklist

1. `just audit-ready` exits 0 on the tagged commit
2. [`docs/CONSTRAINT_INDEX.md`](CONSTRAINT_INDEX.md) — all 60 constraints PASS or acknowledged
3. [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — residual risks documented
4. Fuzz targets run clean (`just fuzz` locally)
5. Release artifacts verifiable per [`VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md)

## Deliverables expected from auditors

- Written report with severity-rated findings
- Mapping of each finding to constraint ID or documented residual risk
- Re-test confirmation for fixes shipped before publication

## References

- KeePassXC / ANSSI precedent for password-manager audits
- [`docs/AUDIT_READINESS.md`](AUDIT_READINESS.md) — automated gate (not a substitute for human review)
