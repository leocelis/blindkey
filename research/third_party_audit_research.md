# Third-Party Audit Commission — Research

> **Task:** Commission scoped third-party security audit post format freeze.
> **Agent-deliverable:** intake package ready for an RFP; **maintainer-only:** vendor selection, NDA, payment, kickoff.

## Why now

| Prerequisite | Status |
|--------------|--------|
| Format v1 frozen (ADR-0005) | ✅ 2026-06-26 |
| CP-7 quality gate (`audit-ready`) | ✅ green on workspace |
| 60/60 constraint sweep | ✅ CONSTRAINT_INDEX.md |
| Threat model + residual risks | ✅ THREAT_MODEL.md |
| v1.0.0 repo prep | ✅ (tag/push deferred until card cleared) |

security-gap review recommends audit **after format freeze, before enterprise marketing** — not a v1.0 code gate.

## Scope (from card + THIRD_PARTY_AUDIT.md)

**In scope for auditors:**

| Area | Primary artifacts |
|------|-------------------|
| On-disk format & parsers | `docs/FILE_FORMAT.md`, `crates/blindkey-core/src/format/`, `fuzz/` |
| KDF & crypto | `docs/CRYPTO.md`, `crates/blindkey-core/src/crypto/` |
| Envelope & stanzas | `crates/blindkey-core/src/envelope/`, UC-09 |
| Memory & runtime | UC-14, `blindkey-sys`, `crates/blindkey-core/src/memory/` |
| AI-era delivery | UC-04, C27/C28/C31, `blindkey-cli`, `blindkey-clip` |
| Desktop boundary | `blindkey-gui` — no crypto in UI crate |
| Supply chain | `scripts/reproducible-build.sh`, `cargo audit`/`deny`, C34 |

**Out of scope:** cloud sync service, team vaults, browser extension, live libfido2/TPM FFI (mock paths only), S-13 agent broker (design only).

## Vendor landscape (~inferred)

Firms commonly used for password-manager / Rust crypto audits:

- **Cure53** — KeePassXC, Bitwarden-adjacent work
- **NCC Group** — enterprise crypto reviews
- **Trail of Bits** — Rust + tooling (cargo-audit ecosystem)
- **Radically Open Security** — OSS-friendly engagements

Selection criteria: prior password-manager or KDF audit, Rust memory-safety review experience, fuzzing familiarity, fixed-scope quote, embargo + coordinated disclosure alignment with [SECURITY.md](../SECURITY.md).

## Engagement model

- **Type:** time-boxed source review + targeted dynamic tests (not full formal verification)
- **Duration:** ~2–4 engineer-weeks typical for this surface (~15k LOC security core)
- **Deliverable:** written report, severity-rated findings, constraint ID mapping, re-test of fixes before publication
- **Embargo:** findings via private channel until patched; UC-15 pipeline

## What “commission” means for this checklist

| Step | Owner | Done when |
|------|-------|-----------|
| Intake package + pre-audit script | Agent/repo | `docs/AUDIT_COMMISSION.md` + `scripts/audit-intake-checklist.sh` |
| Run intake on release commit | Leo | script exits 0 |
| Send RFP + repo access to vendor | Leo | vendor confirms scope |
| Audit execution + report | Vendor | report received |
| Fix + disclose | Maintainers | GHSA / advisory published |

**Checklist item complete (repo side):** intake package shipped and verified. **Leo marks commission executed** when RFP is sent / vendor engaged.

## References

- [THIRD_PARTY_AUDIT.md](../docs/THIRD_PARTY_AUDIT.md)
- [AUDIT_READINESS.md](../docs/AUDIT_READINESS.md)
- KeePassXC audit report (2023) — Molotnikov / Argon2id precedent cited in C2
- security-gap review gap table — “No third-party audit”
