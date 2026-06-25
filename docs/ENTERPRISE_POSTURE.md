# Enterprise Posture

Vault is a **local-first, single-user credential vault** — not a 1Password Business / Bitwarden
Teams replacement. This document states what enterprise buyers can rely on today and what requires
a future product line.

## What Vault provides (v1)

| Property | Evidence |
|----------|----------|
| Zero plaintext entry metadata on disk | C18, `strings` tests |
| Argon2id with enforced floor | C2 |
| Model-blind secret delivery | C27, C13 |
| Reproducible builds + checksums | UC-13, C34, `docs/RELEASE.md` |
| Constraint-driven development | `vault_intent.yaml`, IVD |
| Desktop session hygiene | UC-21 (reveal timeout, lock-on-blur, keyfile GUI) |
| Audit readiness package | [AUDIT_READINESS.md](AUDIT_READINESS.md) (release quality gate) |

## Explicit non-claims (v1)

Vault **does not** provide:

- SOC 2 Type II, ISO 27001, or FedRAMP certification
- Team / organisational vaults, shared collections, or RBAC
- SSO (SAML/OIDC), SCIM provisioning, or directory sync
- Hosted admin console, usage analytics, or central policy server
- Browser extension or native mobile apps (post-v1 roadmap)

These are **intent non-goals** unless a separate enterprise product is scoped.

## Deployment hardening (fleet)

See [guides/enterprise-deployment.md](guides/enterprise-deployment.md):

- `VAULT_VAULT_PATH` — per-user or per-machine vault file location
- `VAULT_CONFIG_DIR` — central config directory (MDM-deployable)
- `VAULT_LOCK_ON_BLUR=1` — force lock when window loses focus
- Pre-1.0 banner until 1.0 tag (UC-21 C50)

## Mitigations for accepted risks

| Risk | Mitigation |
|------|------------|
| Clipboard exposure | Configurable clear timeout; copy warning (C51) |
| RAM while unlocked | Auto-lock, lock-on-blur, minimize→lock |
| Metadata visible when unlocked | Encrypted on disk; search is metadata-only (C35) |
| egui vs native shell | UC-18 P3 SwiftUI deferred; egui hardened UC-20/21 |

## Path to 1.0

1. **CP-7** — `just audit-ready` green + IVD Rule 2 sweep (60 constraints)
2. **v1.0.0** — format freeze after quality gate passes
3. **v2+** — evaluate org vaults / SSO only if product strategy changes (new intent artifact)
