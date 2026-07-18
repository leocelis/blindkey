# UC-22 — Enterprise Readiness

> **Tech spec** · Implemented · June 2026  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-22 · **New constraints:** C55–C60  
> **Builds on:** CP-7 quality gate, UC-20/21, [THREAT_MODEL.md](../THREAT_MODEL.md)

## 1. Scope

Prepare Blindkey for **fleet deployment and release discipline** without falsely claiming SOC2/team-vault
certification. Implements the **release quality gate**, **deployment env hooks**, **release-scale
search benches**, and **honest enterprise posture documentation**.

### In scope

- `docs/AUDIT_READINESS.md` + `scripts/audit-readiness.sh`
- `docs/ENTERPRISE_POSTURE.md` + `docs/guides/enterprise-deployment.md`
- Env-based deployment: `BLINDKEY_VAULT_PATH`, `BLINDKEY_CONFIG_DIR`, `BLINDKEY_LOCK_ON_BLUR`
- C38/C59 release-only search benchmarks
- `just audit-ready` task

### Deferred (documented, not implemented)

| Gap | Tracker |
|-----|---------|
| Third-party audit (optional, human/vendor) | Not required for functionality; documented in CP-7 if pursued later |
| Team / org vaults, SSO, SCIM | Intent `non_goals` · v2+ |
| SOC2 / ISO certification | ENTERPRISE_POSTURE §4 |
| SwiftUI / uniffi shell | S-18 / UC-18 P3 |
| eframe 0.34 bump | ROADMAP sidequest |

## 2. Design

### 2.1 Audit readiness (C55, C56)

`scripts/audit-readiness.sh`:
1. `cargo test -p blindkey-core --release search::tests::latency_under_budget_at_scale`
2. `cargo test -p blindkey-core --release search::tests::latency_at_five_thousand`
3. `cargo clippy --all-targets -- -D warnings`
4. `cargo audit` + `cargo deny check` (if installed)

### 2.2 Fleet deployment (C57)

| Env | Effect |
|-----|--------|
| `BLINDKEY_VAULT_PATH` | Override `~/.blindkey/vault.vlt` |
| `BLINDKEY_CONFIG_DIR` | Override `~/.blindkey/` config directory |
| `BLINDKEY_LOCK_ON_BLUR=1` | Force `lock_on_blur` in GUI config |

### 2.3 Search scale (C58, C59)

- C38 test: **skip** when `cfg!(debug_assertions)`
- C59: new test at **N=5000**, **200 ms** budget, release only

### 2.4 Posture (C60)

`ENTERPRISE_POSTURE.md`: security properties, deployment checklist, explicit non-claims.

## 3. Constraints

| ID | Test |
|----|------|
| C55 | `audit-readiness.sh` exits 0 |
| C56 | `AUDIT_READINESS.md` complete |
| C57 | Env vars honored in gui_config |
| C58 | C38 skips debug |
| C59 | C59 passes `--release` |
| C60 | Posture + deployment guides exist |

## 4. Segments

S1 Docs + script · S2 Env vars · S3 Search tests · S4 Intent + validate
