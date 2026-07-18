# KDF Floor Policy — Research

> **Task:** Hard-reject below-floor Argon2id on `init`; warn-only on `open` + `upgrade-kdf` nudge.

## Problem

Today `validate_kdf_params` returns `KdfStrength::BelowFloor` on open — CLI prints a warning but proceeds. New vaults can be created with `--kdf-m-cost 8192` (test default), which is **below** the OWASP floor (m ≥ 19 456 KiB, t ≥ 2, p ≥ 1).

**Risk:** operators/scripts accidentally create weak-at-birth vaults; only discover on audit.

## Policy split (card recommendation)

| Path | Below-floor behavior | Rationale |
|------|----------------------|-----------|
| **`blindkey init` / `Blindkey::create`** | **Hard reject** | Stop new weak vaults |
| **`blindkey upgrade-kdf` / `change_kdf`** | **Hard reject** target params | Cannot downgrade via upgrade |
| **`blindkey open` / import / ls / get** | **Warn** + suggest `upgrade-kdf` | Don't strand legacy vaults |
| **Tests / CI** | `--allow-weak-kdf` on init only | Fast Argon2id in integration tests |

**Import (`blindkey import --format raw`):** opens an existing vault → inherits open policy (warn only). Raw import does not set KDF params. Future UC-12 migrators that call `Blindkey::create` inherit the write policy automatically.

## Intent amendment (C2)

Add to C2 description (preserve open behavior):

- Creation paths MUST reject below-floor params with a distinct error.
- `upgrade-kdf` target params MUST reject below floor.
- Open of existing below-floor vaults unchanged (WARNING + upgrade offer).

## Escape hatch

`--allow-weak-kdf` on `blindkey init` only (matches UC-11 draft for scripted setup). **Not** on `upgrade-kdf`.

## References

- `vault/blindkey_intent.yaml` C2
- `docs/specs/UC-11-kdf-calibration.md` §3.3
- Card #847 gap table — KDF floor warns, doesn't reject
