# Constraint test index (IVD Rule 3)

Canonical constraints: [`vault_intent.yaml`](../vault_intent.yaml) — **60 constraints**, **15 groups**, intent **v1.7.0**.

Tests are **distributed** across crate suites (not a single monolithic file). Run everything with:

```sh
just check          # fmt + clippy + cargo test --workspace
just audit-ready    # release search benches + clippy (C55)
```

## Where constraints are verified

| Constraints | Primary test location | Notes |
|-------------|----------------------|-------|
| C1–C6 | `crates/vault-core/src/crypto/`, `envelope/` unit tests | Crypto + envelope |
| C7–C10, C30 | `crates/vault-core/src/format/`, `tests/robustness.rs`, `fuzz/` | Parser hardening |
| C11–C13, C25, C33 | `crates/vault-core/src/memory/`, CLI clipboard paths | Memory + delivery |
| C16, C32 | `crates/vault-core/src/rollback/`, `vault.rs` tests | Rollback + atomic save |
| C18–C19 | `crates/vault-core/src/format/payload.rs`, `vault.rs` | Zero plaintext |
| C20–C22 | `crates/vault-cli/tests/cli.rs`, `crypto/tune.rs` | CLI + KDF tune |
| C26 | `crates/vault-core/src/gen.rs` | CSPRNG generator |
| C27–C31 | `crates/vault-cli/tests/cli.rs` | Model-blind + argv |
| C34 | `scripts/reproducible-build.sh`, `.github/workflows/` | Release trust |
| C35–C39 | `crates/vault-core/src/search.rs`, `frecency.rs`, CLI `find` tests | Omni-search |
| C40–C45 | `crates/vault-gui/tests/uc20_constraints.rs` | Desktop hardening |
| C46–C54 | `crates/vault-gui/tests/uc21_constraints.rs` | Session hygiene + keyfile GUI |
| C55–C60 | `crates/vault-gui/tests/uc22_constraints.rs`, `scripts/audit-readiness.sh` | Fleet deploy + quality gate |

## Coverage gaps (honest)

Some constraints are enforced by code review, fuzzing, or release process rather than a dedicated unit test name. Tracked improvements:

- **C3, C4, C6, C14, C15, C17, C23, C24** — partial automation; expand dedicated tests before 1.0
- **C54** — wiring tests pass; manual screen-reader spot-check is NEEDS_REVIEW per intent

Contributors: when you satisfy a constraint, add or point to the test in your PR and update this table.
