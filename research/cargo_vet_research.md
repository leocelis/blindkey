# cargo-vet — supply-chain vetting in release gate

> **Task:** Add `cargo vet` to `just audit-ready`, pin vet exemptions in-repo (M9 gap D2).

## Problem (gap D2)

`cargo audit` / `cargo deny` catch **known advisories** and license/ban policy. They do not gate
**unreviewed dependency code** — a maintainer can add a crate with no security review and still
pass audit/deny.

**cargo-vet** adds a third layer: every dependency must be **audited** (local or imported) or
**explicitly exempted** with a pinned version + criteria (`safe-to-deploy` / `safe-to-run`).

## Decision

| Choice | Rationale |
|--------|-----------|
| Pin `supply-chain/` in git | Reproducible gate; lockfile bumps require conscious vet update |
| Bootstrap via `cargo vet init` exemptions | No mozilla import network fetch required for v1; 461 version-pinned exemptions |
| Gate in `audit-readiness.sh` | Same path as audit/deny; WARN-skip if tool missing (contributor UX) |
| Do **not** claim third-party audit | Semi-auto supply-chain only; aligns with declined external audit item |

## Layout

| Path | Role |
|------|------|
| `supply-chain/config.toml` | Vet config + version-pinned `[[exemptions.*]]` |
| `supply-chain/audits.toml` | Local audit entries (empty at bootstrap) |
| `supply-chain/imports.lock` | Import lock (empty until mozilla/universal wired) |

## Maintainer workflow

```sh
. scripts/dev-env.sh
cargo install cargo-vet --locked   # once, into ./.toolchain/cargo/bin

cargo vet                          # must pass before release
just audit-ready                   # includes vet when installed
```

After `cargo update` or new deps:

```sh
cargo vet                          # fails if new crate/version unvetted
cargo vet regenerate-exemptions    # refresh pinned exemptions (review diff!)
# or: cargo vet certify <crate>     # prefer for crypto-adjacent deps
```

## Crypto-adjacent policy (C3 reinforcement)

Prefer **audit entries** over exemptions for: `argon2`, `chacha20poly1305`, `hkdf`, `hmac`,
`sha2`, `subtle`, `secrecy`, `zeroize`. Exemptions at bootstrap are acceptable; shrink over time.

## References

- `research/security_coverage_gaps.md` §D2
- `docs/specs/UC-13-verifiable-releases.md` — M9 row
- `deny.toml` — parallel supply-chain policy
- [cargo-vet book](https://mozilla.github.io/cargo-vet/)
