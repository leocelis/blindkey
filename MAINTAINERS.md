# Maintainers

Vault is maintained by a small team that practices four-eyes review on all security-critical code.

| Maintainer | Role | GitHub |
|-----------|------|--------|
| Leo | Founder / lead maintainer / code owner | `@leocelis` |
| Juan | Maintainer | `@jgm972` |

## Responsibilities

- Changes to `crates/vault-core/`, the file format, the threat model, `SECURITY.md`, and
  CI/release workflows require review from the code owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).
- Security reports are triaged jointly per [SECURITY.md](SECURITY.md).
- Releases are signed; maintainers hold signing identities (see
  [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md)).

## Decision-making

See [GOVERNANCE.md](GOVERNANCE.md). In short: lazy consensus for routine changes, code-owner
sign-off for anything touching cryptography, the file format, or release integrity.

## Becoming a maintainer

Sustained, high-quality contributions plus demonstrated judgment on security tradeoffs. A new
maintainer is added by unanimous agreement of the existing maintainers.
