# Maintainers

Vault is maintained by:

| GitHub | Security contact |
|--------|------------------|
| `@leocelis` | [leo@leocelis.com](mailto:leo@leocelis.com) |
| `@jgm972` | — |

Path-level review authority is defined in [`.github/CODEOWNERS`](.github/CODEOWNERS), not
here — see [GOVERNANCE.md](GOVERNANCE.md) for how that maps to decision tiers.

## Responsibilities

- Changes to `crates/vault-core/`, the file format, the threat model, `SECURITY.md`, and
  release scripts require review from the code owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).
- Security reports are triaged per [SECURITY.md](SECURITY.md).
- Releases are built with SHA-256 checksums (see
  [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md)).

## Decision-making

See [GOVERNANCE.md](GOVERNANCE.md). In short: lazy consensus for routine changes,
code-owner sign-off for anything touching cryptography, the file format, or release
integrity.

## Becoming a maintainer

Sustained, high-quality contributions plus demonstrated judgment on security tradeoffs.
