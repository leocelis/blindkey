# Contributing to Vault

Thanks for your interest! Vault is a security tool, so we hold contributions to a high bar —
not to gatekeep, but because the cost of a subtle bug here is a leaked credential. This guide
makes that bar explicit and reachable.

## First: how Vault is built (read this)

Vault uses **Intent-Verified Development (IVD)**: the design lives as testable constraints in
[`vault_intent.yaml`](vault_intent.yaml) *before* code is written. Every security property is a
numbered constraint (`C1`…`C27`) with a `test:` field. When you implement or change behavior:

1. **Read the relevant constraint(s)** in `vault_intent.yaml`.
2. **Implement to satisfy them** — for security-critical work, in the segment order in the intent.
3. **Add or update the test** that proves the constraint holds.
4. In your PR, **state which constraints your change touches** (PASS / changed / new).

If you're proposing new behavior with no constraint yet, open a discussion first — we add the
constraint (with a test) before the implementation. See [research/security_coverage_gaps.md](research/security_coverage_gaps.md)
for candidate areas (C28+) we already know we want.

## Ground rules for a security codebase

- **No custom cryptography.** Use the approved audited libraries (libsodium / RustCrypto). If you
  think you need a new primitive, you don't — open an issue.
- **No `unsafe`** outside the designated, reviewed crypto-FFI module.
- **No secrets in `Vec<u8>`/`String`.** Use the `Secret`/`Zeroizing` wrappers (constraint C11).
- **No `==` on secret bytes.** Use constant-time comparison (`subtle`, constraint C25).
- **Never log, print, or serialize secret material.** Not even in `Debug`.
- **Never accept a secret as a command-line argument** (constraint C32 candidate).

## Development setup

```sh
# Toolchain is pinned in rust-toolchain.toml.
git clone https://github.com/leocelis/vault
cd vault

# We use `just` for common tasks (see the justfile):
just            # list tasks
just check      # fmt + clippy + test
just audit      # cargo audit + cargo deny
just fuzz       # smoke-run the fuzz targets
```

If you don't have `just`, the equivalent cargo commands are in the [`justfile`](justfile).

## Pull request checklist

- [ ] `just check` passes (fmt, clippy with `-D warnings`, tests).
- [ ] `just audit` passes (no new advisories or license violations).
- [ ] New/changed behavior has a test, and the test maps to a constraint.
- [ ] The PR description lists affected constraints.
- [ ] No secret material can reach a log, `Debug`, stdout-by-default, or an argv.
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
      (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `security:`).
- [ ] You agree to the dual MIT/Apache-2.0 license (see [COPYRIGHT](COPYRIGHT)).

## Reporting vulnerabilities

Do **not** use issues or PRs. Follow [SECURITY.md](SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree
to uphold it.
