# Contributing to Blindkey

Thanks for your interest! Blindkey is a security tool, so we hold contributions to a high bar —
not to gatekeep, but because the cost of a subtle bug here is a leaked credential. This guide
makes that bar explicit and reachable.

## First: how Blindkey is built (read this)

Blindkey uses **Intent-Verified Development (IVD)**: the design lives as testable constraints in
[`blindkey_intent.yaml`](blindkey_intent.yaml) *before* code is written. Every security property is a
numbered constraint (`C1`…`C66`) with a `test:` field. When you implement or change behavior:

1. **Read the relevant constraint(s)** in `blindkey_intent.yaml`.
2. **Implement to satisfy them** — for security-critical work, in the segment order in the intent.
3. **Add or update the test** that proves the constraint holds.
4. In your PR, **state which constraints your change touches** (PASS / changed / new).

See [`docs/CONSTRAINT_INDEX.md`](docs/CONSTRAINT_INDEX.md) for where constraint tests live today.

If you're proposing new behavior with no constraint yet, open a discussion first — we add the
constraint (with a test) before the implementation. See [research/security_coverage_gaps.md](research/security_coverage_gaps.md)
for post-1.0 candidate areas beyond the current 66 constraints.

## Ground rules for a security codebase

- **No custom cryptography.** Use the approved audited libraries (libsodium / RustCrypto). If you
  think you need a new primitive, you don't — open an issue.
- **No `unsafe`** outside the one designated FFI crate, [`blindkey-sys`](crates/blindkey-sys/) (OS calls
  for `mlock`/`setrlimit`). Every other crate is `#![forbid(unsafe_code)]`.
- **No secrets in `Vec<u8>`/`String`.** Use the `Secret`/`Zeroizing` wrappers (constraint C11).
- **No `==` on secret bytes.** Use constant-time comparison (`subtle`, constraint C25).
- **Never log, print, or serialize secret material.** Not even in `Debug`.
- **Never accept a secret as a command-line argument** (constraint C31).

## Development setup

The Rust toolchain is installed **into the project**, never machine-wide — a vault's build
environment should be self-contained and reproducible, not entangled with whatever Rust is in your
home directory. We use rustup's official `RUSTUP_HOME` / `CARGO_HOME` relocation plus
`--no-modify-path`, so nothing lands in `~/.rustup`, `~/.cargo`, or your shell profiles. The exact
version and components come from [`rust-toolchain.toml`](rust-toolchain.toml) (single source of
truth). See the rustup docs for the mechanism:
[installation](https://rust-lang.github.io/rustup/installation/index.html) ·
[other / `--no-modify-path`](https://rust-lang.github.io/rustup/installation/other.html).

```sh
git clone https://github.com/leocelis/blindkey
cd blindkey

./scripts/setup-rust.sh    # one-time: installs the pinned toolchain into ./.toolchain (git-ignored)
. scripts/dev-env.sh       # activate it for this shell  (or use direnv: `direnv allow`)

# We use `just` for common tasks (see the justfile):
just            # list tasks
just check      # fmt + clippy + test
just audit      # cargo audit + cargo deny + cargo vet
just vet        # cargo vet only (supply-chain/ exemptions)
just fuzz       # smoke-run the fuzz targets
```

The toolchain lives in `./.toolchain/` (~1.2 GB, git-ignored). To remove it completely, just
`rm -rf .toolchain` — there is nothing to uninstall from your machine. If you don't have `just`,
the equivalent cargo commands are in the [`justfile`](justfile). Do **not** `curl … | sh` the
default rustup installer for this repo — that writes to your home directory and edits your shell
profiles; `scripts/setup-rust.sh` is the supported path.

## Sign off your commits (DCO)

Every commit in a PR must carry a `Signed-off-by:` trailer, certifying you wrote it (or have the
right to submit it) under the project's [MIT OR Apache-2.0](COPYRIGHT) license — the
[Developer Certificate of Origin](DCO), same text and mechanism the Linux kernel and most CNCF
projects use. It's a one-line addition, not a CLA and not a copyright transfer: you keep your
copyright, you're certifying provenance.

```sh
git commit -s -m "fix: ..."          # -s appends the trailer automatically
```

This adds `Signed-off-by: Your Name <you@example.com>` (from your git config) to the commit
message. A PR bot checks every commit; if one's missing, amend it (`git commit --amend -s`) or
add a follow-up signed-off commit — no need to open a new PR.

## Pull request checklist

- [ ] `just check` passes (fmt, clippy with `-D warnings`, tests).
- [ ] `just audit` passes (no new advisories, license violations, or unvetted deps).
- [ ] New/changed behavior has a test, and the test maps to a constraint.
- [ ] The PR description lists affected constraints.
- [ ] No secret material can reach a log, `Debug`, stdout-by-default, or an argv.
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
      (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `security:`) and are signed off
      (`git commit -s`, see [DCO](#sign-off-your-commits-dco) above).
- [ ] You agree to the dual MIT/Apache-2.0 license (see [COPYRIGHT](COPYRIGHT)).

## Reporting vulnerabilities

Do **not** use issues or PRs. Follow [SECURITY.md](SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree
to uphold it.

## Getting help

See [SUPPORT.md](SUPPORT.md) — Discussions for questions, issues for bugs, SECURITY.md for vulnerabilities.
