# crates.io publishing (CP-6)

> **BLOCKED — name collision (found in OSS-readiness audit, 2026-07-17):** `blindkey`, `blindkey-cli`,
> and `blindkey-core` are already published on crates.io by unrelated projects (`blindkey` is a
> HashiCorp Blindkey client at v11+; `blindkey-cli`/`blindkey-core` are a separate 2023 project). None of
> the publish commands below will succeed under the current crate names. This blocks `cargo
> install blindkey-cli` everywhere it's promised (SECURITY.md, README, this doc) until the project
> is renamed. Do not attempt to publish until a new name is chosen — see the audit findings for
> the full rationale (SEO collision, and `blindkey-agent` collides with HashiCorp's `blindkey agent`
> subcommand).

Blindkey publishes **`blindkey-cli`** (and its path dependencies) **manually** from a maintainer machine
after the local quality gate passes. There is no **crates.io Trusted Publishing** workflow yet —
manual `cargo login` + `cargo publish` only (see below). A minimal CI workflow runs `just check`
on push; it does not publish crates.

## One-time setup (maintainer)

1. Reserve crate names on [crates.io](https://crates.io): `blindkey-sys`, `blindkey-core`, `blindkey-hardware`, `blindkey-clip`, `blindkey-cli`.
2. Log in locally: `cargo login` (one-time API token from crates.io account settings).
3. Ensure `[workspace.package] version` in root `Cargo.toml` matches the git tag you are shipping.

## Publish order

Dependency order matters — publish leaf crates first:

```sh
./scripts/publish-crates.sh
# equivalent:
cargo publish --locked -p blindkey-sys
cargo publish --locked -p blindkey-core
cargo publish --locked -p blindkey-hardware
cargo publish --locked -p blindkey-clip
cargo publish --locked -p blindkey-cli
```

Dry-run first if unsure: `cargo publish --dry-run -p blindkey-cli`.

## User install path

```sh
cargo install blindkey-cli --locked
```

Or build from source / download a GitHub Release binary — see [INSTALL.md](INSTALL.md).
