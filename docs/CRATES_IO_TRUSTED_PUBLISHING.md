# crates.io publishing (CP-6)

Vault publishes **`vault-cli`** (and its path dependencies) **manually** from a maintainer machine
after the local quality gate passes. There is no **crates.io Trusted Publishing** workflow yet —
manual `cargo login` + `cargo publish` only (see below). A minimal CI workflow runs `just check`
on push; it does not publish crates.

## One-time setup (maintainer)

1. Reserve crate names on [crates.io](https://crates.io): `vault-sys`, `vault-core`, `vault-hardware`, `vault-clip`, `vault-cli`.
2. Log in locally: `cargo login` (one-time API token from crates.io account settings).
3. Ensure `[workspace.package] version` in root `Cargo.toml` matches the git tag you are shipping.

## Publish order

Dependency order matters — publish leaf crates first:

```sh
./scripts/publish-crates.sh
# equivalent:
cargo publish --locked -p vault-sys
cargo publish --locked -p vault-core
cargo publish --locked -p vault-hardware
cargo publish --locked -p vault-clip
cargo publish --locked -p vault-cli
```

Dry-run first if unsure: `cargo publish --dry-run -p vault-cli`.

## User install path

```sh
cargo install vault-cli --locked
```

Or build from source / download a GitHub Release binary — see [INSTALL.md](INSTALL.md).
