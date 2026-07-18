# crates.io publishing

The workspace publishes to crates.io on a **published GitHub Release**, via
[`.github/workflows/publish-crates.yml`](../.github/workflows/publish-crates.yml), using
**crates.io Trusted Publishing** (OIDC) — no long-lived API token is stored in the repo.

> The old `vault` / `vault-cli` / `vault-core` names were taken on crates.io by unrelated
> projects, which is what drove the rename to Blindkey. The `blindkey-*` names are free.

## One-time maintainer setup

1. **Claim the names.** The first publish of a brand-new crate name may need a one-time
   `cargo login` + `cargo publish` (or `cargo publish --dry-run` then publish) to register
   the name to your account. Do this in dependency order (leaf crates first):
   `blindkey-sys` → `blindkey-core` → `blindkey-hardware` → `blindkey-clip` →
   `blindkey-agent` → `blindkey-cli`.
2. **Add a Trusted Publisher** for each crate on crates.io (crate settings → *Trusted
   Publishing*): repository `leocelis/blindkey`, workflow `publish-crates.yml`, environment
   `crates-io`. After this, CI publishes with no stored token.
3. **Create the `crates-io` environment** in the repo settings (optionally require reviewers)
   so the publish job is gated.

## How a release publishes

1. Push a `v*` tag → [`release.yml`](../.github/workflows/release.yml) builds the
   cross-platform binaries and opens a **draft** GitHub Release.
2. The maintainer reviews (and signs/notarizes the macOS binary), then **publishes** the
   release.
3. `publish-crates.yml` fires on `release: published`, mints a short-lived token via OIDC,
   and runs `cargo publish` for each crate in dependency order.

`scripts/publish-crates.sh` remains available for a fully manual publish from a maintainer
machine if ever needed.

## User install path

```sh
cargo install blindkey-cli --locked   # installs the `blindkey` binary
```

Or download a signed GitHub Release binary, or `brew install leocelis/tap/blindkey` — see
[INSTALL.md](INSTALL.md).
