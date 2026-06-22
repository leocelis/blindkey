# crates.io Trusted Publishing (CP-6)

Vault publishes **`vault-cli`** (and its path dependencies) via [Trusted Publishing](https://crates.io/docs/trusted-publishing) from `.github/workflows/release.yml` — no long-lived API token in GitHub secrets.

## One-time setup (maintainer)

1. Reserve crate names on [crates.io](https://crates.io): `vault-sys`, `vault-core`, `vault-hardware`, `vault-clip`, `vault-cli`.
2. **First publish manually** (Trusted Publishing only works after the crate exists):
   ```sh
   # Bump [workspace.package] version in Cargo.toml to match the tag (e.g. 0.1.0)
   cargo publish --locked -p vault-sys
   cargo publish --locked -p vault-core
   cargo publish --locked -p vault-hardware
   cargo publish --locked -p vault-clip
   cargo publish --locked -p vault-cli
   ```
3. **Register Trusted Publisher** on each crate → Settings → Trusted Publishing:
   - Repository: `leocelis/vault`
   - Workflow: `release.yml`
   - (Optional) Environment: leave empty unless you add a GitHub `release` environment
4. Tag and push: `git tag v0.1.0 && git push origin v0.1.0` — workflow publishes automatically after GitHub Release finalizes.

## What CI does

After cosign signing + SLSA provenance attach (`finalize` job), `publish-crates`:

1. Verifies tag `vX.Y.Z` matches `Cargo.toml` workspace version (`scripts/check-release-version.sh`)
2. Obtains a ~30-minute OIDC token via `rust-lang/crates-io-auth-action@v1`
3. Publishes `vault-sys` → `vault-core` → `vault-hardware` → `vault-clip` → `vault-cli` (`scripts/publish-crates.sh`)

## User install path

```sh
cargo install vault-cli --locked
```

The **maximally verified** path remains the signed GitHub Release binary — see [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md). crates.io does not yet attach Sigstore provenance to crate files (RFC 3691 future work).
