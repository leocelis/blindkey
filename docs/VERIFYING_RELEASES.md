# Verifying Releases

A security tool you can't verify is a security tool you have to *trust*. Vault releases are
**maintainer-built** from a tagged commit with a **pinned toolchain** (`rust-toolchain.toml`) and
**SHA-256 checksums** published alongside each binary. *(constraint C34)*

> Vault **1.0.0**. There is no automated cosign/SLSA pipeline — maintainers build
> locally per [RELEASE.md](RELEASE.md). Latest release: [`v1.0.0`](https://github.com/leocelis/vault/releases/tag/v1.0.0)
> (macOS x86_64 binary + SHA256SUMS). Other platforms: [INSTALL.md](INSTALL.md).

## 1. Verify the checksum

```sh
# Download the binary and SHA256SUMS from the GitHub Release, then:
shasum -a 256 -c SHA256SUMS.txt
```

## 2. Verify the signed git tag (optional)

Release tags should be GPG-signed by a maintainer:

```sh
git fetch --tags
git tag -v v1.0.0
```

## 3. Reproduce the build yourself

Because the toolchain is pinned and we build `--locked`, you can rebuild bit-for-bit and compare:

```sh
git checkout vX.Y.Z
./scripts/reproducible-build.sh
shasum -a 256 target/release/vault
# Compare against the published checksum.
```

## 4. (Optional) Verify embedded SBOM (`cargo auditable`)

If the release binary was built with `cargo auditable`, the dependency inventory is embedded:

```sh
cargo install cargo-audit auditable2cdx --locked   # once
cargo audit bin vault   # advisory scan of embedded deps
```

If any step fails, **do not run the binary** — open a security report (see [SECURITY.md](../SECURITY.md)).
