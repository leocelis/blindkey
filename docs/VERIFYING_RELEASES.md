# Verifying Releases

A security tool you can't verify is a security tool you have to *trust*. Vault releases are
**reproducible**, **keylessly signed with Sigstore cosign**, and accompanied by **SLSA build
provenance** and SHA-256 checksums. Here's how to check what you downloaded. *(constraint C34)*

> Applies to tagged releases from `.github/workflows/release.yml`. Vault is **functional
> pre-1.0** — publish your first tag (`v0.1.0` or similar) to exercise this flow; until then,
> build from source per [INSTALL.md](INSTALL.md).

## 1. Verify the checksum

```sh
# Download the binary and its SHA256SUMS file from the GitHub Release, then:
shasum -a 256 -c SHA256SUMS-x86_64-unknown-linux-musl.txt
```

## 2. Verify the cosign signature (keyless / Sigstore)

Each artifact ships with a `.sig` signature and a `.pem` certificate. Cosign verifies the artifact
was signed by Vault's GitHub Actions release workflow via its OIDC identity:

```sh
cosign verify-blob \
  --certificate vault-x86_64-unknown-linux-musl.pem \
  --signature   vault-x86_64-unknown-linux-musl.sig \
  --certificate-identity-regexp 'https://github.com/leocelis/vault/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  vault-x86_64-unknown-linux-musl
```

A `Verified OK` result means the binary was produced by *our* release workflow, not substituted.

## 3. Verify SLSA provenance

The release includes a `provenance` attestation (`*.intoto.jsonl`). Verify it with `slsa-verifier`:

```sh
slsa-verifier verify-artifact vault-x86_64-unknown-linux-musl \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/leocelis/vault
```

## 4. (Optional) Reproduce the build yourself

Because the toolchain is pinned (`rust-toolchain.toml`) and we build `--locked`, you can rebuild
bit-for-bit and compare:

```sh
git checkout vX.Y.Z
cargo build --release --locked --target x86_64-unknown-linux-musl
shasum -a 256 target/x86_64-unknown-linux-musl/release/vault
# Compare against the published checksum.
```

## 5. Verify embedded SBOM (`cargo auditable`)

Release binaries are built with `cargo auditable` — the dependency inventory is embedded in the
artifact. On Linux, each release also ships `vault-<tag>.cdx.json` (CycloneDX derived via
`auditable2cdx`).

```sh
cargo install cargo-audit auditable2cdx --locked   # once
cargo audit bin vault-x86_64-unknown-linux-musl    # advisory scan of embedded deps
```

If any step fails, **do not run the binary** — open a security report (see [SECURITY.md](../SECURITY.md)).
