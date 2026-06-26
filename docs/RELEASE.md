# Release checklist (CP-6 / CP-7)

Releases are **maintainer-built** (binaries, checksums, signed tags). The authoritative gate before
tagging is local: `just check` and `just audit-ready`. A minimal GitHub Actions workflow
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) mirrors `just check` on push — free
tier on public repos; the local gate still wins before every release.

## Before tagging

1. `just check` and `just audit-ready` green on `main`
2. Bump `[workspace.package] version` in root `Cargo.toml` (e.g. `0.1.0-alpha.1` or `0.1.0`)
3. Update `CHANGELOG.md` under `[Unreleased]` → new version section
4. `./scripts/check-release-version.sh v0.1.0` (dry-run the tag you will push)

## Build and publish (maintainer-local)

```sh
# Reproducible release binary (C34)
./scripts/reproducible-build.sh

# SHA-256 checksums for upload
shasum -a 256 target/release/vault > SHA256SUMS.txt

# Optional: macOS app bundle
./scripts/bundle-macos.sh

# Signed git tag
git tag -s v0.1.0 -m "v0.1.0"
git push origin v0.1.0

# GitHub Release (upload binaries + SHA256SUMS manually)
gh release create v0.1.0 target/release/vault SHA256SUMS.txt --notes-file CHANGELOG.md

# crates.io (manual; see CRATES_IO_TRUSTED_PUBLISHING.md)
./scripts/publish-crates.sh   # or cargo publish -p … in dependency order
```

## After release

1. Verify checksums on the downloaded artifact match your local build
2. CP-7: IVD constraint sweep → update [CONSTRAINT_INDEX.md](CONSTRAINT_INDEX.md) if needed
3. **v1.0.0 shipped (repo):** format freeze done ([ADR-0005](adr/0005-format-v1-freeze.md)); post-1.0
   copy in README. Maintainer publishes signed tag + GitHub Release.

See [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md) for what users can check today.
