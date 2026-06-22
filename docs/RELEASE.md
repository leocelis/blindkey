# Release checklist (CP-6 / CP-7)

## Before tagging

1. `just check` and `just audit-ready` green on `main`
2. Bump `[workspace.package] version` in root `Cargo.toml` (e.g. `0.1.0-alpha.1` or `0.1.0`)
3. Update `CHANGELOG.md` under `[Unreleased]` → new version section
4. `./scripts/check-release-version.sh v0.1.0` (dry-run the tag you will push)
5. First crates.io release only: complete [CRATES_IO_TRUSTED_PUBLISHING.md](CRATES_IO_TRUSTED_PUBLISHING.md) manual setup

## Tag and ship

```sh
git tag -s v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`.github/workflows/release.yml` then:

- Builds auditable binaries (4 targets) with reproducible env flags
- Signs with cosign, attaches SLSA provenance, publishes GitHub Release (fail-closed draft → public)
- Verifies cosign on the canonical musl binary
- Publishes crates to crates.io (Trusted Publishing)

## After release

1. Download musl artifact from GitHub Releases; run [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md) steps
2. CP-7: IVD constraint sweep → update [CONSTRAINT_INDEX.md](CONSTRAINT_INDEX.md) if needed
3. For `1.0.0`: format freeze + drop pre-1.0 banner language in README
