# v1.0.0 Release Research — security-gap review P0 item 2 (June 2026)

> **Card:** Trello (internal ref) · checklist: Tag v1.0.0
> **Prerequisite:** Format v1 frozen (ADR-0005) ✅

## What this task requires

Per `docs/RELEASE.md` and the checklist:

1. `just check` + `just audit-ready` green on the release commit
2. Bump `[workspace.package] version` → `1.0.0`
3. CHANGELOG: `[Unreleased]` → `[1.0.0]` section
4. `./scripts/check-release-version.sh v1.0.0`
5. Maintainer-local: reproducible build, SHA256SUMS, signed tag, GitHub Release

## Preconditions (verified)

| Gate | Status |
|------|--------|
| CP-7 constraint sweep | 60/60 PASS (2026-06-25) |
| Format freeze | ADR-0005 (2026-06-26) |
| CP-5 CLI | stanzas + exit 7 shipped |
| CP-6 scripts | `reproducible-build.sh`, `check-release-version.sh` exist |

## User-facing copy at 1.0.0 (RELEASE.md §After release)

**Drop:** “pre-1.0” / “pre-alpha” banner language in README and install paths.

**Keep:** honest “not independently third-party audited” — external audit is security-gap review P1, optional per `THIRD_PARTY_AUDIT.md`.

| Surface | Before | After 1.0.0 |
|---------|--------|-------------|
| README badge | pre-1.0 / unaudited | v1.0.0 / unaudited |
| CLI notice | “pre-1.0 and not independently audited” | “not had an independent third-party security audit” |
| GUI banner (C50) | “Pre-1.0 — no independent…” | “Not third-party audited — keep backup” |
| SECURITY.md | functional pre-1.0 | v1.0.0 supported; alpha upgrade path |

## Version bump scope

- Root `Cargo.toml` `[workspace.package] version`
- Path dependency `version = "…"` in crate manifests (semver for crates.io)
- `Cargo.lock` (regenerate via `cargo build`)
- User docs: README install URLs, INSTALL, VERIFYING_RELEASES, SECURITY table

**Out of scope (avoid mass churn):** UC spec headers still saying “implemented pre-1.0” — historical; update on next spec pass.

## Leo-only steps (not automated here)

Per `GOVERNANCE.md` / internal governance Leo-only actions:

```sh
git tag -s v1.0.0 -m "v1.0.0"
git push origin v1.0.0
./scripts/reproducible-build.sh
gh release create v1.0.0 …
```

## Recommendation

Ship repo-side 1.0.0 prep in one PR/commit; run `audit-ready` locally; Leo runs tag + GitHub Release when ready.
