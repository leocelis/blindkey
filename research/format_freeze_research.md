# Format Freeze Research — security-gap review P0 (June 2026)

> **Purpose:** Research backing ADR-0005 and the format-v1 freeze declaration.

## Question

What does “format freeze” mean for Blindkey when CP-1 code is already shipped?

## Findings

### Code state (verified)

| Artifact | State |
|----------|-------|
| `FORMAT_VERSION` | `1` in `crates/blindkey-core/src/lib.rs` |
| Header write path | Always emits `format_version = 1` (`vault.rs`, `header.rs`) |
| Reader policy | Rejects `format_version > 1` with `Error::NewerVersion` (C7 unit test) |
| Human spec | `docs/FILE_FORMAT.md` documents v1 layout |
| Quality gate | CP-7 green — 60/60 constraints PASS (2026-06-25) |

**Conclusion:** Byte layout is implemented and tested. Freeze is a **governance + user-communication** act, not a crypto change.

### What freeze commits to (GOVERNANCE.md tier)

Per `GOVERNANCE.md` breaking-format tier:

1. Any breaking on-disk layout change requires **`format_version` bump**.
2. Requires **ADR + two-maintainer sign-off + migration plan**.
3. Readers continue to reject unknown newer versions (C7).

### What freeze does *not* mean

| Still true after freeze | Why |
|-------------------------|-----|
| Software is **pre-1.0 / not independently audited** | Audit is optional, separate from format |
| **`1.0.0` tag not yet cut** | Checklist item 2 (release ceremony) |
| Gate 0 intent amendments pending sign-off | Process item (checklist P3) |
| API / CLI surface may evolve | Format freeze ≠ API freeze |

### User-facing language audit (pre-freeze)

Phrases to **remove** (format instability):

- README: “On-disk format may still change before 1.0”
- SECURITY.md: “on-disk format may still change before `1.0.0`”
- PRD status line: “format may change before 1.0”

Phrases to **keep** (audit / backup posture):

- CLI `PRE_RELEASE_NOTICE`: pre-1.0, not independently audited, keep backup
- GUI C50 banner: Pre-1.0, no independent security audit
- INSTALL.md: not independently audited (no format disclaimer today)

### Precedent (KeePass / KDBX)

KeePass uses an explicit **file format version** in the header; breaking changes increment version and ship migration tooling. Blindkey mirrors this via C7 + ADR process — simpler surface (single `.vlt` blob, one `format_version` u16).

### Migration policy (forward)

- **Today → 1.0.0:** `format_version = 1` vaults created on `0.1.0-alpha.*` remain readable; no migration required.
- **Hypothetical v2:** New ADR, bumped `FORMAT_VERSION`, shipped `blindkey migrate` (or documented export/re-import path) before default writers emit v2.

## Recommendation

Declare **format v1 frozen** via ADR-0005; update README/SECURITY/PRD/CHANGELOG; leave unaudited warnings intact until third-party audit (P1) and `1.0.0` tag (P0 item 2).

## Sources

| Source | Use |
|--------|-----|
| `vault/GOVERNANCE.md` | Breaking format process |
| `vault/docs/FILE_FORMAT.md` | v1 layout authority |
| `vault/ROADMAP.md` | “code done; declaration at 1.0” |
| `vault/blindkey_intent.yaml` C7 | Constraint + tests |
| KeePass KDBX format docs | Industry precedent for versioned headers |
