# ADR-0005: Freeze on-disk format at version 1

- **Status:** Accepted
- **Date:** 2026-06-26
- **Deciders:** maintainers (see [GOVERNANCE.md](../../GOVERNANCE.md))
- **Research:** [research/format_freeze_research.md](../../research/format_freeze_research.md)

## Context

Blindkey's `.vlt` layout has been implemented as `format_version = 1` since CP-1. CP-7 is green
(60/60 constraints PASS). Pre-release docs still warned that the on-disk format "may change
before 1.0", which was accurate during alpha but is now misleading: the byte layout, parser
hardening (C30), and verification pipeline (C7–C10) are complete and fuzz-tested.

Users on `0.1.0-alpha.*` need a clear promise: vault files they create today will open on
future 1.x releases without a breaking migration.

## Decision

1. **`format_version = 1` is frozen** as of this ADR. `FORMAT_VERSION` in `blindkey-core` remains
   `1` until a future ADR explicitly supersedes this one.
2. **Breaking layout changes** require, per [GOVERNANCE.md](../../GOVERNANCE.md):
   - a new ADR superseding ADR-0005,
   - two-maintainer sign-off,
   - incrementing `format_version`,
   - and a documented migration path (tool or export/re-import procedure) before default
     writers emit the new version.
3. **User-facing docs** distinguish two independent facts:
   - **Format:** v1 is stable (this ADR).
   - **Software maturity:** Blindkey remains pre-1.0 and not independently audited until the
     `1.0.0` release ceremony and optional third-party audit.
4. **Backward compatibility:** vault files written at `format_version = 1` on any
   `0.1.0-alpha.*` release MUST remain openable by subsequent 1.x releases without migration.

## Consequences

### Positive

- Users and integrators can rely on v1 `.vlt` files across alpha → 1.0 upgrades.
- Removes a self-inflicted trust gap ("format may change") while keeping honest unaudited warnings.
- Aligns documentation with CP-1 completion noted in [ROADMAP.md](../../ROADMAP.md).

### Negative / accepted

- Future improvements that require breaking layout (e.g. Padmé padding default-on, hybrid-PQ wrap
  reservation) must wait for a v2 format cycle with migration tooling.
- Format freeze does not freeze CLI/API surfaces or constraint count — only the on-disk byte layout
  governed by C7–C10 and [FILE_FORMAT.md](../FILE_FORMAT.md).

## References

- Constraint **C7** — [blindkey_intent.yaml](../../blindkey_intent.yaml)
- [FILE_FORMAT.md](../FILE_FORMAT.md) — human-readable v1 spec
