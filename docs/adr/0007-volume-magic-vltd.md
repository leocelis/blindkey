# ADR-0007: Freeze UC-25 volume magic `VLTD` and extension `.vltd`

- **Status:** Accepted
- **Date:** 2026-07-21
- **Deciders:** maintainers (see [GOVERNANCE.md](../../GOVERNANCE.md))
- **Spec:** [UC-25](../specs/UC-25-local-encrypted-volume.md) · Constraint **C67**
- **Research:** [encrypted_volume_mount_research.md](../../research/encrypted_volume_mount_research.md)

## Context

UC-25 introduces a third Blindkey container kind beside the credential vault (`VLT\0` / `.vlt`)
and sealed archives (`VLTF` / `.vltf`). ADR-0005 freezes vault format v1 layout; it does not
allocate a magic for live volumes. Without a frozen magic and extension:

- implementers risk inventing a longer tag (e.g. `VLTD1`) that breaks the 4-byte peer of `VLTF`;
- CLI/GUI kind dispatch and wrong-kind errors have no stable wire identity;
- C67's "distinct container" requirement stays prose-only.

Phase A1 already landed `MAGIC_VLTD` and `ContainerKind::Volume` in `blindkey-core`. This ADR
ratifies that choice so later payload work cannot silently rename the kind.

## Decision

1. **Magic:** exactly four bytes `b"VLTD"` (`0x56 0x4C 0x54 0x44`), exposed as
   `blindkey_core::MAGIC_VLTD`.
2. **Kind:** `ContainerKind::Volume` maps to that magic via `magic()` / `from_magic()`.
3. **Extension:** on-disk files use **`.vltd`** (lowercase). Other spellings (e.g. `.vltv`) are
   rejected as product surface — not as a second magic.
4. **Hygiene (ADR-0005):** `.vlt` / `.vltf` byte layouts and magics are unchanged. Wrong-kind
   open yields `Error::WrongContainerKind` (not a format oracle).
5. **Out of scope here:** volume payload / AEAD block layout, Merkle algorithm, FUSE crate
   shape, and macOS mount provider — separate Gate-0 ADRs.

## Consequences

### Positive

- Kind table and C67 tests have a frozen oracle matching shipped consts.
- Peek/CLI dispatch can branch on `MAGIC_VLTD` without bikeshedding.
- Public docs can state magic/extension as decided, not draft.

### Negative / follow-ups

- Changing magic later requires a superseding ADR and a migration story (same bar as ADR-0005).
- Payload format inside `.vltd` remains unfrozen until UC-25 Phase A2+ lands and is accepted.

## Verification

- `MAGIC_VLTD == *b"VLTD"` and `ContainerKind::Volume.magic()` in `crates/blindkey-core`.
- `cargo test -p blindkey-core --test volume_constraints` (`c67_*`).
- Header unit tests: `vltd_magic_round_trip`, `volume_wrong_kind_rejected`.
