# ADR-0011: Volume cloud story is checkout / checkin, not live mount

- **Status:** Accepted
- **Date:** 2026-09-06
- **Spec:** [UC-30](../specs/UC-30-volume-working-copy.md) · **Amends** [UC-25](../specs/UC-25-local-encrypted-volume.md) C73 posture
- **Related:** [ADR-0009](0009-volume-mount-blindkey-fuse.md) · [ADR-0010](0010-volume-macos-mount-matrix.md)

## Context

Operators want a UC-25 `.vltd` to live in an untrusted sync folder so the brick is off-machine
when the laptop is closed. Mounting that path while the sync client is running (C73) races
partial uploads and two-writer conflict copies.

Two designs were considered:

1. Pause the sync client for the duration of the mount.
2. Copy the brick to a local non-sync working path, mount that, copy back on eject.

(1) depends on vendor APIs, fails if pause is skipped, and still writes the sync-path file
during the mount. (2) keeps C73’s invariant: the sync client never sees a mounted, changing
container.

## Decision

1. **Cloud-backed Blindfolder = UC-30 working copy.** Checkout → UC-25 mount of the copy →
   checkin via atomic replace.
2. **C73 stays:** `volume mount` of a detectable sync-root path remains unsupported.
3. **Do not** embed or require Dropbox/Drive pause.
4. **Stale remote:** if the sync-folder brick changed since checkout, checkin fails closed
   (no silent last-write-wins).
5. **macOS mount** remains ADR-0010 (Phase C). UC-30 does not ship a useful desktop flow until
   that provider exists.

## Consequences

- UC-23 `seal` remains the snapshot archive for cloud; UC-30 is the *repeatable workspace*.
- Intent gains G22 (C99–C102). Existing C73 CLI/GUI refuse tests must stay green.
- Large volumes pay a copy on open and close. Prefer hole-preserving clone
  (`clonefile` / `FICLONE`); cost tracks **allocated** bytes, not Padmé logical
  size. Dense bricks still copy in full.
