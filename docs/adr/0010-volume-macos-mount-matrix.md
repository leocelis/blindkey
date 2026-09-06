# ADR-0010: UC-25 macOS mount provider matrix

- **Status:** Accepted
- **Date:** 2026-07-21
- **Spec:** [UC-25](../specs/UC-25-local-encrypted-volume.md) · Constraint **C72**
- **Related:** [ADR-0009](0009-volume-mount-blindkey-fuse.md)

## Context

macOS has no single FUSE story: macFUSE 5 offers an FSKit backend (~15.4+), Fuse-T offers
NFS/SMB backends (all current macOS) and native FSKit only on **macOS 26+**, and kernel
extensions are increasingly hostile. Cryptomator's Dokany/WebDAV lessons apply.

## Decision

1. **Preferred (macOS 15.4+):** macFUSE with `-o backend=fskit` when available.
2. **Fallback (older / no macFUSE):** Fuse-T NFS/SMB userspace path.
3. **Fuse-T native FSKit:** only when running macOS **26+**; embedding Fuse-T requires a
   **commercial license** review before shipping in Blindkey.app — personal use alone is not
   a distribution license. **Decided (2026-07-21):** do **not** embed/redistribute Fuse-T
   commercially in Blindkey.app without a cleared commercial license; prefer **macFUSE FSKit on
   macOS 15.4+** as the shipped provider; **no kernel extension is a v1 hard requirement**. Until
   legal clears Fuse-T terms, ship depends on the user's own macFUSE/Fuse-T install rather than a
   bundled Fuse-T binary.
4. **Hard requirement:** no kernel extension as a v1 must-have.
5. **Degraded only:** WebDAV-localhost fallback (document as degraded semantics).
6. **Not crypto core:** `hdiutil` encrypted sparsebundle remains a stopgap UX demo only —
   never Blindkey's AEAD data plane.
7. **Windows:** out of v1 GUI/mount scope; future WinFsp (Dokany forbidden as primary).

## Consequences

- Ship docs must state the matrix honestly (perf vs dm-crypt; residual cleartext while mounted).
- CI primary mount tests remain **Linux `fuser`**; macOS mount is HITL / Phase C packaging.
- License gate blocks embedding Fuse-T until Leo/legal clears commercial terms.
- **Shipped (2026-09):** GUI Blindfolder uses `MaterializedMount` (cleartext working folder) by
  default on macOS. Checkin uses real `NSFileCoordinator` `ForReplacing` via `blindkey-sys`
  (objc2). Linux GUI enables FUSE with default `volume-mount`. Optional macOS live mount:
  user installs [macFUSE](https://macfuse.io), then rebuilds with `--features macos-fuse`
  (links libfuse at build time; runtime probe via `macfuse_available`). Blindkey never
  embeds/redistributes macFUSE or Fuse-T. kill-9 leftover cleartext is adopted on unlock
  (`open_or_adopt`), never wiped.
