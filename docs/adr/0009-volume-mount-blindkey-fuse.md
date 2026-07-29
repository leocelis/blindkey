# ADR-0009: UC-25 mount lives in `blindkey-fuse` crate (not core feature)

- **Status:** Accepted
- **Date:** 2026-07-21
- **Spec:** [UC-25](../specs/UC-25-local-encrypted-volume.md) · Constraint **C72**

## Context

Live mount needs a FUSE-class userspace adapter (`fuser` on Linux; macOS via FSKit/Fuse-T
wrappers). Two packaging options: (a) optional feature on `blindkey-cli` / `blindkey-core`,
or (b) a thin sibling crate.

Pulling `fuser` into `blindkey-core` would enlarge the security-boundary dependency graph
for users who only want vault/seal APIs.

## Decision

1. **Crypto + virtual FS API** stay in `blindkey-core::volume` (no FUSE types).
2. **Mount adapter** lives in new workspace crate **`blindkey-fuse`**, depending on
   `blindkey-core` + `fuser` (Linux) / platform backends as phased.
3. **CLI** `blindkey volume mount|umount` depends on `blindkey-fuse` via a Cargo feature
   `volume-mount` (default **on** for desktop builds; off for minimal CI if needed).
4. The fuse crate contains **no** key unwrap, AEAD, or KDF — only `Volume` I/O + lifecycle.

## Consequences

- Core stays auditable without FUSE.
- Platforms without FUSE still compile `blindkey-core` volume create/open/peek.
- macOS packaging (Fuse-T license, FSKit) is a separate ADR (0010).
