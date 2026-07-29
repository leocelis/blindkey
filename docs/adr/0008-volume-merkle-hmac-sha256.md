# ADR-0008: UC-25 Merkle tree uses HMAC-SHA-256 (not BLAKE3) for v1

- **Status:** Accepted
- **Date:** 2026-07-21
- **Spec:** [UC-25](../specs/UC-25-local-encrypted-volume.md) · Constraint **C70**
- **Related:** [ADR-0004](0004-data-key-keyed-hmacs.md) (data-key-keyed HMACs)

## Context

UC-25 requires a Merkle or keyed MAC tree over AEAD block tags so cut-paste / rewind of
ciphertext fails closed. Two candidates were open: **HMAC-SHA-256** (already in
`blindkey-core`) vs **BLAKE3** (faster, new dependency).

## Decision

1. **v1 Merkle leaves and internal nodes use HMAC-SHA-256** keyed by `mac_key`
   (HKDF-derived from the volume master key).
2. Leaf preimage: `block_id ‖ version ‖ tag` (little-endian ids; 16-byte Poly1305 tag).
3. Root lives in the authenticated volume header (dual-copy).
4. **BLAKE3 is deferred** — may appear in a later ADR only after a measured need and
   RustCrypto-quality dependency review (C3).

## Consequences

- Zero new crypto crates for the tree.
- Aligns with ADR-0004 culture (HMAC from keyed material, not bare SHA of ciphertext).
- BLAKE3 adopters must supersede this ADR; v1 `.vltd` readers stay HMAC-only.
