# Architecture Decision Records (ADRs)

We record significant, hard-to-reverse decisions as ADRs (see ADR-0001 for the rationale).
Each ADR is immutable once accepted; supersede rather than edit.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-aead-xchacha20-poly1305-stream.md) | XChaCha20-Poly1305 STREAM for payload AEAD | Accepted (payload-key salt superseded by 0003) |
| [0003](0003-nonce-prefix-payload-key-salt.md) | Per-body-write nonce_prefix as payload-key HKDF salt | Accepted (2026-06-26) |
| [0004](0004-data-key-keyed-hmacs.md) | Data-key-keyed HMACs; master_seed bound to body writes | Accepted (2026-06-26) |
| [0005](0005-format-v1-freeze.md) | Freeze on-disk format at version 1 | Accepted (2026-06-26) |
| [0006](0006-agent-broker-scaffold.md) | Agent broker scaffold (S-13) | Accepted (scaffold, 2026-06-26) |
| [0007](0007-volume-magic-vltd.md) | Freeze UC-25 volume magic `VLTD` + extension `.vltd` | Accepted (2026-07-21) |
| [0008](0008-volume-merkle-hmac-sha256.md) | UC-25 Merkle tree = HMAC-SHA-256 (v1) | Accepted (2026-07-21) |
| [0009](0009-volume-mount-blindkey-fuse.md) | Mount adapter in `blindkey-fuse` crate | Accepted (2026-07-21) |
| [0010](0010-volume-macos-mount-matrix.md) | macOS mount provider matrix | Accepted (2026-07-21) |
