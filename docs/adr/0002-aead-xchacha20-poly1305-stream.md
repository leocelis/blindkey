# ADR-0002: XChaCha20-Poly1305 STREAM for payload AEAD

- **Status:** Accepted
- **Date:** 2026-06-10
- **Constraint:** C1

## Context

The vault payload must be encrypted with an authenticated cipher that is safe with randomly
generated nonces, resists reorder/truncate/splice of a synced file, and releases no plaintext
before authentication. Candidates: AES-256-GCM, AES-GCM-SIV, ChaCha20-Poly1305 (IETF),
XChaCha20-Poly1305.

## Decision

Use **XChaCha20-Poly1305 in STREAM mode** (64 KiB chunks; per-chunk nonce = 11-byte counter +
1-byte final marker; payload key via HKDF-SHA-256 over the random data key).

## Rationale

- **192-bit nonce** → random nonces are collision-safe at scale (unlike AES-GCM's 96-bit nonce,
  whose reuse is catastrophic — Joux forbidden attack).
- **STREAM** makes each chunk location-bound: a chunk cannot be reordered, truncated, or spliced in
  from another ciphertext without an authentication failure (Tink STREAM property).
- **Tag-before-release**: no plaintext byte is exposed before its Poly1305 tag verifies (prevents
  EFail-style partial-plaintext leaks).
- Available in audited libraries (`chacha20poly1305` / libsodium) — satisfies "no custom crypto" (C3).

## Alternatives rejected

- **AES-256-GCM** — nonce-reuse cliff; 96-bit nonce too small for random generation.
- **AES-GCM-SIV** — acceptable (nonce-misuse-resistant) but thinner audited-library coverage.
- **ChaCha20-Poly1305 (IETF)** — fine for counter nonces, but 96-bit nonce discourages random use.

## Consequences

The body is layered: STREAM chunks (encryption unit) wrapped by the HmacBlockStream (integrity unit,
ADR/Constraint C10). See [docs/FILE_FORMAT.md](../FILE_FORMAT.md).
