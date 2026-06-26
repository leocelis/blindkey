# Post-quantum posture — Research (security-gap review P2)

> **Task:** Publish honest PQ posture + crypto-agility statement (gap E1).

## Problem (gap E1)

Users and auditors ask whether Vault is "quantum-safe." The symmetric core is Grover-resilient;
optional asymmetric hardware stanzas have theoretical store-now-decrypt-later (SNDL) exposure.
No single doc stated policy, agility path, or v2 reservation.

## Policy (shipped as docs)

| Layer | PQ impact | Vault v1 posture |
|-------|-----------|------------------|
| Payload AEAD (XChaCha20-Poly1305) | Grover → ~128-bit from 256-bit keys | **Adequate** for password-vault lifetime |
| KDF (Argon2id) + HMAC/HKDF-SHA-256 | Same | **Adequate** |
| Password stanza wrap (XChaCha20) | Same | **Adequate** |
| FIDO2 P-256 / SE secp256r1 (optional) | Shor breaks ECDH/ECDSA class | **SNDL in principle**; wraps data key only; password path remains |
| TPM / YubiKey HMAC | Symmetric on device | **Device-dependent** |

**We do not claim NIST PQ compliance or ML-KEM in v1.**

## Crypto agility (C7)

- `format_version` + typed `kdf_algorithm` / stanza records allow new algorithms in a **v2** cycle.
- ADR-0005 freezes v1 layout; hybrid-PQ wrap (e.g. ML-KEM + classical) is explicitly deferred to
  a future ADR + `format_version` bump + migration.

## References

- `docs/guides/post-quantum-posture.md` — user-facing canonical
- `docs/CRYPTO.md` — engineer summary
- `docs/FILE_FORMAT.md` — versioned header fields
- `docs/adr/0005-format-v1-freeze.md` — v2 PQ reservation
- NIST SP 800-208 (hybrid key establishment) — informative for v2 design
