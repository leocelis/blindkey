# Post-quantum posture

> **Gap E1** — what Vault v1 promises about quantum-era threats and how we can evolve.

## Short answer

Vault's **symmetric** cryptography (XChaCha20-Poly1305, Argon2id, HMAC/HKDF-SHA-256) is
**post-quantum adequate** for a password vault: Grover's algorithm at most halves effective key
strength, so 256-bit keys retain roughly **128-bit** security — sufficient for decades of
offline guessing resistance when Argon2id parameters are healthy.

Vault does **not** claim NIST PQ certification and does **not** ship ML-KEM or hybrid wraps in v1.

## Optional hardware stanzas (lower practical risk)

Some optional unlock paths use **classical elliptic-curve** machinery (e.g. FIDO2 P-256,
Secure Enclave secp256r1). A future cryptographically relevant quantum computer could, in
principle, decrypt **old captures** of those wraps (store-now-decrypt-later).

In Vault v1:

- Those stanzas only wrap the **256-bit data key** — not entry plaintext directly.
- The **password stanza always remains** (C5 OR model); hardware is never the sole path.
- Practical PQ risk for most users is **low** compared to malware, weak passwords, or leaked blobs.

## Crypto agility (format v1 frozen)

The on-disk header is versioned ([FILE_FORMAT.md](../FILE_FORMAT.md)):

- `format_version` — breaking layout changes require a new version + migration (ADR-0005).
- `kdf_algorithm` — typed KDF id (v1 = Argon2id only).

New algorithms (including a future **hybrid classical + PQ wrap**, e.g. ML-KEM alongside
XChaCha20) require a **v2 format cycle**: new ADR, maintainer sign-off, migration tooling —
not a silent upgrade.

See [ADR-0005](../adr/0005-format-v1-freeze.md) consequences: hybrid-PQ wrap is an accepted
deferral until v2.

## What you should do today

1. Use a **strong master password** (Argon2id is the bottleneck, not Grover).
2. Treat **exfiltrated `.vlt` files** as long-lived ciphertext — rotate data key if compromised
   ([deletion-and-rotation.md](deletion-and-rotation.md)).
3. Do not rely on optional hardware stanzas as your **only** backup unlock path without offline
   recovery codes ([recovery-codes.md](recovery-codes.md)).

## See also

- [CRYPTO.md](../CRYPTO.md) — primitive choices
- [THREAT_MODEL.md](../THREAT_MODEL.md) — adversary model and residual risks
