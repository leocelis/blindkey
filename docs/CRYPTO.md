# Cryptographic Design

This is a reader's summary. The **authoritative, testable** specification is
[vault_intent.yaml](../vault_intent.yaml) (constraints C1–C6, C9–C10, C25); the research rationale
is in [research/vault_spec.md](../research/vault_spec.md).

## Primitives (audited libraries only — constraint C3)

| Purpose | Primitive | Crate |
|---------|-----------|-------|
| Payload AEAD | XChaCha20-Poly1305, STREAM (64 KiB chunks) | `chacha20poly1305` |
| Password KDF | Argon2id (m=64 MiB, t=3, p=4 default) | `argon2` |
| Key wrapping / derivation | HKDF-SHA-256 | `hkdf` |
| Header & block integrity | HMAC-SHA-256 | `hmac`, `sha2` |
| Constant-time comparison | `subtle::ConstantTimeEq` | `subtle` |
| Randomness | OS CSPRNG | `getrandom` |

**No custom cryptography. Ever.** (C3) If a primitive isn't in an audited library, we don't ship it.

## Key hierarchy

```
master password ──Argon2id(salt, m,t,p)──▶ master_key
                                             │
                 HKDF(info="vault-pw-wrap")  ▼
                                          wrapping_key ──unwrap──▶ data_key (256-bit, random)
                                                                     │
                          HKDF(salt=nonce_prefix, info="vault-payload-v1")   ▼
                                                              payload_key ──STREAM──▶ entries
```

- The **data key** is random per vault (CSPRNG), never derived from the password, never stored in
  plaintext (C4). Changing the password re-wraps one stanza; the payload is untouched.
- **Any-of-N stanzas**: password (always present) + optional second factors. **v1 ships** YubiKey
  challenge-response and keyfile **2FA** (required-both AND model). **Deferred:** FIDO2 / TPM /
  Secure Enclave / DPAPI — file format and mocks exist; live device FFI is S-8a/S-8c ([hardware
  factor status](guides/hardware-factor-status.md)). Optional OR-unlock stanzas (lose hardware →
  password still works) apply to future factors per C5.

## Why these choices (the short version)

- **XChaCha20 over AES-GCM**: 192-bit nonce → safe random nonces at scale; no catastrophic
  nonce-reuse cliff. STREAM chunks are location-bound (no reorder/truncate/splice).
- **Argon2id over Argon2d/PBKDF2**: memory-hard *and* side-channel-resistant (the KeePassXC auditor's
  explicit recommendation). The **floor is enforced on every open** so a downgraded file is caught;
  the **ceiling** (also C2) rejects hostile/overflowing params *before* any allocation — necessarily
  before the keyed header HMAC, which can't be verified until the KDF has run.
- **NFC normalization of the master password** (C2): macOS keyboards commonly emit NFD where Linux
  emits NFC; without normalization the same typed password derives different keys per platform.
- **KDBX-4-style integrity**: unauthenticated `SHA-256(header)` for fast corruption detection, plus
  a **data-key-keyed** `HMAC-SHA-256(header)` verifiable on every unlock path — including
  hardware-only — and stable across password rotation (G0.2). KDF downgrade is caught by the
  password stanza's AEAD tag (tampered params ⇒ wrong wrapping key ⇒ unwrap fails).

## What we deliberately do *not* do

- No deterministic per-entry encryption (leakage-abuse attacks — Grubbs et al.).
- No server-supplied or compiled-in KDF params — the **file** is authoritative (C8).
- No `memset`/`memzero` for zeroization — `zeroize`'s volatile write + fence only (C11).
- No network calls, telemetry, or update checks (C23).

## Post-quantum posture

The symmetric core (XChaCha20-Poly1305, Argon2id, HMAC/HKDF-SHA-256) retains ~128-bit security
under Grover — adequate for a password vault. Optional asymmetric stanzas (FIDO2 P-256, Secure
Enclave secp256r1) wrap only the data key; the password path always remains (C5).

**Canonical statement:** [guides/post-quantum-posture.md](guides/post-quantum-posture.md).

**Agility:** `format_version` and typed algorithm ids ([FILE_FORMAT.md](FILE_FORMAT.md)) allow
new primitives in a future format version. v1 is frozen (ADR-0005); hybrid-PQ wrap (e.g. ML-KEM
alongside classical seal) is reserved for a v2 cycle with migration — not shipped in 1.0.
