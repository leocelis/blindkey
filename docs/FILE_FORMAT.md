# Vault File Format (`.vlt`) — v1

> Authoritative spec: constraints **C7–C10, C18, C19** in [vault_intent.yaml](../vault_intent.yaml).
> This document is the human-readable rendering. All multi-byte integers are **little-endian**.

## Top-level layout

```
┌──────────────────── plaintext header ────────────────────┐
│ magic            [4]   0x56 0x4C 0x54 0x00  ("VLT\0")     │  C7
│ format_version   u16   = 1                                │  C7
│ vault_id         [16]  random UUIDv4, fixed at creation   │  C8  (HKDF domain salt)
│ kdf_algorithm    u8    1 = Argon2id                       │  C8
│ argon2id_m_cost  u32   KiB                                │  C2/C8  (floor & ceiling checked)
│ argon2id_t_cost  u32                                      │
│ argon2id_p_cost  u32                                      │
│ argon2id_salt    [32]  CSPRNG, fixed at creation          │  C8
│ master_seed      [32]  CSPRNG, regenerated every save     │  C8/C10
│ stanza_count     u8    1..=8                               │  C5
│ stanzas          [..]  stanza_count × stanza_record       │  C5
│ header_hash      [32]  SHA-256(all bytes above)           │  C9  (corruption, no key)
│ header_hmac      [32]  HMAC-SHA-256(above, key=HKDF(mk))  │  C9  (tamper / KDF-downgrade)
└───────────────────────────────────────────────────────────┘
┌──────────────────── encrypted body ──────────────────────┐
│ HmacBlockStream of 1 MiB blocks, each:                    │  C10
│   [hmac 32][size u32][ciphertext size]                    │
│   wrapping the XChaCha20-Poly1305 STREAM (64 KiB chunks)  │  C1
│     └─ inner header (inner stream key, regen per open)    │  C19
│     └─ vault_version  u64  (monotonic counter)            │  C16
│     └─ entries: ALL fields encrypted (incl. URLs/titles)  │  C18
└───────────────────────────────────────────────────────────┘
```

## Stanza record

```
stanza_type     u8     1=password 2=fido2 3=yubikey 4=tpm 5=keychain 6=dpapi
stanza_data_len u32    ≤ 4096
stanza_data     [len]  { wrap_nonce[24], wrapped_key[48], extra[..] }
```

`wrapped_key` is always 48 bytes = 32-byte data key + 16-byte Poly1305 tag, regardless of stanza type.
`wrapping_key = HKDF-SHA-256(ikm=<stanza secret>, salt=vault_id, info=<type label>)`.

## The only plaintext permitted

Magic + version (C7), the KDF-params block (C8), the two header integrity tags (C9), and the stanza
headers (wrapped key ciphertext). **Everything else — every entry field, the entry count, the
version counter — lives inside the AEAD body.** (C18)

## Verification order on open (never skip)

1. `header_hash` (fast, keyless) → reject corrupt files cheaply.
2. **Reject KDF params outside floor *and* ceiling** before running Argon2id (coverage-gap A1).
3. Argon2id → master key → `header_hmac` → abort on mismatch, decrypt nothing.
4. Per-block HMAC → per-chunk AEAD tag → only then release plaintext.

## Hardening rules for the parser

- Bound every length field against the remaining buffer **before** allocating.
- Reject `stanza_count > 8`, `stanza_data_len > 4096`, and any integer overflow in size math.
- The parser is **fuzzed** (`fuzz/`) and must never panic, hang, or over-allocate on hostile input.

## Versioning

`format_version` is bumped on any breaking layout change; readers reject versions newer than they
support with a clear "created by a newer version" error (C7). Breaking changes require an ADR and a
migration path (see [GOVERNANCE.md](../GOVERNANCE.md)).
