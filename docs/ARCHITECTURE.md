# Architecture

Vault is a Cargo workspace with a deliberately small, auditable security core.

```
┌─────────────────────────────────────────────────────────────┐
│  vault-cli  (the `vault` binary)                             │
│  clap commands · clipboard/stdout delivery · prompts         │  C20–C22, C26, C27
└───────────────┬─────────────────────────────────────────────┘
                │ depends on
┌───────────────▼─────────────────────────────────────────────┐
│  vault-core  (library — the security boundary)               │
│                                                              │
│  crypto/     XChaCha20-Poly1305 STREAM · Argon2id · HKDF     │  C1–C3
│  envelope/   data key · multi-stanza OR wrapping            │  C4–C6
│  format/     header · KDF params · integrity · block stream  │  C7–C10
│  memory/     Secret/Zeroizing types · mlock · constant-time  │  C11–C13, C25
│  rollback/   monotonic counter · local state anchor          │  C16
└───────────────┬─────────────────────────────────────────────┘
                │ optional
┌───────────────▼─────────────────────────────────────────────┐
│  vault-hardware  (optional crate, feature-gated)             │
│  FIDO2 (libfido2) · TPM 2.0 · Secure Enclave · DPAPI         │  C14, C15
└─────────────────────────────────────────────────────────────┘
```

## Why this shape

- **Library/CLI split** (like `age`, `rustls`): the security-critical code (`vault-core`) is
  auditable and fuzzable in isolation, with no CLI/argument-parsing concerns in the trust boundary.
- **Hardware behind a feature gate**: a user with no FIDO2 key compiles and runs without that code
  path; hardware factors are *additive*, never required (the password stanza always unlocks — C5).
- **One trust boundary**: secrets only ever live inside `vault-core` types (`Secret<…>`,
  `Zeroizing<…>`); the CLI receives delivery *channels* (clipboard handle), not raw key material —
  the same principle that protects against AI-agent exfiltration (C27).

## Data flow: opening a vault

1. Read plaintext header; verify `SHA-256(header)` (fast corruption check — no key needed). `C9`
2. Run Argon2id over the master password using the **file's** KDF params (validated against the
   floor **and** ceiling). `C2`, `C8`
3. Derive the master key → verify `header_hmac`. On failure: abort, decrypt nothing. `C9`
4. Unwrap the data key from the first valid stanza (OR model). `C4`–`C6`
5. Verify each HmacBlockStream block, then STREAM-decrypt each 64 KiB chunk (tag-checked before
   release) into `mlock`'d, zeroizing buffers. `C1`, `C10`–`C12`
6. Read the inner header; check the monotonic counter against the local anchor (rollback). `C16`, `C19`

## Invariants the code must uphold

- No secret type implements `Debug`/`Display` that reveals bytes; none uses plain `Vec<u8>`. `C11`
- No `==` on secret bytes — constant-time only. `C25`
- No payload byte is returned before its authentication tag verifies. `C1`, `C9`, `C10`
- No secret is ever written to a network socket or an LLM-readable channel by default. `C23`, `C27`

See [CRYPTO.md](CRYPTO.md) and [FILE_FORMAT.md](FILE_FORMAT.md) for the details.
