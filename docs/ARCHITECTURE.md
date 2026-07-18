# Architecture

Blindkey is a Cargo workspace with a deliberately small, auditable security core.

```
┌─────────────────────────────────────────────────────────────┐
│  blindkey-cli  (the `blindkey` binary)                             │
│  clap commands · stdout delivery · prompts                   │  C20–C22, C26, C27
│  output sanitization · export escaping · no argv secrets     │  C28, C29, C31
└───────────────┬─────────────────────────────────────────────┘
                │ uses
┌───────────────▼─────────────────────────────────────────────┐
│  blindkey-clip  (clipboard delivery — no vault secrets at rest) │  C13, C27, C33
│  arboard · concealment hints · headless session detection    │
└───────────────┬─────────────────────────────────────────────┘
                │ depends on
┌───────────────▼─────────────────────────────────────────────┐
│  blindkey-tui / blindkey-gui  (thin UI shells — no crypto here)    │  C40–C54, C27
│  ratatui TUI · egui desktop window · search/deliver loop     │
└───────────────┬─────────────────────────────────────────────┘
                │ depends on
┌───────────────▼─────────────────────────────────────────────┐
│  blindkey-core  (library — the security boundary)               │
│                                                              │
│  crypto/     XChaCha20-Poly1305 STREAM · Argon2id · HKDF     │  C1–C3
│  envelope/   data key · multi-stanza OR wrapping            │  C4–C6
│  format/     header · KDF params · integrity · block stream  │  C7–C10, C30
│  memory/     Secret/Zeroizing types · mlock · constant-time  │  C11–C13, C25, C33
│  search/     fuzzy metadata search (in-memory only)          │  C35–C39
│  rollback/   monotonic counter · local anchor · atomic save  │  C16, C32
└───────────────┬─────────────────────────────────────────────┘
                │ uses
┌───────────────▼─────────────────────────────────────────────┐
│  blindkey-sys  (OS calls: mlock, setrlimit — only `unsafe`)     │
└───────────────┬─────────────────────────────────────────────┘
                │ optional
┌───────────────▼─────────────────────────────────────────────┐
│  blindkey-hardware  (optional crate, feature-gated)             │
│  v1 shipped: YubiKey CR (`ykman`) · keyfile 2FA              │
│  mock/stub only: FIDO2 (libfido2) · TPM · SE · DPAPI (S-8*)  │  C14, C15
└─────────────────────────────────────────────────────────────┘
```

## Why this shape

- **Library/CLI split** (like `age`, `rustls`): the security-critical code (`blindkey-core`) is
  auditable and fuzzable in isolation, with no CLI/argument-parsing concerns in the trust boundary.
- **Hardware behind a feature gate**: a user with no FIDO2 key compiles and runs without that code
  path; hardware factors are *additive*, never required (the password stanza always unlocks — C5).
- **One trust boundary**: secrets only ever live inside `blindkey-core` types (`Secret<…>`,
  `Zeroizing<…>`). `blindkey-clip` handles clipboard I/O only; the CLI/GUI receive delivery
  *channels*, not long-lived key material — the same principle that protects against AI-agent
  exfiltration (C27).

## Data flow: opening a vault

1. Read plaintext header; verify `SHA-256(header)` (fast corruption check — no key needed). `C9`
2. Validate the **file's** KDF params against the floor **and** ceiling. `C2`, `C8`
3. Unwrap the data key from the first valid stanza (OR model; password path runs Argon2id —
   wrong password and tampered KDF params both fail here, indistinguishably). `C4`–`C6`, `C9`
4. Verify `header_hmac` with the data-key-derived key (works on every unlock path, including
   hardware-only). On failure: abort, decrypt nothing. `C9`
5. Verify each HmacBlockStream block (data-key-keyed), then STREAM-decrypt each 64 KiB chunk
   (tag-checked before release) into `mlock`'d, zeroizing buffers. `C1`, `C10`–`C12`
6. Read the inner header; check the monotonic counter against the local anchor (rollback). `C16`, `C19`

## Invariants the code must uphold

- No secret type implements `Debug`/`Display` that reveals bytes; none uses plain `Vec<u8>`. `C11`
- No `==` on secret bytes — constant-time only. `C25`
- No payload byte is returned before its authentication tag verifies. `C1`, `C9`, `C10`
- No secret is ever written to a network socket or an LLM-readable channel by default. `C23`, `C27`
- No secret is ever accepted as a command-line argument. `C31`
- No stored field reaches a terminal or an export file unsanitized. `C28`, `C29`
- No in-place write of the vault file — atomic rename with a verified backup, always. `C32`

See [CRYPTO.md](CRYPTO.md) and [FILE_FORMAT.md](FILE_FORMAT.md) for the details.
