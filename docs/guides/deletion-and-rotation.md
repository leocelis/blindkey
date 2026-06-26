# Deletion & data-key rotation

> **Gap C2** — honest semantics for `vault rm` and forward secrecy via `vault rotate-data-key`.

## What `vault rm` guarantees

When you delete an entry, vault:

1. Removes it from the in-memory payload.
2. Saves a **new** encrypted blob (fresh STREAM keys per C8).

The deleted entry is **crypto-shredded** in that new file: it is not present in the ciphertext and cannot be recovered without the current data key.

## What we do **not** promise

- **Physical disk erasure** on SSDs (wear leveling).
- **Removal from sync history** — Dropbox/iCloud/git may keep older vault generations.
- **`.bak` siblings** — `vault.vlt.bak` from the previous save may still decrypt to the old payload.

For a leaked **old copy** of the vault file, run **`vault rotate-data-key`** after you trust the current machine again.

## `vault rotate-data-key`

Generates a fresh 256-bit data key, re-wraps every unlock stanza, and re-encrypts the payload on save.

```sh
vault rotate-data-key
```

Use after:

- A **compromised** hardware factor was removed (`vault stanzas remove …`).
- You suspect an **old synced blob** was exfiltrated while the vault was unlocked elsewhere.

**Password-only vault:** master password prompt only.

**YubiKey 2FA:** touch the key when prompted; if a recovery-code stanza exists:

```sh
vault rotate-data-key --re-seal-recovery
```

**Keyfile 2FA:** pass `--keyfile PATH` (same as unlock).

Old files encrypted under the previous data key remain readable **if someone still has that file and the old stanzas** — rotation protects **new** writes; purge old copies from sync/backups separately.

## See also

- [CLI.md](../CLI.md) — command reference
- [sync-to-untrusted-storage.md](sync-to-untrusted-storage.md) — rollback / version floors
- [THREAT_MODEL.md](../THREAT_MODEL.md) — residual risks
