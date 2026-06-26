# Crypto-shredding & data-key rotation — Research (security-gap review P2)

> **Task:** Define honest deletion semantics + ship `vault rotate-data-key` (gap C2).

## Problem (gap C2)

`vault rm` removes an entry from the **current** re-encrypted payload, but:

- Older `.bak` siblings and sync-backend history may still hold prior blobs.
- SSD wear-leveling does not guarantee physical erasure.

Users need clear guarantees and a path to **forward secrecy** after suspected compromise.

## Policy

| Operation | Guarantee | Does NOT promise |
|-----------|-----------|------------------|
| **`vault rm`** | Entry absent from new blob; unreadable without current data key | Erasing old sync copies or disk blocks |
| **`vault rotate-data-key`** | Fresh 256-bit data key; all stanzas re-wrapped; payload re-encrypted on save | Invalidating copies you still host elsewhere |

## `rotate-data-key` behavior

1. Unlock vault (master password + 2FA factors as usual).
2. `Vault::rotate_data_key` — CSPRNG new data key, re-wrap every stanza.
3. Body-writing `save` — new `master_seed`, `nonce_prefix`, STREAM ciphertext (C8/C1).
4. Old exfiltrated file + old stanzas still open the **old** key until removed from sync.

### 2FA vaults

- **pw-yubikey:** YubiKey tap during rotation (new challenge).
- **pw-keyfile:** `--keyfile` required (same as unlock).
- **Recovery stanza:** `--re-seal-recovery` + recovery code prompt — keeps anti-lockout path valid.

## References

- `docs/specs/UC-06-entry-management.md` §3.5
- `docs/specs/UC-09-hardware-factors.md` §3.5
- `research/security_coverage_gaps.md` C2
- `vault-core` `Vault::rotate_data_key`
