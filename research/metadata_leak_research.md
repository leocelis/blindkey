# Sync metadata leak — Research

> **Task:** THREAT_MODEL documents file-size / mtime metadata as accepted residual (C17).

## Problem

C17 mandates a single opaque blob — no per-entry plaintext paths, names, or counts. Intent
explicitly states the **residual** channel: total file size + modification timestamp (C17
rationale line 934). THREAT_MODEL had a 3-line stub; this review requires a complete, honest
statement cross-linked to UC-07 and user guides.

## What the backend learns (accepted, not a bug)

| Signal | Reveals | Mitigation in v1 |
|--------|---------|------------------|
| Blob size (exact bytes) | Entry count, coarsely | Optional Padmé padding (`blindkey pad on`) — buckets size to O(log log L) bits |
| Size deltas across versions | Approximate edit magnitude | Same padding; backend version history still retains curve |
| mtime / version timestamps | Save schedule, activity patterns | None in v1 — documented residual |
| Save frequency | Usage intensity | None in v1 |
| Git/Dropbox version history | All past blob sizes + KDF params at each era | User education; `upgrade-kdf` does not erase backend history |

## What remains protected (C17/C18)

- Entry titles, URLs, tags, usernames, passwords — all inside AEAD payload
- Entry count as an exact integer — not exposed; only correlated via size
- Directory structure — single file, no per-entry paths

## References

- `blindkey_intent.yaml` C17 rationale
- `docs/specs/UC-07-untrusted-storage-sync.md` §3.1–3.2
- `docs/guides/sync-to-untrusted-storage.md`
- Grubbs et al. — why per-entry encryption was rejected
