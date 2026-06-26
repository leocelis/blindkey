# Size padding (Padmé)

> **S-12 / UC-07 §3.2** — optional mitigation for **file-size metadata leak** on untrusted sync.

## What it does

Your `.vlt` is one encrypted blob. Even with perfect crypto, a sync backend still sees **how big**
the file is — roughly correlated with how many entries you have.

**Padmé padding** rounds the encrypted payload's inner plaintext up to a **bucket** before
encryption, so nearby sizes collapse. Leakage drops from exact bytes to about **`O(log log L)`**
significant length bits, with **≤ ~12 %** storage overhead (smaller on large vaults).

Padding is **inside the AEAD** (after the parser's `END` marker). The backend cannot see padding
bytes — only the **outer** file size changes.

## What it does *not* do

- Hide **save times** or **how often** you edit (mtime / frequency still leak).
- Erase **old versions** on backends with history (Git, Dropbox versions).
- Replace a strong master password or off-site backup.

See [sync-to-untrusted-storage.md](sync-to-untrusted-storage.md) and
[THREAT_MODEL.md](../THREAT_MODEL.md#accepted-residual-syncstorage-metadata-c17).

## Default: off

New vaults ship **unpadded** (`PadMode::None`). Turn padding on only when you sync over storage
you do not trust and accept the overhead.

## Enable / disable

**CLI** (requires unlock — re-saves the vault):

```sh
vault pad on    # enable Padmé bucketing
vault pad off   # back to exact size
```

**Desktop app:** check **"Pad size"** in the top bar (same policy, persisted on save).

## When to use it

| Situation | Recommendation |
|-----------|----------------|
| Vault on Google Drive / Dropbox / git remote | **Consider `pad on`** |
| Local-only vault, no sync | Optional — little benefit |
| Tiny vault, size already obvious | Low benefit |
| Need minimal disk/sync bandwidth | Stay **off** |

## Technical reference

- Implementation: [`crates/vault-core/src/pad.rs`](../../crates/vault-core/src/pad.rs)
- Research: [`research/padme_padding_research.md`](../../research/padme_padding_research.md)
- Spec: [UC-07 §3.2](../specs/UC-07-untrusted-storage-sync.md)

**v2 note:** default-on Padmé requires a new intent constraint and maintainer sign-off — not planned
for v1.0.
