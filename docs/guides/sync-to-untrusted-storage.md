# Guide — Park your `keys.txt` on Google Drive / a droplet, safely

> Audience: someone who has a messy `keys.txt` and wants **one encrypted file** they can drop on
> storage they don't fully trust (Google Drive, Dropbox, a VPS/droplet, a git repo) — readable only
> with Vault, and tamper-evident.
>
> This is a user-facing walkthrough. The authority is the tech spec
> [UC-07](../specs/UC-07-untrusted-storage-sync.md) (untrusted storage) + [UC-17](../specs/UC-17-quick-capture-raw-import.md)
> (import) and the testable constraints in [`vault_intent.yaml`](../../vault_intent.yaml).

## The 60-second version

```sh
vault init                              # pick a master password (do NOT lose it)
vault import --format raw keys.txt      # review the masked list → confirm
cp ~/.vault/vault.vlt  ~/Drive/vault.vlt   # the .vlt is the only thing you upload
```

That `vault.vlt` is a single opaque blob. Upload it anywhere. To use it elsewhere:

```sh
vault --vault ~/Drive/vault.vlt get github   # prompts for your master password, copies the secret
```

The desktop app does the same: open it, drag `keys.txt` onto the window, then search and copy.

## What you are (and aren't) protected against

| You're safe from… | Why | Constraint |
|---|---|---|
| The backend (or anyone who grabs the file) **reading** your secrets | Whole file is one AEAD blob; the data key is wrapped by your Argon2id-stretched password and never stored in the clear. Every field — even URLs and titles — is inside the encryption | C1, C5, C18 |
| The backend **altering** the file undetectably (bit-flips, splicing, truncation, KDF-downgrade) | Keyed header HMAC + per-block encrypt-then-MAC + per-chunk AEAD tags. Any change makes it fail to open — loudly, not silently | C9, C10, C1 |
| The backend serving you an **older copy** (rollback) | A local, non-synced anchor records the highest version this machine has seen; opening an older one warns (and on a pipe, exits with code `2`) | C16 |

| You're **not** protected from… | What to do |
|---|---|
| The backend **deleting / corrupting-to-garbage** the file (availability) | Keep your own copy. Vault guarantees confidentiality + tamper-*evidence*, not that a vandal can't destroy the file. |
| The backend learning **metadata**: file size (≈ how many entries), how often you save, timestamps | Turn on **size-padding** — [`vault pad on`](../../docs/guides/size-padding-padme.md) (or the desktop app's **"Pad size"** toggle) — Padmé buckets file size (`≤ ~12 %` overhead). Save frequency / timestamps still leak. |
| **Forgetting your master password** | There is no recovery. The whole design assumes the blob will be stolen, so there is no backdoor. |

## Rollback detection in practice (C16)

Vault keeps an 8-byte "last version I saw" file **outside** the synced folder:

- Linux `~/.local/share/vault/<id>.state` · macOS `~/Library/Application Support/vault/<id>.state` · Windows `%LOCALAPPDATA%\vault\<id>.state`

If your cloud serves an older vault than this machine last saw:

```
WARNING: vault version regressed (expected >= 7, got 5). The sync backend may have served an older copy.
Proceed anyway? [y/N]
```

- On a terminal: default is **No** (abort).
- Non-interactively (scripts/CI): **no prompt**, exit code **2** (reserved for rollback). Use
  `vault --allow-rollback …` to proceed anyway (the anchor is not lowered).
- **Fresh machine, first open:** there's no anchor yet, so any valid version is trusted
  (trust-on-first-use). See [Provisioning a new machine](#provisioning-a-new-machine-fleet--tofu)
  below for `--expect-min-version`. Residual risk is also in
  [docs/THREAT_MODEL.md](../THREAT_MODEL.md).

## Provisioning a new machine (fleet / TOFU)

When you drop a synced `vault.vlt` onto a **brand-new laptop**, Vault has no local anchor yet.
Any **valid** copy of the file opens — including an **old** copy an attacker might have kept on
the sync backend. That is the documented TOFU gap (constraint C16).

**Mitigation:** pass a version floor on the first (and every) open until the anchor exists:

```sh
vault --vault /path/to/vault.vlt --expect-min-version 42 ls
```

`--expect-min-version N` is a **global** flag (works with `ls`, `get`, `import`, etc.). Vault
compares the decrypted `vault_version` against `max(N, local_anchor)`. If the file is older than
that floor:

- **Interactive terminal:** prints the rollback warning and prompts `[y/N]` (default abort).
- **Scripts / CI / MDM** (stdin not a TTY): **no prompt**, exit code **2**. Override only when
  you deliberately accept an old copy: `--allow-rollback` (the anchor is **not** lowered).

### Where does **N** come from?

On a **trusted machine** that already uses this vault, after any normal successful open, read the
local anchor (never synced):

| OS | Anchor directory |
|----|------------------|
| Linux | `~/.local/share/vault/<vault_id_hex>.state` |
| macOS | `~/Library/Application Support/vault/<vault_id_hex>.state` |
| Windows | `%LOCALAPPDATA%\vault\<vault_id_hex>.state` |

The file is 8 bytes — little-endian `u64` = the last `vault_version` this machine saw:

```sh
# Linux/macOS — pick the .state file for your vault (one per vault_id)
od -An -tu8 -N8 -j0 ~/.local/share/vault/*.state
```

Publish that number in your internal runbook (or MDM env var) before imaging new machines.

### Fleet provisioning example

Headless first open on a new host — fails closed if the cloud served a stale copy:

```sh
#!/usr/bin/env bash
# /etc/vault/provision-first-open.sh — run once per new machine (MDM / onboarding)
set -euo pipefail

VAULT_FILE="${VAULT_FILE:-$HOME/Drive/vault.vlt}"
# Set by IT from a trusted admin workstation (see "Where does N come from?" above)
VAULT_EXPECT_MIN_VERSION="${VAULT_EXPECT_MIN_VERSION:?set VAULT_EXPECT_MIN_VERSION}"

# Unlock via VAULT_PASSWORD_FILE (mode 0600) — see UC-05; never put secrets on argv
export VAULT_PASSWORD_FILE="${VAULT_PASSWORD_FILE:-/etc/vault/unlock.password}"

if vault --vault "$VAULT_FILE" \
         --expect-min-version "$VAULT_EXPECT_MIN_VERSION" \
         ls; then
  echo "vault: anchor established; future opens use local rollback detection"
else
  code=$?
  if [ "$code" -eq 2 ]; then
    echo "vault: rollback or below-floor version — refuse stale sync copy" >&2
  fi
  exit "$code"
fi
```

After this succeeds, the local `.state` anchor is written and routine use no longer depends on
`--expect-min-version` — but keeping **N** in MDM as a belt-and-braces floor is harmless
(`max(N, anchor)`).

Enterprise MDM notes (config dir, lock policy): [enterprise-deployment.md](enterprise-deployment.md).

Global flags reference: [CLI.md](../CLI.md#global-flags-rollback-c16).

## If you use Git as the backend

- `.gitattributes` already marks `*.vlt binary` (no textual diff/merge — a forced text merge of two
  vaults produces garbage that fails verification).
- Every save rewrites the whole blob (fresh `nonce_prefix`/`master_seed`), so commits are
  whole-file binary changes — use a dedicated repo and `git gc` occasionally.
- `git commit -S` (signed) plus pinning the last-seen commit hash is an optional belt-and-braces
  layer on top of C16.
