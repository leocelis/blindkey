# CLI Reference

> **Status:** core loop implemented and tested (pre-1.0). Authoritative constraints:
> **C20–C22, C26–C29, C31, C33, C35–C39** in [blindkey_intent.yaml](../blindkey_intent.yaml).
> Stubs below are marked *(not yet implemented)*.

Default vault path: `$HOME/.blindkey/vault.vlt` (override with `--vault PATH`).

## Global flags (rollback — C16)

These flags apply to every subcommand that opens the vault (`ls`, `get`, `import`, …):

| Flag | Effect |
|------|--------|
| `--vault PATH` | Blindkey file (default `~/.blindkey/vault.vlt`; env `BLINDKEY_VAULT_PATH`) |
| `--expect-min-version N` | Require decrypted `vault_version >= N` even on a fresh machine (TOFU mitigation). Floor is `max(N, local_anchor)`. |
| `--allow-rollback` | Proceed after a version-regression warning without lowering the local anchor. |
| `--strict-yubikey` | Abort body-writing saves when the YubiKey is absent (constraint C5). |
| `--allow-stale-yubikey` | Allow saves without refreshing the YubiKey stanza (graceful staleness). |

On rollback (file version below the floor): interactive TTY prompts `[y/N]`; non-interactive
(stdin not a TTY) exits **2** unless `--allow-rollback`. See
[sync guide — fleet provisioning](guides/sync-to-untrusted-storage.md#provisioning-a-new-machine-fleet--tofu).

YubiKey 2FA vaults default to **strict** at enrollment (`blindkey enroll yubikey`). Opt out with
`blindkey enroll yubikey --graceful-yubikey` or `--allow-stale-yubikey` on individual saves.

## Implemented commands

| Command | Description |
|---------|-------------|
| `blindkey init` | Create a vault (master password prompt; seeds `vault.vlt.bak`). Optional offline recovery code: `--with-recovery-code` or TTY confirm — see [recovery guide](guides/recovery-codes.md). |
| `blindkey import --format raw <file> [--yes]` | Import a messy `keys.txt` (masked review; `--yes` for scripts). |
| `blindkey ls [--search QUERY]` | List entry titles; substring search on title/tags. |
| `blindkey find [QUERY] [--stdout]` | Fuzzy omni-search (UC-19); copies top match to clipboard. |
| `blindkey get NAME [--field FIELD] [--stdout]` | Get a field — clipboard by default. |
| `blindkey add NAME` | Add an entry (interactive prompts; no secrets on argv). |
| `blindkey edit NAME` | Edit an entry (interactive). |
| `blindkey rm NAME` | Delete an entry (confirmation on TTY). |
| `blindkey lock` | Clear clipboard; note per-process CLI has no persistent unlock session. |
| `blindkey gen [--length N] [--charset …] [--words N]` | CSPRNG password / diceware generator. |
| `blindkey otp NAME [--stdout]` | Current TOTP code for an entry with a 2FA secret (CLI → clipboard; **GUI shows in-app only**). |
| `blindkey audit` | Offline **password health** report (weak/reused/stale) — not the CI dependency audit |
| `blindkey export --format json [--yes]` | Decrypted JSON to stdout (warning on stderr; `--yes` when piped). |
| `blindkey upgrade-kdf` | Re-encrypt with stronger Argon2id parameters. |
| `blindkey rotate-data-key [--re-seal-recovery]` | Fresh data key + re-wrap stanzas (gap C2; see [deletion guide](guides/deletion-and-rotation.md)). |
| `blindkey tune` | Benchmark and recommend Argon2id params (~300 ms target). |
| `blindkey pad on\|off` | Toggle Padmé payload size-padding (UC-07). |
| `blindkey agent allow …` | Register opaque handle for model-blind agent use (S-13). |
| `blindkey agent run` | Start local broker (Unix socket, OS approval per use). |
| `blindkey agent list` / `revoke` / `use` | Manage handles; `use` returns status-only JSON. |
| `blindkey enroll yubikey` | Required-both YubiKey 2FA + one-time recovery code (strict saves by default). |
| `blindkey enroll keyfile <PATH>` | Required-both keyfile 2FA (no hardware). |
| `blindkey enroll-tpm` | TPM stanza enrollment (mock/dev path; live TPM FFI deferred). |
| `blindkey re-enroll-tpm` | Re-seal TPM stanza after firmware/kernel update (mock/dev). |
| `blindkey stanzas list` | Show enrolled stanza types (no secrets). Works on `.vlt` and `.vltf` headers. |
| `blindkey stanzas add TYPE` | Enrollment guidance (delegates to `blindkey enroll …`). |
| `blindkey stanzas remove TYPE` | Remove a non-password stanza (requires unlock). |

See [AGENT_BROKER.md](AGENT_BROKER.md) for the S-13 scaffold workflow.

## Sealed file containers (UC-23 — `.vltf`)

Password-protected **opaque file archives** for cloud sync (Cryptomator-style). Reuses the v1
header + stanza envelope + STREAM body (constraints **C61–C66**). Padmé padding is **on by default**.

| Command | Description |
|---------|-------------|
| `blindkey seal PATH… [-o OUT.vltf] [--no-pad]` | Seal one or more files/directories into a new `.vltf` (refuses overwrite). |
| `blindkey seal PATH… -o OUT.vltf --append` | Merge new paths into an existing `.vltf` (full re-encrypt; unlock required). |
| `blindkey seal - [-o OUT.vltf]` | Seal stdin as inner path `-` (passphrase via TTY / fd / `BLINDKEY_PASSWORD_FILE`; not `--password-stdin`). |
| `blindkey open ARCHIVE.vltf [-C DIR]` | Extract all entries under `DIR` (default: cwd). Staging dir `.vltf-partial/` until complete. |
| `blindkey open ARCHIVE.vltf --stdout` | Decrypt a **single** small file to stdout (stderr warning; 64 MiB cap — SC9). |
| `blindkey peek ARCHIVE.vltf` | List inner paths and sizes only (no file bodies). |
| `blindkey --vault FILE.vltf enroll keyfile\|yubikey\|fido2 …` | Add stanzas to a sealed container (header re-wrap only; inner archive unchanged). |
| `blindkey --vault FILE.vltf enroll-tpm` / `re-enroll-tpm` | TPM OR stanza on `.vltf` (same PCR-7 policy as `.vlt`). |
| `blindkey --vault FILE.vltf upgrade-kdf …` | Re-wrap password stanza at new Argon2id params (inner archive unchanged). |
| `blindkey --vault FILE.vltf rotate-data-key` | Fresh data key + full inner re-encrypt (password/keyfile/YubiKey stanzas only; drop FIDO2/TPM first). |
| `blindkey --vault FILE.vltf stanzas remove TYPE` | Remove a non-password stanza from `.vltf` (requires unlock). |

**Unlock flags** (same as vault commands): `--password-stdin`, `--password-file PATH`,
`--keyfile PATH`, `--recovery` — keyfile/YubiKey stanzas use the same UC-09 paths as `.vlt`.

**KDF tuning:** `--allow-weak-kdf`, `--kdf-m-cost`, `--kdf-t-cost`, `--kdf-p-cost` (same names as init).

**Exit codes:** wrong password / tamper → **5** (`auth:` on stderr). Usage errors → **1**.
Open/extract failure after auth → uniform message `sealed container could not be opened` (C64).

Spec: [UC-23-sealed-file-storage.md](specs/UC-23-sealed-file-storage.md).

## Local encrypted volumes (UC-25 — `.vltd`)

Live **local** encrypted workspace (PGP Disk / VeraCrypt-class): create a `.vltd`, mount it as a
folder, edit files, eject → ciphertext only. Reuses the v1 header + stanza envelope; the payload is
fixed-size AEAD blocks + Merkle/Kcom + local freshness (constraints **C61 parity, C67–C74**). Padmé
padding is **on by default**. Sibling to `.vltf` (UC-23, for cloud); a `.vltd` is **local-only** —
live RW mount on a cloud-sync folder is unsupported (C73).

> **Status:** the volume crypto core (`blindkey-core::volume`), the `blindkey volume` CLI verbs +
> `peek` magic dispatch, the desktop **GUI** Create / Mount / Eject shell, and the userspace
> **Linux FUSE** adapter (`blindkey-fuse`, [ADR-0009](specs/../adr/0009-volume-mount-blindkey-fuse.md))
> is **implemented** (`--features volume-mount`). **macOS** live-folder mount is optional:
> install [macFUSE](https://macfuse.io), then build with `--features macos-fuse` (Blindkey does
> not bundle macFUSE/Fuse-T — [ADR-0010](specs/../adr/0010-volume-macos-mount-matrix.md)).
> Without that feature, GUI Blindfolder opens a cleartext working folder (`MaterializedMount`).
> The surface below is the accepted contract
> ([spec §7](specs/UC-25-local-encrypted-volume.md#7-cli-surface-clap)).

| Command | Description |
|---------|-------------|
| `blindkey volume create PATH.vltd --size SIZE [--max-size SIZE] [--block-size-kib 32] [--no-pad]` | Create a new encrypted volume (refuses overwrite; Padmé on by default). |
| `blindkey volume mount PATH.vltd [MOUNTPOINT]` | Unlock + mount as a folder (userspace FUSE). Files are cleartext to the OS while mounted. |
| `blindkey volume umount PATH.vltd\|MOUNTPOINT` | Eject: end the FUSE session, sync, zeroize keys. |
| `blindkey volume resize PATH.vltd --size SIZE` | Grow the sparse volume up to `--max-size`. |
| `blindkey volume status PATH.vltd\|MOUNTPOINT` | Mount state + version/freshness summary (no secrets). |
| `blindkey volume trust-anchor PATH.vltd` | Explicitly accept the current on-disk version as fresh on a new device (MSV-19). |
| `blindkey volume checkout PATH.vltd [--work-dir DIR] [--mount MOUNTPOINT]` | UC-30: copy a sync-folder brick to `…/blindkey/volumes/work/<id>/`. Optional `--mount` unlocks+mounts the **work** copy (never the sync path). |
| `blindkey volume checkin [WORK_ID] [--work-dir DIR]` | UC-30: atomic replace of the sync-folder brick from the working copy (C100/C101). Exit **10** on E1 fingerprint mismatch. |
| `blindkey volume work-status [WORK_ID] [--work-dir DIR]` | UC-30: list or show working-copy sessions. |
| `blindkey volume work-discard WORK_ID [--work-dir DIR]` | UC-30: discard a working copy without writing the sync path. |

UC-30 working-copy exits: **10** E1 remote changed · **11** E5 hydration · **12** E6 work under sync root · **13** E8 rename/replace failed. Orphan sessions print a resume/discard hint on any `volume` command.
| `blindkey peek PATH.vltd` | List the virtual tree (paths + sizes only, no file bodies). |

**Unlock flags:** same UC-09 paths as vault/`.vltf` (`--password-stdin`, `--password-file`,
`--keyfile`, `--recovery`). **KDF tuning:** `--allow-weak-kdf`, `--kdf-m-cost`, `--kdf-t-cost`,
`--kdf-p-cost`. **Cloud policy (C73 / UC-30):** if `PATH.vltd` is under a detectable sync root
(Dropbox/Drive/iCloud/Syncthing/…), `mount` refuses and points to `volume checkout` or
`blindkey seal`. Use `--force-local` only as an unsupported escape hatch.
**Errors:** auth/parse failures collapse to the uniform `volume could not be opened` (C74).

Spec: [UC-25-local-encrypted-volume.md](specs/UC-25-local-encrypted-volume.md) ·
[UC-30-volume-working-copy.md](specs/UC-30-volume-working-copy.md).

## Not yet implemented

| Command | Notes |
|---------|-------|
| `blindkey import --format txt\|json` | Structured importers (UC-12). |
| `blindkey merge OLD NEW` | Conflict merge (UC-08). |
| `blindkey volume mount` on **macOS** | Optional: install macFUSE + build with `--features macos-fuse`. Default GUI Blindfolder uses `MaterializedMount` (cleartext working folder). |

## `blindkey find` — searchable fields (constraint C35)

`blindkey find` and `blindkey ls --search` match **metadata only**:

- **Searched:** `title`, `username`, `url`, `tags`
- **Never searched:** `password`, `otp_secret`, protected custom fields, `notes`

This is intentional — the matcher cannot leak a secret it never sees. Use `blindkey get NAME` after
finding by title.

`--stdout` lists ranked titles only (no secret values, scriptable).

## `blindkey import --format raw`

Parses unstructured secrets files (`key=value`, bare secret lines, `---` block rulers).

- **Interactive (TTY):** shows masked previews, prompts `Import these into the vault? [y/N]`
- **Scripted (piped stdin):** requires `--yes` (exit **8** without it)
- **`--yes` on TTY:** skips the confirmation prompt

## Second factors — true 2FA (UC-09)

**v1 hardware honesty:** [guides/hardware-factor-status.md](guides/hardware-factor-status.md) —
YubiKey CR and keyfile 2FA ship; FIDO2/TPM/Secure Enclave are deferred (mocks only).

`blindkey enroll yubikey` and `blindkey enroll keyfile <PATH>` turn the master password into a
**required-both** factor: the data key is re-wrapped under
`HKDF(Argon2id(password) ‖ factor)`, so the password **alone no longer unlocks**.

- Keyfile unlock: `blindkey --keyfile <PATH> <cmd>` — keep the keyfile on a **separate device**.
- **Anti-lockout:** enrollment prints a one-time **recovery code**; `blindkey --recovery <cmd>` if
  the factor is lost.
- Only one second factor enrolled at a time.

## Secret-handling rules

- **No secrets on argv** (C31) — passwords via no-echo prompt or stdin.
- **`blindkey get` → clipboard by default** (C27); `--stdout` is explicit opt-in with warning.
- **Headless:** `blindkey get` without clipboard refuses with exit **7** unless `--stdout`.
- **Clipboard auto-clears** via detached helper (C13/C33).
- **Terminal output sanitized** (C28/C30).

## Pre-1.0 / backup notice

Blindkey is **not independently audited**. On `init` and `import`, the CLI prints a notice and writes
`vault.vlt.bak` beside the vault before overwriting. Keep an **off-site copy** — do not make the
vault file your only backup.

## Exit codes (stable — constraint C21)

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | generic / unexpected error |
| 2 | rollback detected, not overridden (C16) |
| 3 | not a vault file / newer format version (C7) |
| 4 | corruption — header hash, block HMAC, or AEAD tag (C9, C10, C1) |
| 5 | authentication — invalid credentials or tampered header (C9) |
| 6 | KDF parameters outside the safe range (C2) |
| 7 | no clipboard available and `--stdout` not given (C27) |
| 8 | usage error — bad arguments/flags (e.g. piped import without `--yes`) |
| 9 | entry or field not found / ambiguous |

## Configuration

`~/.vault.toml` (optional; partial support):

```toml
clipboard_timeout = 30     # seconds, 5..=300
auto_lock_seconds = 300    # seconds, 30..=3600, 0 = disabled
keep_backup = false        # retain vault.vlt.bak after a verified save (constraint C32)
yubikey_strict = true      # per-vault default after `blindkey enroll yubikey`; set false for graceful mode
```

## Install

See [INSTALL.md](INSTALL.md) — `./scripts/install.sh` or `cargo install --git …`.
