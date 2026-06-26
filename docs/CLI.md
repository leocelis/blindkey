# CLI Reference

> **Status:** core loop implemented and tested (pre-1.0). Authoritative constraints:
> **C20–C22, C26–C29, C31, C33, C35–C39** in [vault_intent.yaml](../vault_intent.yaml).
> Stubs below are marked *(not yet implemented)*.

Default vault path: `$HOME/.vault/vault.vlt` (override with `--vault PATH`).

## Global flags (rollback — C16)

These flags apply to every subcommand that opens the vault (`ls`, `get`, `import`, …):

| Flag | Effect |
|------|--------|
| `--vault PATH` | Vault file (default `~/.vault/vault.vlt`; env `VAULT_VAULT_PATH`) |
| `--expect-min-version N` | Require decrypted `vault_version >= N` even on a fresh machine (TOFU mitigation). Floor is `max(N, local_anchor)`. |
| `--allow-rollback` | Proceed after a version-regression warning without lowering the local anchor. |
| `--strict-yubikey` | Abort body-writing saves when the YubiKey is absent (constraint C5). |
| `--allow-stale-yubikey` | Allow saves without refreshing the YubiKey stanza (graceful staleness). |

On rollback (file version below the floor): interactive TTY prompts `[y/N]`; non-interactive
(stdin not a TTY) exits **2** unless `--allow-rollback`. See
[sync guide — fleet provisioning](guides/sync-to-untrusted-storage.md#provisioning-a-new-machine-fleet--tofu).

YubiKey 2FA vaults default to **strict** at enrollment (`vault enroll yubikey`). Opt out with
`vault enroll yubikey --graceful-yubikey` or `--allow-stale-yubikey` on individual saves.

## Implemented commands

| Command | Description |
|---------|-------------|
| `vault init` | Create a vault (master password prompt; seeds `vault.vlt.bak`). Optional offline recovery code: `--with-recovery-code` or TTY confirm — see [recovery guide](guides/recovery-codes.md). |
| `vault import --format raw <file> [--yes]` | Import a messy `keys.txt` (masked review; `--yes` for scripts). |
| `vault ls [--search QUERY]` | List entry titles; substring search on title/tags. |
| `vault find [QUERY] [--stdout]` | Fuzzy omni-search (UC-19); copies top match to clipboard. |
| `vault get NAME [--field FIELD] [--stdout]` | Get a field — clipboard by default. |
| `vault add NAME` | Add an entry (interactive prompts; no secrets on argv). |
| `vault edit NAME` | Edit an entry (interactive). |
| `vault rm NAME` | Delete an entry (confirmation on TTY). |
| `vault lock` | Clear clipboard; note per-process CLI has no persistent unlock session. |
| `vault gen [--length N] [--charset …] [--words N]` | CSPRNG password / diceware generator. |
| `vault otp NAME [--stdout]` | Current TOTP code for an entry with a 2FA secret (CLI → clipboard; **GUI shows in-app only**). |
| `vault audit` | Offline **password health** report (weak/reused/stale) — not the CI dependency audit |
| `vault export --format json [--yes]` | Decrypted JSON to stdout (warning on stderr; `--yes` when piped). |
| `vault upgrade-kdf` | Re-encrypt with stronger Argon2id parameters. |
| `vault rotate-data-key [--re-seal-recovery]` | Fresh data key + re-wrap stanzas (gap C2; see [deletion guide](guides/deletion-and-rotation.md)). |
| `vault tune` | Benchmark and recommend Argon2id params (~300 ms target). |
| `vault pad on\|off` | Toggle Padmé payload size-padding (UC-07). |
| `vault agent allow …` | Register opaque handle for model-blind agent use (S-13). |
| `vault agent run` | Start local broker (Unix socket, OS approval per use). |
| `vault agent list` / `revoke` / `use` | Manage handles; `use` returns status-only JSON. |
| `vault enroll yubikey` | Required-both YubiKey 2FA + one-time recovery code (strict saves by default). |
| `vault enroll keyfile <PATH>` | Required-both keyfile 2FA (no hardware). |
| `vault enroll-tpm` | TPM stanza enrollment (mock/dev path; live TPM FFI deferred). |
| `vault re-enroll-tpm` | Re-seal TPM stanza after firmware/kernel update (mock/dev). |
| `vault stanzas list` | Show enrolled stanza types (no secrets). |
| `vault stanzas add TYPE` | Enrollment guidance (delegates to `vault enroll …`). |
| `vault stanzas remove TYPE` | Remove a non-password stanza (requires unlock). |

See [AGENT_BROKER.md](AGENT_BROKER.md) for the S-13 scaffold workflow.

## Not yet implemented

| Command | Notes |
|---------|-------|
| `vault import --format txt\|json` | Structured importers (UC-12). |
| `vault merge OLD NEW` | Conflict merge (UC-08). |

## `vault find` — searchable fields (constraint C35)

`vault find` and `vault ls --search` match **metadata only**:

- **Searched:** `title`, `username`, `url`, `tags`
- **Never searched:** `password`, `otp_secret`, protected custom fields, `notes`

This is intentional — the matcher cannot leak a secret it never sees. Use `vault get NAME` after
finding by title.

`--stdout` lists ranked titles only (no secret values, scriptable).

## `vault import --format raw`

Parses unstructured secrets files (`key=value`, bare secret lines, `---` block rulers).

- **Interactive (TTY):** shows masked previews, prompts `Import these into the vault? [y/N]`
- **Scripted (piped stdin):** requires `--yes` (exit **8** without it)
- **`--yes` on TTY:** skips the confirmation prompt

## Second factors — true 2FA (UC-09)

**v1 hardware honesty:** [guides/hardware-factor-status.md](guides/hardware-factor-status.md) —
YubiKey CR and keyfile 2FA ship; FIDO2/TPM/Secure Enclave are deferred (mocks only).

`vault enroll yubikey` and `vault enroll keyfile <PATH>` turn the master password into a
**required-both** factor: the data key is re-wrapped under
`HKDF(Argon2id(password) ‖ factor)`, so the password **alone no longer unlocks**.

- Keyfile unlock: `vault --keyfile <PATH> <cmd>` — keep the keyfile on a **separate device**.
- **Anti-lockout:** enrollment prints a one-time **recovery code**; `vault --recovery <cmd>` if
  the factor is lost.
- Only one second factor enrolled at a time.

## Secret-handling rules

- **No secrets on argv** (C31) — passwords via no-echo prompt or stdin.
- **`vault get` → clipboard by default** (C27); `--stdout` is explicit opt-in with warning.
- **Headless:** `vault get` without clipboard refuses with exit **7** unless `--stdout`.
- **Clipboard auto-clears** via detached helper (C13/C33).
- **Terminal output sanitized** (C28/C30).

## Pre-1.0 / backup notice

Vault is **not independently audited**. On `init` and `import`, the CLI prints a notice and writes
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
yubikey_strict = true      # per-vault default after `vault enroll yubikey`; set false for graceful mode
```

## Install

See [INSTALL.md](INSTALL.md) — `./scripts/install.sh` or `cargo install --git …`.
