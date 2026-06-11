# CLI Reference

> Authoritative spec: constraints **C20–C22, C26–C29, C31, C33** in [vault_intent.yaml](../vault_intent.yaml).
> Commands are **not yet implemented** (pre-alpha); this documents the intended surface.

## Commands

| Command | Description |
|---------|-------------|
| `vault init [--file PATH]` | Create a vault (prompts for a master password). |
| `vault add NAME [--interactive]` | Add an entry. **Secrets are never passed as flags.** |
| `vault get NAME [--field FIELD] [--stdout]` | Get a field — **to the clipboard by default**. |
| `vault gen [--length N] [--charset alnum\|ascii\|words] [--words N]` | CSPRNG password generator. |
| `vault ls [--search QUERY]` | List/search entry names (after unlock, in memory only). |
| `vault edit NAME` | Edit an entry. |
| `vault rm NAME` | Delete an entry (confirmation required). |
| `vault lock` | Clear the in-memory session. |
| `vault export --format json` | Export decrypted entries (prints a security warning). |
| `vault import --format txt\|json` | Import entries. |
| `vault upgrade-kdf` | Re-derive with current recommended Argon2id params. |
| `vault tune` | Benchmark and recommend Argon2id params for this machine. |
| `vault merge OLD.vlt NEW.vlt` | Manually merge two conflicting vault versions. |
| `vault stanzas list\|add TYPE\|remove TYPE` | Manage hardware/OS-keystore unlock stanzas (C5). |
| `vault enroll-tpm` / `re-enroll-tpm` | Manage the optional TPM stanza. |

## Secret-handling rules (why the CLI looks the way it does)

- **No secrets on the command line.** Passwords are read via a no-echo prompt, stdin, or
  `--password-fd N` — never an argv flag (it would leak to shell history and `ps`). *(constraint C31)*
- **`vault get` delivers to the clipboard by default.** Printing to stdout requires the explicit
  `--stdout` flag, which prints a warning — so an AI agent watching the process's stdout can't
  silently scrape the secret. This guards against *incidental* capture; an agent that can run shell
  commands on an unlocked session is same-user malware (see the threat model). With **no clipboard
  available** (headless SSH), `vault get` refuses with exit code 7 rather than silently degrading
  to stdout. *(constraint C27)*
- **Clipboard auto-clears** after 30s (configurable 5–300s) via a **detached helper process** (a
  one-shot CLI's thread can't outlive it) that clears only if the clipboard still holds our value,
  and is marked concealed/transient so OS clipboard history / cloud-clipboard sync skip it.
  *(constraints C13, C33)*
- **Output is sanitized**: control/ANSI escape sequences in stored fields are neutralized before
  being written to a terminal, and exports escape formula metacharacters. *(constraints C28, C29)*

## Exit codes (stable — scripts can rely on them; constraint C21)

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
| 8 | usage error — bad arguments/flags |
| 9 | entry or field not found / ambiguous |

## Configuration

`~/.vault.toml` (optional):

```toml
clipboard_timeout = 30     # seconds, 5..=300
auto_lock_seconds = 300    # seconds, 30..=3600, 0 = disabled
keep_backup = false        # retain vault.vlt.bak after a verified save (constraint C32)
yubikey_strict = false     # abort body-writing saves when the YubiKey is absent (constraint C5)
```
