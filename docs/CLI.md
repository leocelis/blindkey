# CLI Reference

> Authoritative spec: constraints **C20–C22, C26, C27** in [vault_intent.yaml](../vault_intent.yaml).
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
| `vault enroll-tpm` / `re-enroll-tpm` | Manage the optional TPM stanza. |

## Secret-handling rules (why the CLI looks the way it does)

- **No secrets on the command line.** Passwords are read via a no-echo prompt, stdin, or
  `--password-fd N` — never an argv flag (it would leak to shell history and `ps`). *(coverage-gap B1)*
- **`vault get` delivers to the clipboard by default.** Printing to stdout requires the explicit
  `--stdout` flag, which prints a warning — so an AI agent watching the process's stdout can't
  silently scrape the secret. *(constraint C27)*
- **Clipboard auto-clears** after 30s (configurable 5–300s) and is marked transient so OS clipboard
  history / cloud-clipboard sync skip it. *(constraint C13, coverage-gap B2)*
- **Output is sanitized**: control/ANSI escape sequences in stored fields are neutralized before
  being written to a terminal. *(coverage-gap A2)*

## Configuration

`~/.vault.toml` (optional):

```toml
clipboard_timeout = 30     # seconds, 5..=300
auto_lock_seconds = 300    # seconds, 30..=3600, 0 = disabled
```
