# Recovery codes

> **Gap C3** — optional offline escape hatch when you forget the master password.

## At init

On an interactive terminal, `blindkey init` may ask:

> Add an offline recovery code? There is NO password reset — lose master password AND recovery code = lose the vault forever.

Or pass explicitly:

```sh
blindkey init --with-recovery-code
```

A high-entropy code is generated (CSPRNG, ~143 bits), enrolled as a **second password stanza**, and
printed **once**. Store it offline (paper/safe) — it is not saved in plaintext anywhere.

## Unlock with recovery

```sh
vault --recovery ls
# prompt: enter recovery code (not master password)
```

The master password continues to work normally.

## Honest limits

- **No password reset** — no server, no escrow, no hint recovery.
- Lose **both** master password and recovery code → vault is **permanently** lost.
- 2FA vaults get a recovery code at **enrollment** (`blindkey enroll yubikey|keyfile`) — same unlock path.

## See also

- [CLI.md](../CLI.md) — `blindkey init`, `--recovery`
- [deletion-and-rotation.md](deletion-and-rotation.md) — `--re-seal-recovery` on rotate-data-key
