# Enterprise deployment (local-first)

Vault v1 is **single-user, offline-first**. Enterprise fleets deploy it as a **managed local
utility** — not a cloud password manager.

## Environment variables

| Variable | Component | Effect |
|----------|-----------|--------|
| `VAULT_VAULT_PATH` | `vault-gui`, `vault-cli` | Absolute path to `vault.vlt` (overrides `~/.vault/vault.vlt`) |
| `VAULT_CONFIG_DIR` | `vault-gui` | Directory for GUI config (`config` file inside) |
| `VAULT_LOCK_ON_BLUR` | `vault-gui` | Set to `1` to force lock when the window loses focus |

Secrets **must not** be passed via environment variables. For headless CLI unlock, use
`--password-fd` / `--password-stdin` / `VAULT_PASSWORD_FILE` per
[UC-05](specs/UC-05-script-and-ci-output.md). The password file must be mode `0600` on Unix.

## Rollback / sync on fleet machines (C16)

New laptops have **no rollback anchor** until the first successful open (trust-on-first-use).
When the vault file lives on shared storage (Drive, Syncthing, git), provision with a version
floor so a stale backend copy cannot pass silently:

```sh
vault --vault "$VAULT_VAULT_PATH" --expect-min-version "$VAULT_EXPECT_MIN_VERSION" ls
```

Obtain `VAULT_EXPECT_MIN_VERSION` from a trusted admin machine's local `.state` file; full walkthrough
and a headless onboarding script:
[sync-to-untrusted-storage.md — Provisioning a new machine](sync-to-untrusted-storage.md#provisioning-a-new-machine-fleet--tofu).

Non-interactive rollback → exit **2** unless `--allow-rollback`.

## MDM / fleet policy example

Deploy config via MDM to `~/.vault/config` or set `VAULT_CONFIG_DIR` to a managed path:

```ini
auto_lock_secs=300
clipboard_timeout_secs=15
lock_on_blur=1
dismissed_pre10=0
```

Set `VAULT_LOCK_ON_BLUR=1` in the shell profile for defense-in-depth.

## Audit & compliance

- Run [`../AUDIT_READINESS.md`](../AUDIT_READINESS.md) checks before fleet rollout
- Read [`../ENTERPRISE_POSTURE.md`](../ENTERPRISE_POSTURE.md) for non-claims (no SOC2/SSO)

## Native shell roadmap

macOS SwiftUI via UniFFI remains **S-18** (post-v1). The egui desktop app is the supported v1 GUI.
