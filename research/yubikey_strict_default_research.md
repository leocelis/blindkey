# YubiKey strict default — Research

> **Task:** Default `yubikey_strict` for new 2FA enrollments; graceful mode docs only.

## Problem

Composite YubiKey 2FA vaults store a **fixed challenge** in the stanza. On body-writing saves the
core rotates `master_seed` but, without a refresh step, the composite stanza keeps the same
challenge/wrap — a captured `(password, YubiKey response)` pair remains valid across saves.

**Card recommendation:** default **strict** for new enrollments (abort save without key); document
graceful opt-out only.

## Shipped model (UC-09 §2)

Vault uses **PW_YUBIKEY** composite (password AND key required), not the OR-envelope YUBIKEY stanza.
Strict policy still applies: on save, refresh the stanza with a new challenge + YubiKey tap when
the device is present; abort or warn when absent.

## Policy

| Path | Behavior |
|------|----------|
| **New `vault enroll yubikey`** | `payload.yubikey_strict = true` (persisted in AEAD) |
| **`vault enroll yubikey --graceful-yubikey`** | `yubikey_strict = false` |
| **Save, key present** | New challenge, re-wrap composite stanza (anti-replay) |
| **Save, key absent, strict** | `Error::YubiKeyStrictSave` — file unchanged |
| **Save, key absent, graceful** | Save proceeds + `YUBIKEY_STALE_WARNING` on stderr |
| **CLI override** | `--strict-yubikey` / `--allow-stale-yubikey` (global) |

## Storage

TLV `0x0004 YUBIKEY_STRICT` in encrypted payload (absent → false for legacy vaults).

## References

- `vault/vault_intent.yaml` C5 (G0.7)
- `docs/specs/UC-09-hardware-factors.md` §2–§3.3
- security-gap review gap table — YubiKey stale-challenge replay
