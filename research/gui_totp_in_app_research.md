# GUI in-app TOTP display — Research (security-gap review P3)

> **Task:** In-app TOTP/code path that never touches the clipboard (high-risk 2FA codes).

## Problem

TOTP codes are **short-lived high-value secrets**. Clipboard delivery exposes them to:

- Clipboard history managers (gap B2 / C33)
- Cloud clipboard sync
- Same-user malware polling the clipboard

The GUI already rendered live TOTP in the detail panel but also offered **📋 Copy** — same risk as
`vault otp` on CLI without `--stdout`.

## Decision (v1.0 GUI)

| Field | GUI delivery |
|-------|----------------|
| Password | Clipboard default (model-blind, C27) + optional reveal |
| Username | Clipboard on demand |
| **TOTP / 2FA code** | **In-app only** — live monospace display + countdown; **no clipboard path** |

CLI unchanged: `vault otp` still defaults to clipboard (script/autofill use case); GUI is the
human high-assurance path.

## Implementation notes

- Remove `copy_otp`, `Action::CopyOtp`, and the Copy button on the 2FA row.
- `request_repaint_after(1s)` while the selected entry has `otp_secret` so the code rolls.
- Helper copy: "In-app only — not copied to clipboard."

## References

- `vault_core::totp` (RFC 6238)
- UC-04 C27 (clipboard default for passwords, not for GUI TOTP)
- gap B2 / C33 clipboard history
