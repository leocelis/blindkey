# Desktop GUI accessibility (C54)

Every password field in `blindkey-gui` has a preceding `ui.label(...)` so screen readers can
discover the control. Automated tests in `uc21_constraints.rs` verify label wiring in source.

## Manual spot-check (recommended before v1.0)

On macOS with VoiceOver (or Windows with NVDA):

1. Unlock screen — hear "Master password" before the masked field
2. Create vault — hear "Confirm password" on the second field
3. Keyfile vault — hear "Recovery code" when `--recovery` path is shown
4. Entry editor — hear "Password" and "2FA secret" before masked fields
5. Keyfile enroll modal — hear "Master password" before confirm field

Pass criteria: each masked field is announced with its label; no unlabeled password inputs.
