# Marketing hardware claims — Research

> **Task:** Remove/soften hardware security claims until S-8a (libfido2) + S-8c (TPM FFI) ship.

## v1 reality (verified)

| Factor | v1 status | User path |
|--------|-----------|-----------|
| Password | ✅ Shipped | Always present |
| Keyfile 2FA | ✅ Shipped | `blindkey enroll keyfile` (CLI + GUI) |
| YubiKey CR 2FA | ✅ Shipped | `blindkey enroll yubikey` via `ykman` subprocess (S-8b) |
| Recovery code | ✅ Shipped | Init + 2FA enroll |
| FIDO2 (libfido2 CTAP2) | ⏸ Mock/tests only | No CLI enroll (M7 / S-8a) |
| TPM PCR seal | ⏸ Stub/mock only | `enroll-tpm` disabled in default build (S-8c) |
| Secure Enclave / Touch ID | ⏸ Post-v1 | SwiftUI shell (S-18) |
| Windows DPAPI stanza | ⏸ Deferred | S-8d |

## Overclaim patterns to fix

- PRD UC-9 reads as if all factors are available today
- README "optional hardware" without naming what's live vs deferred
- ARCHITECTURE diagram lists libfido2/TPM/SE without mock annotation
- CRYPTO.md lists all stanza types equally
- Evil-maid row cites "TPM PCR sealing" without partial/mock footnote

## Honest framing

- **Shipped:** password + optional **YubiKey or keyfile 2FA** (required-both AND model)
- **Constraint-verified** via mocks for FIDO2/TPM crypto math — not production device FFI
- **Do not market** FIDO2, TPM, Secure Enclave, or Touch ID as v1 features

## References

- ROADMAP S-8a/S-8b/S-8c/S-8d
- `docs/specs/UC-09-hardware-factors.md`
- `docs/AUDIT_COMMISSION.md` out-of-scope (mock paths)
