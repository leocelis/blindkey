# Hardware factor status (v1.0.0)

> **security-gap review** — hardware paths on real devices (S-8a/S-8c shipped via OS tool subprocesses).

## Shipped in v1 (use these)

| Factor | Command / UI | Notes |
|--------|----------------|-------|
| **Master password** | Always | Required at init; stanza always remains (C5) |
| **Keyfile 2FA** | `vault enroll keyfile <PATH>` · GUI **Keyfile 2FA** | Required-both AND model; recovery code at enroll |
| **YubiKey challenge-response 2FA** | `vault enroll yubikey` | HMAC-SHA1 slot 2 via **YubiKey Manager (`ykman`)** subprocess — not browser WebAuthn |
| **FIDO2 / CTAP2 hmac-secret** | `vault enroll fido2` | `fido2-token` (libfido2); needs hmac-secret-capable key |
| **TPM 2.0 PCR seal** | `vault enroll-tpm` | `tpm2-tools`; Linux/Windows TPM 2.0 (PCR 7 default) |

YubiKey 4/NEO use challenge-response (not FIDO2 hmac-secret). FIDO2 security keys use a separate OR stanza path.

## Optional / deferred

| Factor | Roadmap | v1 state |
|--------|---------|----------|
| **macOS Secure Enclave / Touch ID** | S-18 (post-v1) | Not shipped |
| **Windows DPAPI stanza** | S-8d | Deferred |

Constraint tests for FIDO2/TPM crypto **math and file format** pass against mocks — that is
**constraint-verified**, not a claim that your TPM or FIDO2 key is enrolled in production builds.

## Marketing language

- ✅ "Optional **YubiKey, keyfile, FIDO2, or TPM** factors (CLI; FIDO2/TPM need OS tools + hardware)"
- ✅ "Multi-stanza OR envelope; password always unlocks"
- ❌ "Touch ID / Secure Enclave unlock" as a v1 feature
- ❌ "Independently audited" — Vault has **not** had a third-party audit ([THIRD_PARTY_AUDIT.md](../THIRD_PARTY_AUDIT.md))

## See also

- [CLI.md](../CLI.md) — second factors section
- [specs/UC-09-hardware-factors.md](../specs/UC-09-hardware-factors.md) — design target
- [ROADMAP.md](../../ROADMAP.md) — S-8a/S-8b/S-8c
- [AUDIT_READINESS.md](../AUDIT_READINESS.md) — release gate (not third-party audit)
