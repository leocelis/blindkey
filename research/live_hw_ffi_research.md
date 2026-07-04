# Live FIDO2 + TPM hardware paths — Research (S-8a/S-8c)

> **Task:** Replace mock-only FIDO2/TPM with production device paths.

## Verdict (2026-06-26)

| Question | Answer |
|----------|--------|
| Rust `libfido2-sys` / `tss-esapi` in-tree? | **Deferred** — `vault-sys` stays OS-hardening-only; new deps need vet + CI images |
| Production path for S-8a/S-8c | **Subprocess** to `fido2-token` (libfido2) and `tpm2-tools` — same pattern as YubiKey/`ykman` (S-8b) |
| Mocks removed? | **No** — mocks remain for CI; live modules are the default runtime when tools + devices present |
| OR vs AND model | **OR** — FIDO2/TPM stanzas are additive; password stanza stays (UC-09 §3.1) |

## FIDO2 (S-8a / C14)

- Raw CTAP2 `hmac-secret` via `fido2-token -h` (libfido2 CLI, not browser WebAuthn).
- Salt: `SHA-256(vault_id ‖ "fido2-hw-v1")` — [`fido2_salt.rs`](../crates/vault-hardware/src/fido2_salt.rs).
- Wrapping: `HKDF(prf_output, vault_id, "vault-hw-wrap-v1")` — never use PRF bytes as key (C6).
- Runtime deps: `libfido2` + `fido2-token` on PATH; security key with hmac-secret support.

## TPM (S-8c / C15)

- Seal 32-byte `tpm_ikm` (not data key) to **PCR 7** (SHA-256 bank) via `tpm2_policypcr` + `tpm2_create` + `tpm2_unseal`.
- Wrapping: `HKDF(tpm_ikm, vault_id, "vault-tpm-wrap-v1")`.
- PCR mismatch → verbatim C15 message + `vault re-enroll-tpm`.
- Runtime deps: `tpm2-tools`, accessible TPM 2.0 (Linux/Windows; not macOS without external TPM).

## Open order (CLI)

1. TPM stanza (silent) if enrolled and tools available  
2. FIDO2 stanza (touch prompt) if enrolled  
3. Existing YubiKey/keyfile/password paths  

## Residual

- Bus attacks on discrete TPM (C15b) — documented, not mitigated.
- macOS without TPM: `enroll-tpm` fails with clear message.
- `fido2-token` absent → enroll/open skip FIDO2 with stderr hint.

## References

- [UC-09](../docs/specs/UC-09-hardware-factors.md) §3.3–3.4
- libfido2 `cred.c` / `assert.c` examples (`-h` hmac-secret, `-s` salt file)
- systemd-cryptenroll PCR 7 convention
