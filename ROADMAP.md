# Roadmap

Vault is implemented **by constraint segment**, in the order defined by the IVD segmentation plan
in [`vault_intent.yaml`](vault_intent.yaml). Each milestone is "done" only when its constraints'
tests pass.

## Milestones

### M0 — Research & specification ✅
- Security research foundation ([research/](research/))
- Intent specification: 27 constraints, 10 groups ([vault_intent.yaml](vault_intent.yaml))
- AI-era threat landscape + coverage-gap analysis

### M1 — Open-source scaffolding ✅ *(this milestone)*
- Repository structure, governance, CI/security automation, docs skeleton

### M2 — File format core *(next)*
- `C7`–`C10`: magic/version, KDF-params block, header integrity (SHA-256 + HMAC), HmacBlockStream
- Serialization round-trip tests; **fuzz harnesses** for every parser
- `docs/FILE_FORMAT.md` finalized

### M3 — Cryptographic core
- `C1`–`C6`: XChaCha20-Poly1305 STREAM, Argon2id (floor **and** ceiling), HKDF, data key, envelope, FIDO2 PRF
- `cargo audit` / `cargo deny` green

### M4 — Memory & runtime hardening
- `C11`–`C13`, `C25`: zeroize, mlock, clipboard auto-clear, constant-time, core-dump-off, auto-lock, anti-ptrace

### M5 — Vault read/write & rollback
- `C4`, `C5`, `C16`: open/save, password rotation, monotonic counter + local anchor
- **Atomic writes + file locking** (crash safety)

### M6 — CLI surface
- `C20`–`C22`, `C26`, `C27`: init/add/get/ls/edit/rm/export/import/tune/**gen**, clipboard-default + `--stdout` opt-in
- **No secrets on argv**

### M7 — Hardware & OS-keystore stanzas *(optional)*
- `C14`, `C15`: FIDO2 (libfido2), TPM 2.0 (with re-enrollment); macOS Secure Enclave / Windows DPAPI

### M8 — Distribution & trust
- Reproducible builds, Sigstore/cosign signing, SLSA provenance, SBOM (`docs/VERIFYING_RELEASES.md`)

### M9 — Hardening backlog (candidate constraints C28+)
- From [research/security_coverage_gaps.md](research/security_coverage_gaps.md): KDF ceiling, output/CSV
  sanitization, Unicode normalization, recovery codes, clipboard cloud-sync exclusion, PQ posture

### M10 — Independent security audit → v1.0
- Third-party audit (format/parser, KDF, memory, hardware FFI, AI-era delivery), then **1.0.0**

## Out of scope for v1

Hosted cloud sync · browser extension · team/org vaults · GUI · any LLM/AI agent inside the trust
boundary (see [vault_intent.yaml](vault_intent.yaml) `non_goals` and `C27`).

## Bigger vision (post-1.0, under discussion)

Vault's audience protects more than passwords — files, `.env`s, code, database URLs, and the
secrets their AI tools touch. Expanding from "credential vault" to "developer secret vault"
(file/blob encryption, secret injection into running apps without exposing plaintext to an agent)
is the north star, scoped deliberately *after* the credential core is audited and solid.
