# Vault Threat Model

> Status: living document. Derived from [research/vault_spec.md](../research/vault_spec.md) §6 and
> [research/llm_offensive_threats.md](../research/llm_offensive_threats.md). Cross-referenced to the
> constraints in [vault_intent.yaml](../vault_intent.yaml).

## Assets we protect

1. **Master password** (highest value — never stored; derives the master key).
2. **Data key** (256-bit, unlocks the payload; never stored in plaintext).
3. **Entry contents** — passwords, usernames, **and all metadata** (URLs, titles, tags, timestamps).
4. **Entry existence / taxonomy** — even *which* entries exist, and how many.

## Core assumption

> **Assume the vault file is exfiltrated on day one.** (LastPass 2022: the encrypted blob was
> stolen.) After that, the only protection is KDF cost + cipher + zero-plaintext. We design for it.

## Adversaries and defenses

| Adversary | Capability | Primary defenses | Constraints |
|-----------|-----------|------------------|-------------|
| **Offline brute-forcer** | Has the stolen blob; rents GPUs | Argon2id (floor enforced); XChaCha20-Poly1305; CSPRNG-generated passwords | C1, C2, C26 |
| **Malicious / compromised sync backend** | Serves, withholds, reorders, or rolls back the file | STREAM segment-binding; keyed header HMAC; monotonic counter + local anchor | C9, C10, C16 |
| **Passive file observer** | Reads the blob at rest | Single opaque blob; zero plaintext metadata | C17, C18, C19 |
| **Host malware / infostealer** | Same-user process; reads memory, swap, clipboard | `zeroize` + `mlock`; core-dump off; clipboard auto-clear; auto-lock; anti-ptrace* | C11–C13, C25 |
| **Evil-maid** | Physical access between uses | Keyed HMAC (KDF-downgrade detection); TPM PCR sealing* | C9, C15 |
| **AI-orchestrated attacker** | Frontier LLM drives recon→exfil; agentic tools | Zero metadata to recon; model-blind secret delivery; no secrets on argv | C17, C18, C27, C29, C31 |
| **Supply-chain attacker** | Compromises a dependency or the release pipeline | Audited-libs-only; `cargo audit`/`deny`/`vet`; reproducible + signed releases* | C3, C24 |
| **Hostile-file attacker** | Hands you a crafted vault file | Parser fuzzing*; KDF parameter ceiling*; bounded allocations | C7–C10 |

`*` = partially covered today or proposed as a constraint in
[research/security_coverage_gaps.md](../research/security_coverage_gaps.md). The KDF ceiling,
no-secrets-on-argv, ANSI sanitization, and the presentation-layer boundary were ratified as
**C28–C31** in intent v1.3.0; remaining candidates start at C32.

## Explicitly out of scope (residual risk)

- **Physical bus-level attacks on a discrete TPM** (SPI sniffing, TPM Genie) — documented, not mitigated.
- **A fully compromised OS kernel / root attacker** while the vault is unlocked.
- **An attacker who already possesses the unlocked master key or the decrypted payload.**
- **Coercion / rubber-hose** and **shoulder-surfing beyond auto-lock**.
- **The human typing the master password into a phishing surface** (mitigated only indirectly by the
  zero-network design — there is no legitimate online surface to imitate).

## What leaks even in the best case

For a single-blob vault synced over untrusted storage: **total file size** (loosely correlated with
entry count) and **modification timestamp**. Nothing else.

## STRIDE quick map

| Threat | Covered by |
|--------|-----------|
| **S**poofing | Keyed header HMAC; stanza authentication |
| **T**ampering | AEAD tags; HmacBlockStream; header HMAC |
| **R**epudiation | (Single-user, local; out of scope) |
| **I**nformation disclosure | Zero-plaintext; zeroize/mlock; model-blind delivery |
| **D**enial of service | KDF ceiling*; parser fuzzing*; atomic writes* |
| **E**levation of privilege | mlock; core-dump off; anti-ptrace*; memory-safe Rust |
