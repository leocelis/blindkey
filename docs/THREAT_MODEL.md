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
| **Malicious / compromised sync backend** | Serves, withholds, reorders, or rolls back the file | STREAM segment-binding; per-save payload-key freshness (no cross-version keystream/XOR channel); keyed header HMAC; monotonic counter + local anchor | C1, C9, C10, C16 |
| **Passive file observer** | Reads the blob at rest | Single opaque blob; zero plaintext metadata | C17, C18, C19 |
| **Host malware / infostealer** | Same-user process; reads memory, swap, clipboard | `zeroize` + `mlock`; core-dump off; clipboard auto-clear + concealment; auto-lock; anti-ptrace* | C11–C13, C25, C33 |
| **Evil-maid** | Physical access between uses | Stanza AEAD tag (KDF-downgrade detection); data-key-keyed header HMAC; TPM PCR sealing* | C2, C9, C15 |
| **AI-orchestrated attacker** | Frontier LLM drives recon→exfil; agentic tools | Zero metadata to recon; model-blind secret delivery; no secrets on argv; sanitized output | C17, C18, C27, C28, C31 |
| **Supply-chain attacker** | Compromises a dependency or the release pipeline | Audited-libs-only; `cargo audit`/`deny` (`vet`*); reproducible + signed releases | C3, C24, C34 |
| **Hostile-file attacker** | Hands you a crafted vault file | Parser fuzzing; KDF parameter ceiling; bounded allocations | C2, C7–C10, C30 |

`*` = partially covered today. Further hardening (anti-ptrace, `cargo vet` in the release path,
live TPM/FIDO2 FFI) is tracked in
[research/security_coverage_gaps.md](../research/security_coverage_gaps.md) Part 2 — distinct from
the shipped C1–C60 set (C35–C39 are omni-search, already in intent v1.7.0).

## Explicitly out of scope (residual risk)

- **Physical bus-level attacks on a discrete TPM** (SPI sniffing, TPM Genie) — documented, not mitigated.
- **A fully compromised OS kernel / root attacker** while the vault is unlocked.
- **An attacker who already possesses the unlocked master key or the decrypted payload.**
- **Coercion / rubber-hose** and **shoulder-surfing beyond auto-lock**.
- **The human typing the master password into a phishing surface** (mitigated only indirectly by the
  zero-network design — there is no legitimate online surface to imitate).
- **A hostile or prompt-injected agent with shell access to an unlocked session.** Model-blind
  delivery (C27) defends against *incidental* capture — a secret landing in an agent's tool-result
  stream or context window. An agent that can run shell commands can itself invoke
  `vault get --stdout` or read the clipboard; it is same-user malware, bounded — not eliminated —
  by auto-lock (C25), clipboard concealment (C33), and the timed clear (C13).
- **Rollback against a freshly provisioned device** (C16 limitation). The first open on a machine
  with no local state anchor is trust-on-first-use: any valid older vault is accepted and becomes
  the anchor. `vault open --expect-min-version N` can pin expectations during provisioning; a TPM
  NV monotonic counter is the hardened upgrade path.
- **Clipboard managers that ignore concealment hints** (C33 limitation) — on X11 especially, any
  client can read the clipboard during the window before the timed clear.
- **YubiKey stale-challenge replay window** (C5 graceful staleness) — if body-writing saves happen
  while the device is absent, a previously captured challenge-response can unlock the newer file
  until the next device-present save rotates the challenge; loudly warned, and `yubikey_strict`
  closes it entirely.

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
| **D**enial of service | KDF ceiling (C2); parser fuzzing (C30); atomic writes (C32) |
| **E**levation of privilege | mlock; core-dump off; anti-ptrace*; memory-safe Rust |
