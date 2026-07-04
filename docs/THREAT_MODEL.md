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
| **Passive file observer** | Reads the blob at rest | Single opaque blob; zero **plaintext** entry metadata (C17/C18). Residual: blob size + mtime — see [§Accepted sync metadata](#accepted-residual-syncstorage-metadata-c17) | C17, C18, C19 |
| **Host malware / infostealer** | Same-user process; reads memory, swap, clipboard | `zeroize` + `mlock`; core-dump off; clipboard auto-clear + concealment; auto-lock; anti-ptrace (Linux) | C11–C13, C25, C33 |
| **Evil-maid** | Physical access between uses | Stanza AEAD tag (KDF-downgrade detection); data-key-keyed header HMAC; TPM PCR sealing* (stub in v1) | C2, C9, C15 |
| **AI-orchestrated attacker** | Frontier LLM drives recon→exfil; agentic tools | Zero metadata to recon; model-blind secret delivery; no secrets on argv; sanitized output | C17, C18, C27, C28, C31 |
| **Supply-chain attacker** | Compromises a dependency or the release pipeline | Audited-libs-only; `cargo audit`/`deny` (`vet`*); reproducible + signed releases | C3, C24, C34 |
| **Hostile-file attacker** | Hands you a crafted vault file | Parser fuzzing; KDF parameter ceiling; bounded allocations | C2, C7–C10, C30 |
| **Hostile sealed container** | Validly sealed `.vltf` with zip-slip paths or corrupt inner chunks | Inner archive TLV fuzzing; traversal-safe extract (C65); fail-closed staging (C64); uniform errors | C62–C66, C30 |
| **Passive `.vltf` observer** | Stores the sealed blob on untrusted cloud | Same as credential vault: outer blob size + mtime only; inner paths/sizes/counts inside AEAD (C62) | C61–C66, C17 |

`*` = partially covered today. Further hardening (macOS anti-ptrace, dependency budget,
live TPM/FIDO2 FFI) is tracked in
[research/security_coverage_gaps.md](../research/security_coverage_gaps.md) Part 2 — distinct from
the shipped C1–C66 set (C35–C39 are omni-search; C61–C66 are sealed file storage, intent v1.8.0).

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
  by auto-lock (C25), clipboard concealment (C33), and the timed clear (C13). **Mitigation path:**
  [S-13 agent broker](AGENT_BROKER.md) (`vault agent run`) — opaque handles, OS approval per use,
  status-only IPC; does not remove the `--stdout` path while the vault is unlocked outside the broker.
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
- **Quantum-era capture of optional asymmetric stanzas** — FIDO2 P-256 and Secure Enclave
  secp256r1 wraps are classical elliptic-curve; a future CRQC could decrypt **old captures** of
  those stanza blobs (store-now-decrypt-later). They wrap only the data key; the password path
  remains. See [guides/post-quantum-posture.md](guides/post-quantum-posture.md).
- **Sync/storage metadata channel (C17 accepted residual)** — a backend that stores the `.vlt` learns
  blob size, modification time, and save frequency even when every entry field is encrypted.
  This is **by design**, not a confidentiality failure. See
  [§Accepted sync metadata](#accepted-residual-syncstorage-metadata-c17).

## Accepted residual: sync/storage metadata (C17)

Vault's default is a **single opaque blob** (C17). That closes the worst leaks — plaintext entry
names in paths, per-entry file counts, directory structure, git history of filenames — that tools
like `pass` expose without decryption.

What a **passive sync backend** (Dropbox, Google Drive, Git, Syncthing, a VPS) can still observe
**even when cryptography is perfect**:

| Signal | What it reveals | v1 mitigation |
|--------|-----------------|---------------|
| **Total blob size** | Entry count, coarsely (~200–600 B per typical entry + fixed header/overhead) | Optional **Padmé padding** — [`vault pad on`](guides/size-padding-padme.md) or desktop **"Pad size"** — buckets length to
  O(log log L) bits (UC-07 §3.2). Default v1: **unpadded** (full size visible). |
| **Size deltas** across stored versions | Approximate magnitude of each edit | Padding reduces granularity; backends with version history retain a growth curve |
| **mtime / timestamps** | When you save; editing schedule; correlation with external events | **None** — documented residual |
| **Save frequency** | How actively the vault is used | **None** — documented residual |

Backends that keep **version history** (Git, Dropbox) retain every past blob. Implications:

- Old copies remain crackable at the **KDF cost of that era** after `vault upgrade-kdf`.
- Size history is a long-term growth curve — not entry names, but activity and scale.

**What does *not* leak** to the backend: entry titles, URLs, tags, usernames, passwords, notes,
exact entry count, or which service an entry belongs to — all are inside the AEAD payload (C18).

**User guidance:** [guides/sync-to-untrusted-storage.md](guides/sync-to-untrusted-storage.md).
**Authority:** [specs/UC-07-untrusted-storage-sync.md](specs/UC-07-untrusted-storage-sync.md) §3.1.
Optional size-padding is evaluated in UC-07 §3.2 (Padmé / PURBs); v2 may promote a default.

## What leaks even in the best case (summary)

For a single-blob vault on untrusted storage: **file size** (and deltas), **modification
timestamp**, and **save frequency**. No entry-level plaintext. Padding narrows the size channel
only when enabled.

## STRIDE quick map

| Threat | Covered by |
|--------|-----------|
| **S**poofing | Keyed header HMAC; stanza authentication |
| **T**ampering | AEAD tags; HmacBlockStream; header HMAC |
| **R**epudiation | (Single-user, local; out of scope) |
| **I**nformation disclosure | Zero-plaintext entry fields; zeroize/mlock; model-blind delivery. **Residual:** sync metadata (size/mtime) per C17 — not entry names |
| **D**enial of service | KDF ceiling (C2); parser fuzzing (C30); atomic writes (C32) |
| **E**levation of privilege | mlock; core-dump off; anti-ptrace (Linux); memory-safe Rust |
