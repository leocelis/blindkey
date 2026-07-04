# Security Coverage Gaps — Areas the Vault Should Cover (and Currently Doesn't)

> **Historical research (June 2026).** This document audited the intent at **27 constraints**
> (later **34**, now **60** in intent v1.7.0). The Promotion ledger and matrix table reflect
> what was promoted on 2026-06-10; many gaps are now **ADDRESSED** in code. Read
> [`docs/CONSTRAINT_INDEX.md`](../docs/CONSTRAINT_INDEX.md) for current verification status.
>
> **Method:** each gap is stated as a concrete attacker capability, mapped to the existing
> constraint(s) that touch it, given a coverage verdict, grounded in precedent (CVE / CWE /
> standard where one exists), and paired with a *proposed direction*.
>
> **These are findings, not changes.** Per design-before-implementation discipline, nothing
> here is added to `vault_intent.yaml` until explicitly approved. Proposed constraint IDs
> (C28+) are placeholders to make discussion concrete.
> **Update 2026-06-10:** the high-severity subset was explicitly approved and promoted — see the
> *Promotion ledger* under the coverage matrix for the authoritative gap→constraint mapping. The
> per-gap "proposed direction (Cxx)" IDs in the body text predate promotion and may differ from
> the final IDs.
>
> **Confidence markers:** `✓ verified` (CVE/standard fetched) · `~ inferred` (analysis from
> the existing spec + domain precedent) · `? open` (design question needing a decision).

---

## 0 — What's already strong (so we don't re-litigate it)

The 27 constraints in place at the time of this audit (34 since the 2026-06-10 promotion) already
give the vault a security posture stronger than most free managers on the dimensions they cover: AEAD-at-rest (C1), enforced Argon2id **floor** (C2),
audited-libraries-only (C3), age-style envelope (C4–C6), KDBX-style header integrity (C7–C10),
zeroize/mlock/clipboard-clear/constant-time/auto-lock (C11–C13, C25), hardware factors
(C14–C15), rollback detection (C16), single opaque blob + zero plaintext (C17–C19),
zero-network (C23), OSS licensing + cargo-audit/deny (C24), and the new AI-era pair —
CSPRNG generation (C26) and model-blind delivery (C27).

The gaps below are the surface those constraints **leave open**. None requires changing the
cryptography; most are about *untrusted-input handling, secret-exposure side channels,
data-integrity, distribution trust, and project governance* — exactly the categories where
"correct crypto" products still get CVEs.

---

## 1 — Coverage Matrix (at a glance)

| # | Gap area | Closest existing constraint | Verdict | Severity |
|---|---|---|---|---|
| A1 | KDF parameter **ceiling** (memory-DoS / integer overflow on open) | C2 (floor only), C8 (reads verbatim) | **PROMOTED → C2 ceiling** | High |
| A2 | Terminal / ANSI escape injection on display (`ls`, `get`) | — | **PROMOTED → C28** | High |
| A3 | CSV / formula injection on `export` | C21 (export) | **PROMOTED → C29** | High |
| A4 | Parser fuzzing & memory-safety on malformed/hostile vault files | C3 (libs), C7–C10 (format) | **PROMOTED → C30** | High |
| B1 | Secrets on argv / shell history / process list | C20 example actively violated this | **PROMOTED → C31** | High |
| B2 | Clipboard capture: history managers + OS cloud-clipboard sync | C13 (clears after timeout) | **PROMOTED → C33** | Med-High |
| B3 | Live process memory read via ptrace/debugger (same-uid) | C25 (core dumps only) | **PARTIAL** *(Linux ADDRESSED; macOS deferred)* | Med |
| C1 | Atomic writes + file locking (crash/concurrent-write corruption) | C17 (single blob) | **PROMOTED → C32** | High |
| C2 | Secure deletion / crypto-shredding semantics on `rm` & rotation | C4 (data key) | **ADDRESSED** *(rotate-data-key + guide)* | Med |
| C3 | Recovery from forgotten password / all-factors-lost | C5 (multi-stanza) | **ADDRESSED** *(init + 2FA recovery)* | Med |
| D1 | Reproducible builds + signed releases (SLSA / sigstore) | C20 (build), C24 (audit) | **PROMOTED → C34** | High |
| D2 | Dependency vetting depth (cargo-vet, SBOM, dep budget) | C3, C24 (audit/deny) | **PARTIAL** *(vet ADDRESSED; dep budget open)* | Med |
| E1 | Post-quantum posture + crypto-agility statement | C7 (versioned format) | **ADDRESSED** *(2026-06-26)* | Low-Med |
| E2 | Unicode normalization of the master password | C2 (KDF) | **PROMOTED → C2 (NFC)** | Med |
| F1 | Coordinated vulnerability disclosure policy (SECURITY.md) | C24 (OSS) | **ADDRESSED** (SECURITY.md shipped) | High (governance) |
| F2 | Formal threat model document (STRIDE / attack trees) | research taxonomy | **ADDRESSED** (docs/THREAT_MODEL.md) | Med |
| F3 | Independent security audit before v1.0 | spec checklist | **OPTIONAL** ([THIRD_PARTY_AUDIT.md](../docs/THIRD_PARTY_AUDIT.md)) | High |

### Promotion ledger (2026-06-10)

Maintainer-approved promotion of the high-severity set into `vault_intent.yaml` ("Part 1"):
**A1 → C2 (ceiling)** and **E2 → C2 (NFC)** were folded into the existing KDF constraint;
**A2 → C28**, **A3 → C29**, **A4 → C30**, **B1 → C31**, **C1 → C32**, **B2 → C33**, **D1 → C34**
were added under the new group **G11** (C28–C30) and existing groups G4/G6/G8/G9.
The constraint count moved from 27 to 34. The proposed IDs below (written before promotion) are
therefore historical placeholders; the mapping above is authoritative.
The rows still marked *(Part 2)* — B3, C2, C3, D2 — remain open findings; each lands via its
own ADR per [GOVERNANCE.md](../GOVERNANCE.md) (see ROADMAP M9).

---

## 2 — Theme A: Untrusted-Input Handling (the parser & the output)

The vault parses **attacker-influenceable bytes** (a synced/exfiltrated-then-restored vault
file) and prints **attacker-influenceable content** (entry fields an attacker may have seeded,
e.g. a shared login, a phished entry, an imported list). Both directions are classic CVE soil.

### A1 — KDF parameter ceiling (memory-exhaustion / overflow DoS) — **ADDRESSED (C2 ceiling)**
- **Attack:** C8 mandates reading KDF params *verbatim from the file*; C2 enforces only a
  **minimum** floor. A malicious or corrupted vault file can therefore declare
  `argon2id_m_cost = 0xFFFFFFFF` KiB (~4 TiB) or a value that **integer-overflows** when KiB→bytes
  is computed, causing OOM-kill or a huge allocation **before** the password is ever checked.
- **Precedent:** ✓ verified — Argon2 memory-cost is set in KiB and converted to bytes, which
  *"can cause integer overflow on 64-bit platforms allowing allocation of more than 4 GB"*; this
  was a real fix in the libgcrypt/cryptsetup Argon2 KDF
  ([gcrypt-devel patch](https://www.mail-archive.com/gcrypt-devel@gnupg.org/msg00128.html)).
- **Why it bites us specifically:** C9's header HMAC is verified *using a key derived by running
  Argon2id with those very params* — so the expensive/overflowing allocation happens **before**
  any tamper check can reject the params. The downgrade defense protects the *low* end; nothing
  protects the *high* end.
- **Proposed direction (C28):** enforce a **maximum** alongside the floor — e.g. reject on open
  if `m_cost > 4 GiB` **or** `m_cost > (available_RAM / 2)`, `t_cost > 24`, `p_cost > 16`; perform
  the KiB→bytes computation with checked/saturating arithmetic and reject overflow *before*
  allocating; print "KDF parameters exceed safe limits — possible hostile or corrupt file."

### A2 — Terminal / ANSI escape injection on display — **ADDRESSED (C28)**
- **Attack:** entry titles/usernames/notes are arbitrary user bytes. When `vault ls` or
  `vault get` prints them to a TTY, embedded ANSI/OSC escape sequences can rewrite the terminal,
  spoof output, or (on some terminals) **inject into the clipboard** or trigger actions.
- **Precedent:** ✓ verified — CVE-2025-55754 (Apache Tomcat): ANSI escape-sequence injection
  that *"could inject a malicious command into the clipboard that executes if the administrator
  pastes"*. Terminal-escape injection is a recurring CWE-150 class.
- **Proposed direction (C29):** when writing any stored field to a terminal, **strip or
  visibly-escape** C0/C1 control characters and ANSI/OSC sequences (allow only printable +
  newline/tab). Apply to `ls`, `get --stdout`, `edit` previews, and error messages that echo
  field content.

### A3 — Export injection (CSV / formula) — **ADDRESSED (C29; CSV export not offered in v1)**
- **Attack:** `vault export` (C21) emits decrypted entries. If a CSV export is added (or a JSON
  field is later opened in a spreadsheet), a field beginning with `=`, `+`, `-`, or `@` becomes a
  **live formula** when the file is opened in Excel/Sheets — data exfiltration to RCE.
- **Precedent:** ✓ verified — CVE-2019-20184 (KeePass 2.4.1 CSV injection); OWASP *CSV Injection*;
  [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html). This is a *password-manager-specific*
  history, not a hypothetical.
- **Proposed direction (C30):** for any tabular/CSV export, prefix-escape leading formula
  metacharacters (e.g. prepend `'`), quote per RFC 4180, and strip control chars; for JSON, ensure
  strict escaping. Document that exports are plaintext and warn (C21 already requires the warning).

### A4 — Parser fuzzing & memory-safety on hostile files — **ADDRESSED (C30 + fuzz CI)**
- **Attack:** the header/stanza/HmacBlockStream parsers (C7–C10) consume untrusted bytes. A
  malformed `stanza_data_len`, truncated block, or absurd `stanza_count` must never panic, hang,
  over-read, or over-allocate — a crash on open is a sync-delivered DoS, and any FFI mishandling
  (libsodium/libfido2) is worse.
- **Precedent:** ~ inferred — standard practice for attacker-facing parsers; OSS-Fuzz routinely
  finds such bugs in format parsers.
- **Proposed direction (C31):** `#![forbid(unsafe_code)]` outside a small, vetted crypto-FFI
  module; `cargo-fuzz` harnesses for the header parser, each stanza type, and the block reader,
  run in CI and enrolled in OSS-Fuzz; bound every length field against the remaining buffer
  before allocation (ties to A1).

---

## 3 — Theme B: Secret-Exposure Side Channels (runtime)

The crypto can be flawless while the secret leaks out the side.

### B1 — Secrets on argv / shell history / process list — **ADDRESSED (C31)**
- **Attack:** passing a secret as a command-line flag exposes it to (a) shell history files,
  (b) `ps aux` / `/proc/<pid>/cmdline` readable by other processes, (c) shoulder-surfing.
- **The spec contradicts itself here:** ✓ verified — C20's own acceptance test runs
  `vault add github --username u --password p`, i.e. **password on argv**. That example would
  ship the exact anti-pattern.
- **Proposed direction (C32):** **forbid** accepting any secret (master password, entry password)
  via a CLI argument. Read only via (a) no-echo TTY prompt, (b) stdin pipe, or (c) an explicit
  `--password-fd N` / file descriptor. Update the C20/C21 examples to use prompts. Mirrors gopass.

### B2 — Clipboard capture beyond timed clear — **ADDRESSED (C33)**
- **Attack:** C13 clears the clipboard after 30 s, but during that window (and sometimes after)
  the secret is captured by **clipboard-history managers** and **OS cloud-clipboard sync**
  (Windows Cloud Clipboard, macOS Universal Clipboard) — exfiltrating the password to another
  device or a history buffer the clear never touches.
- **Precedent:** ~ inferred (documented OS behaviors); related to CVE-2025-55754's clipboard angle.
- **Proposed direction (C33):** mark clipboard writes **sensitive/transient** so OS history and
  cloud sync skip them — macOS `org.nspasteboard.ConcealedType` / `…TransientType`; Windows
  `ExcludeClipboardContentFromMonitorProcessing` + `CanIncludeInClipboardHistory=false`; Linux
  best-effort (prefer primary selection / direct injection). Keep the timed clear (C13) as backstop.

### B3 — Live process-memory read via ptrace/debugger — **PARTIAL (Linux ADDRESSED; macOS deferred)**
- **Attack:** C25 disables **core dumps**, but a same-uid process can still `ptrace`-attach (or
  read `/proc/<pid>/mem`) to scrape unlocked keys from the running vault.
- **Addressed (2026-06-26):** Linux `PR_SET_DUMPABLE` + `coredump_filter=0` in
  `vault-sys`; `harden_process()` at CLI/TUI/GUI startup; `ptrace_scope` documented in INSTALL.md.
- **Remaining:** macOS `PT_DENY_ATTACH` deferred (low value, breaks debugging); root/kernel
  attacker while unlocked is out of scope (THREAT_MODEL).

---

## 4 — Theme C: Data Integrity & Availability

A single opaque blob (C17) maximizes confidentiality but concentrates **availability risk**:
one bad write loses *everything*.

### C1 — Atomic writes + file locking — **ADDRESSED (C32)**
- **Attack/Failure:** a crash, full disk, or two concurrent `vault` processes writing mid-save can
  truncate or interleave the single blob and **destroy the entire vault**. C16's version counter
  detects rollback but not a half-written file.
- **Proposed direction (C35):** never write in place — serialize to a temp file in the same
  directory, `fsync`, then **atomically rename** over the target (and `fsync` the dir); take an
  advisory `flock` for the session; keep the previous generation as `vault.vlt.bak` until the new
  one verifies. This is data-loss prevention as much as security.

### C2 — Secure deletion / crypto-shredding semantics — **ADDRESSED (2026-06-26)**
- **Policy:** `vault rm` crypto-shreds in the new blob; no physical/sync-history erase promise.
- **Shipped:** `vault rotate-data-key`, `Vault::rotate_data_key`, guide
  `docs/guides/deletion-and-rotation.md`.
- **Honest limit:** old exfiltrated blobs remain decryptable until removed from sync/backups.

### C3 — Recovery from forgotten password / all factors lost — **ADDRESSED (2026-06-26)**
- **Shipped:** optional recovery-code stanza at `vault init` (`--with-recovery-code` / TTY confirm);
  `Vault::add_recovery_stanza`; OR-unlock tries all password stanzas; guide
  `docs/guides/recovery-codes.md`.
- **Existing:** 2FA enrollment recovery (YubiKey/keyfile) unchanged.
- **Honest limit:** no master-password reset without prior recovery enrollment; lose both = lost vault.

---

## 5 — Theme D: Supply-Chain & Distribution Trust

For a *security* tool, "how do I trust the binary I downloaded" is a first-class security
property — and the current intent stops at `cargo audit`/`cargo deny`.

### D1 — Reproducible builds + signed releases — **ADDRESSED (C34 + cargo auditable SBOM)**
- **Gap:** C20 produces a static binary and C24 audits dependencies, but nothing lets a user
  **verify the release artifact** they download matches the audited source. A compromised CI or
  release account could ship a backdoored binary undetectably.
- **Precedent:** ✓ verified — SLSA provenance + Sigstore/cosign keyless signing are 2025 baseline;
  Rust tooling exists (`cargo-vet`, `cargo-cyclonedx`, cosign, GitHub OIDC)
  ([SLSA](https://slsa.dev/spec/v1.0/faq), [Sigstore/cosign](https://aquilax.ai/blog/supply-chain-artifact-signing-slsa)).
- **Proposed direction (C38):** **reproducible builds** (pinned toolchain, `--locked`, documented
  build env) so anyone can rebuild bit-for-bit; **cosign keyless signature** + **SLSA L3 build
  provenance** on every release artifact via GitHub OIDC; publish SHA-256 checksums; document the
  `cosign verify` / checksum steps in the README. This is the distribution analogue of C9's
  header HMAC: integrity the user can check without trusting the channel.

### D2 — Dependency vetting depth — **PARTIAL (cargo-vet in gate; dep budget open)**
- **Gap:** `cargo audit` catches *known* advisories; it does not vet *unreviewed* code or shrink
  the trusted surface.
- **Addressed (2026-06-26):** `cargo vet` in `just audit-ready` / `just audit`;
  `supply-chain/config.toml` pins versioned exemptions; `cargo vet` must pass before release.
- **Remaining:** dependency budget cap; optional mozilla audit imports to shrink exemptions.
- **Proposed direction (C39):** emit CycloneDX **SBOM** per release; justify each crypto-adjacent dep.

---

## 6 — Theme E: Cryptographic Agility & Longevity

### E1 — Post-quantum posture + agility statement — **ADDRESSED (2026-06-26)**
- **Symmetric core** (XChaCha20-Poly1305, Argon2id, HMAC/HKDF-SHA-256): Grover-resilient —
  ~128-bit effective security from 256-bit keys; adequate for password-vault lifetime.
- **Optional asymmetric stanzas** (FIDO2 P-256, Secure Enclave secp256r1): store-now-decrypt-later
  in principle; wrap data key only; password stanza always remains (C5).
- **Shipped:** `docs/guides/post-quantum-posture.md` (canonical); expanded `CRYPTO.md`,
  `FILE_FORMAT.md` (agility table), `THREAT_MODEL.md` (residual);
  regression `pq_posture.rs`.
- **Deferred to v2:** hybrid-PQ wrap (e.g. ML-KEM) per ADR-0005; no NIST PQ marketing claims in v1.

### E2 — Unicode normalization of the master password — **ADDRESSED (C2 NFC)**
- **Attack/Failure:** a password containing non-ASCII (accents, emoji, CJK) can be encoded as
  different byte sequences (NFC vs NFD) by different OSes/keyboards, so the **same typed password
  fails to unlock** on another platform — or, worse, a normalization mismatch silently weakens the
  effective keyspace.
- **Proposed direction (C41):** **normalize the master password to NFC** (document the choice)
  before feeding Argon2id, consistently on every platform. Decide NFC vs NFKC explicitly
  (NFKC is more aggressive — fewer surprises, but collapses some distinct strings).

---

## 7 — Theme F: Governance (it's an *open-source security* project)

### F1 — Coordinated vulnerability disclosure policy — **ADDRESSED**
- **Status:** [`SECURITY.md`](../SECURITY.md) ships with GHSA intake, SLA table, and safe harbor.
  Optional age intake key publication is tracked in ROADMAP S-9 / UC-15.

### F2 — Formal threat model document — **ADDRESSED (`docs/THREAT_MODEL.md`)**
- **Gap:** the research has a threat *taxonomy*; a maintained `THREAT_MODEL.md` (STRIDE or attack
  trees) was missing.
- **Shipped:** adversary table, residual-risk list, STRIDE map, cross-links to specs/guides.
- **Verified (2026-06-26):** accepted sync metadata (file size, mtime, save frequency)
  documented per C17; patterns `metadata_leak_patterns.yaml`; regression `threat_model_metadata.rs`.
  trees, explicit **in-scope / out-of-scope** adversaries, and the residual-risk list) makes the
  guarantees auditable and sets expectations (e.g. "evil-maid with hardware TPM bus access is
  out of scope" per `vault_spec.md`).
- **Proposed direction:** promote the taxonomy into a versioned threat-model doc, cross-linked to
  the constraints that mitigate each entry.

### F3 — Independent audit before v1.0 — **OPTIONAL (not a code gate)**
- v1.0 is gated on the **CP-7 release quality gate** (`just audit-ready` + IVD Rule 2 sweep), not
  on commissioning a third-party audit. External review remains valuable but optional.

---

## 8 — Prioritized Recommendation (if promoting to constraints)

If/when these are approved into `vault_intent.yaml`, suggested order by **risk-reduction per unit
effort**:

1. **A1 (KDF ceiling)** + **A4 (parser fuzzing)** — close the hostile-file DoS/overflow surface;
   small code, high severity, concrete CVE precedent.
2. **B1 (no secrets on argv)** — fixes a self-contradiction in the current spec; trivial.
3. **C1 (atomic writes + locking)** — prevents catastrophic vault loss; pure correctness win.
4. **A2/A3 (terminal + CSV/formula sanitization)** — documented password-manager CVE class.
5. **D1 (reproducible + signed releases)** — the trust anchor for an OSS security binary.
6. **B2/B3, E2, C3** — meaningful side-channel and UX-security hardening.
7. **F1/F2/F3** — governance; cheap, expected, and required before asking anyone to trust v1.

A natural grouping is a new **G11 — "Robustness & untrusted-input handling"** (A1–A4, C1),
extending **G4** for B2/B3, **G8** for B1/C3/E2, and a new **G12 — "Distribution & governance
trust"** (D1–D2, F1–F3). Counts and segmentation would update accordingly — *pending approval.*

> **Resolution (2026-06-10):** approved with a slightly different grouping — G11 took the
> input/output items (A2→C28, A3→C29, A4→C30); the rest landed in existing groups (B1→C31 in G8,
> C1→C32 in G6, B2→C33 in G4, D1→C34 in G9) and no G12 was created. See the Promotion ledger.

---

## Sources Index

| Source | Type | Used for |
|---|---|---|
| [OWASP — CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection) | Standard | A3 |
| [CWE-1236 — Formula Injection in CSV](https://cwe.mitre.org/data/definitions/1236.html) | Weakness catalog | A3 |
| [CVE-2019-20184 — KeePass 2.4.1 CSV Injection](https://medium.com/@Pablo0xSantiago/cve-2019-20184-keepass-2-4-1-csv-injection-33f08de3c11a) | CVE writeup | A3 (password-manager precedent) |
| [CVE-2025-55754 — Apache Tomcat ANSI escape injection](https://www.sentinelone.com/vulnerability-database/cve-2025-55754/) | CVE | A2, B2 |
| [libgcrypt Argon2 memory-cost overflow fix](https://www.mail-archive.com/gcrypt-devel@gnupg.org/msg00128.html) | Patch/advisory | A1 |
| [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/html/rfc9106) | IETF RFC | A1 (param bounds) |
| [SLSA spec / FAQ](https://slsa.dev/spec/v1.0/faq) | Framework | D1 |
| [Sigstore / cosign + SLSA for supply chain](https://aquilax.ai/blog/supply-chain-artifact-signing-slsa) | Analysis | D1 |
| [Supply-chain security in Rust (cargo-vet, cyclonedx, cosign)](https://disant.medium.com/building-compliant-distributed-systems-in-rust-1b9fc2ba4f1e) | Practitioner | D1, D2 |
| `vault_spec.md` (this repo) | Internal research | Threat model, out-of-scope adversaries |
| `llm_offensive_threats.md` (this repo) | Internal research | C27 / AI-era delivery audit scope |

---

*Compiled June 2026 against the then-27-constraint `vault_intent.yaml`; audits uncovered attack
surface across untrusted-input handling, secret-exposure side channels, data integrity,
supply-chain trust, crypto longevity, and project governance. CVE/standard precedents fetched and
quoted; spec-internal analysis marked `~ inferred`. All items are findings — no constraints are
added to `vault_intent.yaml` without explicit approval. The high-severity subset was approved and
promoted on 2026-06-10 (see the Promotion ledger above); the intent now has **60 constraints** (v1.7.0).*
