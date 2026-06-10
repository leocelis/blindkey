# Security Coverage Gaps — Areas the Vault Should Cover (and Currently Doesn't)

> **Status:** Coverage-gap research (June 2026). Third companion to `vault_spec.md` and
> `llm_offensive_threats.md`. This document audits the **27 constraints** in
> `vault_intent.yaml` against the full attack surface of a real-world, locally-installed,
> sync-exposed credential vault and identifies where coverage is **missing** or **partial**.
>
> **Method:** each gap is stated as a concrete attacker capability, mapped to the existing
> constraint(s) that touch it, given a coverage verdict, grounded in precedent (CVE / CWE /
> standard where one exists), and paired with a *proposed direction*.
>
> **These are findings, not changes.** Per design-before-implementation discipline, nothing
> here is added to `vault_intent.yaml` until explicitly approved. Proposed constraint IDs
> (C28+) are placeholders to make discussion concrete.
>
> **Confidence markers:** `✓ verified` (CVE/standard fetched) · `~ inferred` (analysis from
> the existing spec + domain precedent) · `? open` (design question needing a decision).

---

## 0 — What's already strong (so we don't re-litigate it)

The existing 27 constraints already give the vault a security posture stronger than most free
managers on the dimensions they cover: AEAD-at-rest (C1), enforced Argon2id **floor** (C2),
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
| A1 | KDF parameter **ceiling** (memory-DoS / integer overflow on open) | C2 (floor only), C8 (reads verbatim) | **GAP** | High |
| A2 | Terminal / ANSI escape injection on display (`ls`, `get`) | — | **GAP** | High |
| A3 | CSV / formula injection on `export` | C21 (export) | **GAP** | High |
| A4 | Parser fuzzing & memory-safety on malformed/hostile vault files | C3 (libs), C7–C10 (format) | **GAP** | High |
| B1 | Secrets on argv / shell history / process list | C20 example actively violates this | **GAP** | High |
| B2 | Clipboard capture: history managers + OS cloud-clipboard sync | C13 (clears after timeout) | **PARTIAL** | Med-High |
| B3 | Live process memory read via ptrace/debugger (same-uid) | C25 (core dumps only) | **PARTIAL** | Med |
| C1 | Atomic writes + file locking (crash/concurrent-write corruption) | C17 (single blob) | **GAP** | High |
| C2 | Secure deletion / crypto-shredding semantics on `rm` & rotation | C4 (data key) | **GAP/UNSPEC** | Med |
| C3 | Recovery from forgotten password / all-factors-lost | C5 (multi-stanza) | **PARTIAL** | Med |
| D1 | Reproducible builds + signed releases (SLSA / sigstore) | C20 (build), C24 (audit) | **GAP** | High |
| D2 | Dependency vetting depth (cargo-vet, SBOM, dep budget) | C3, C24 (audit/deny) | **PARTIAL** | Med |
| E1 | Post-quantum posture + crypto-agility statement | C7 (versioned format) | **NOTE/PARTIAL** | Low-Med |
| E2 | Unicode normalization of the master password | C2 (KDF) | **GAP** | Med |
| F1 | Coordinated vulnerability disclosure policy (SECURITY.md) | C24 (OSS) | **GAP** | High (governance) |
| F2 | Formal threat model document (STRIDE / attack trees) | research taxonomy | **PARTIAL** | Med |
| F3 | Independent security audit before v1.0 | spec checklist | **NOTED** | High |

---

## 2 — Theme A: Untrusted-Input Handling (the parser & the output)

The vault parses **attacker-influenceable bytes** (a synced/exfiltrated-then-restored vault
file) and prints **attacker-influenceable content** (entry fields an attacker may have seeded,
e.g. a shared login, a phished entry, an imported list). Both directions are classic CVE soil.

### A1 — KDF parameter ceiling (memory-exhaustion / overflow DoS) — **GAP, High**
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

### A2 — Terminal / ANSI escape injection on display — **GAP, High**
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

### A3 — Export injection (CSV / formula) — **GAP, High**
- **Attack:** `vault export` (C21) emits decrypted entries. If a CSV export is added (or a JSON
  field is later opened in a spreadsheet), a field beginning with `=`, `+`, `-`, or `@` becomes a
  **live formula** when the file is opened in Excel/Sheets — data exfiltration to RCE.
- **Precedent:** ✓ verified — CVE-2019-20184 (KeePass 2.4.1 CSV injection); OWASP *CSV Injection*;
  [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html). This is a *password-manager-specific*
  history, not a hypothetical.
- **Proposed direction (C30):** for any tabular/CSV export, prefix-escape leading formula
  metacharacters (e.g. prepend `'`), quote per RFC 4180, and strip control chars; for JSON, ensure
  strict escaping. Document that exports are plaintext and warn (C21 already requires the warning).

### A4 — Parser fuzzing & memory-safety on hostile files — **GAP, High**
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

### B1 — Secrets on argv / shell history / process list — **GAP, High (and self-contradicted)**
- **Attack:** passing a secret as a command-line flag exposes it to (a) shell history files,
  (b) `ps aux` / `/proc/<pid>/cmdline` readable by other processes, (c) shoulder-surfing.
- **The spec contradicts itself here:** ✓ verified — C20's own acceptance test runs
  `vault add github --username u --password p`, i.e. **password on argv**. That example would
  ship the exact anti-pattern.
- **Proposed direction (C32):** **forbid** accepting any secret (master password, entry password)
  via a CLI argument. Read only via (a) no-echo TTY prompt, (b) stdin pipe, or (c) an explicit
  `--password-fd N` / file descriptor. Update the C20/C21 examples to use prompts. Mirrors gopass.

### B2 — Clipboard capture beyond timed clear — **PARTIAL, Med-High**
- **Attack:** C13 clears the clipboard after 30 s, but during that window (and sometimes after)
  the secret is captured by **clipboard-history managers** and **OS cloud-clipboard sync**
  (Windows Cloud Clipboard, macOS Universal Clipboard) — exfiltrating the password to another
  device or a history buffer the clear never touches.
- **Precedent:** ~ inferred (documented OS behaviors); related to CVE-2025-55754's clipboard angle.
- **Proposed direction (C33):** mark clipboard writes **sensitive/transient** so OS history and
  cloud sync skip them — macOS `org.nspasteboard.ConcealedType` / `…TransientType`; Windows
  `ExcludeClipboardContentFromMonitorProcessing` + `CanIncludeInClipboardHistory=false`; Linux
  best-effort (prefer primary selection / direct injection). Keep the timed clear (C13) as backstop.

### B3 — Live process-memory read via ptrace/debugger — **PARTIAL, Med**
- **Attack:** C25 disables **core dumps**, but a same-uid process can still `ptrace`-attach (or
  read `/proc/<pid>/mem`) to scrape unlocked keys from the running vault.
- **Proposed direction (C34):** on Linux call `prctl(PR_SET_DUMPABLE, 0)` (also blocks non-root
  same-uid ptrace under the default Yama `ptrace_scope`); document `ptrace_scope` hardening; on
  macOS evaluate `PT_DENY_ATTACH` with its caveats. Pairs with mlock (C12) and core-dump-off (C25)
  to close the live-memory surface.

---

## 4 — Theme C: Data Integrity & Availability

A single opaque blob (C17) maximizes confidentiality but concentrates **availability risk**:
one bad write loses *everything*.

### C1 — Atomic writes + file locking — **GAP, High**
- **Attack/Failure:** a crash, full disk, or two concurrent `vault` processes writing mid-save can
  truncate or interleave the single blob and **destroy the entire vault**. C16's version counter
  detects rollback but not a half-written file.
- **Proposed direction (C35):** never write in place — serialize to a temp file in the same
  directory, `fsync`, then **atomically rename** over the target (and `fsync` the dir); take an
  advisory `flock` for the session; keep the previous generation as `vault.vlt.bak` until the new
  one verifies. This is data-loss prevention as much as security.

### C2 — Secure deletion / crypto-shredding semantics — **GAP/UNSPEC, Med**
- **Question (? open):** when `vault rm` removes an entry, the old ciphertext may persist in SSD
  wear-leveled blocks and in `.bak`/sync history. What guarantee do we make?
- **Proposed direction (C36):** define deletion as **crypto-shredding** — the entry is gone from
  the re-encrypted payload and is unreadable without the data key; we do **not** promise physical
  block erasure (it's infeasible on modern SSDs). Additionally offer `vault rotate-data-key` for
  true forward-secrecy after a suspected compromise (re-encrypt payload under a fresh data key, so
  old exfiltrated blobs stay sealed under the old key). Document the distinction honestly.

### C3 — Recovery from forgotten password / all factors lost — **PARTIAL, Med**
- **Gap:** multi-stanza (C5) gives a *hardware* fallback, but a user with only a password stanza
  who forgets it has **no recovery** — by design there is no backdoor, which is correct, but the
  UX should make the tradeoff explicit and offer a *user-controlled* escape hatch.
- **Proposed direction (C37):** optional **recovery-code stanza** at init — a high-entropy CSPRNG
  code (uses C26) printed once for the user to store offline (paper/safe); it wraps the data key
  like any stanza. Plus a blunt, one-time "there is no password reset; lose all factors = lose the
  vault" confirmation. No escrow, no server.

---

## 5 — Theme D: Supply-Chain & Distribution Trust

For a *security* tool, "how do I trust the binary I downloaded" is a first-class security
property — and the current intent stops at `cargo audit`/`cargo deny`.

### D1 — Reproducible builds + signed releases — **GAP, High**
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

### D2 — Dependency vetting depth — **PARTIAL, Med**
- **Gap:** `cargo audit` catches *known* advisories; it does not vet *unreviewed* code or shrink
  the trusted surface.
- **Proposed direction (C39):** add `cargo-vet` (trusted-review gating of dependency updates),
  emit a CycloneDX **SBOM** per release, and set a **dependency budget** (cap transitive crate
  count; justify each crypto-adjacent dep). Reinforces C3.

---

## 6 — Theme E: Cryptographic Agility & Longevity

### E1 — Post-quantum posture + agility statement — **NOTE/PARTIAL, Low-Med**
- **Status:** the **symmetric** core (XChaCha20-Poly1305, Argon2id, HMAC/HKDF-SHA-256) is
  PQ-resilient — Grover only halves brute-force, so 256-bit keys retain ~128-bit security. The
  **optional asymmetric** stanzas (FIDO2 P-256, Secure Enclave secp256r1 ECIES) are
  store-now-decrypt-later exposed *in principle*, but they wrap a symmetric data key and the
  password stanza always remains, so the practical PQ risk is low.
- **Proposed direction (C40, doc-level):** add a short **PQ posture** statement; note that C7's
  versioned format + algorithm IDs already provide crypto-agility, and reserve a future
  **hybrid-PQ wrap** option (e.g. ML-KEM alongside the classical wrap) for a later format_version.

### E2 — Unicode normalization of the master password — **GAP, Med**
- **Attack/Failure:** a password containing non-ASCII (accents, emoji, CJK) can be encoded as
  different byte sequences (NFC vs NFD) by different OSes/keyboards, so the **same typed password
  fails to unlock** on another platform — or, worse, a normalization mismatch silently weakens the
  effective keyspace.
- **Proposed direction (C41):** **normalize the master password to NFC** (document the choice)
  before feeding Argon2id, consistently on every platform. Decide NFC vs NFKC explicitly
  (NFKC is more aggressive — fewer surprises, but collapses some distinct strings).

---

## 7 — Theme F: Governance (it's an *open-source security* project)

### F1 — Coordinated vulnerability disclosure policy — **GAP, High (governance)**
- **Gap:** no `SECURITY.md`, no security contact, no embargo/disclosure process. For a credential
  vault this is table stakes — researchers need a private channel and users need advisories.
- **Proposed direction:** ship `SECURITY.md` (contact, PGP/age key, response SLA, safe-harbor),
  use GitHub Security Advisories + CVE issuance, and a documented embargo window.

### F2 — Formal threat model document — **PARTIAL, Med**
- **Gap:** the research has a threat *taxonomy*; a maintained `THREAT_MODEL.md` (STRIDE or attack
  trees, explicit **in-scope / out-of-scope** adversaries, and the residual-risk list) makes the
  guarantees auditable and sets expectations (e.g. "evil-maid with hardware TPM bus access is
  out of scope" per `vault_spec.md`).
- **Proposed direction:** promote the taxonomy into a versioned threat-model doc, cross-linked to
  the constraints that mitigate each entry.

### F3 — Independent audit before v1.0 — **NOTED, High**
- The `vault_spec.md` checklist already calls for an audit; elevate it to a release gate (mirroring
  the KeePassXC Molotnikov / ANSSI precedent) covering: format/parser, KDF integration, memory
  handling, hardware-token FFI, and the new AI-era delivery path (C27).

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

*Compiled June 2026. Audits the 27-constraint `vault_intent.yaml` for uncovered attack surface
across untrusted-input handling, secret-exposure side channels, data integrity, supply-chain
trust, crypto longevity, and project governance. CVE/standard precedents fetched and quoted;
spec-internal analysis marked `~ inferred`. All items are findings — no constraints added to
`vault_intent.yaml` without explicit approval.*
