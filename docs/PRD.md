# Vault — Product Requirements Document (PRD)

> **Status:** Draft v0.1 · June 2026 · pre-alpha (no functional release yet)
> **Sources of truth:** [`vault_intent.yaml`](../vault_intent.yaml) (34 testable constraints),
> [`research/vault_spec.md`](../research/vault_spec.md),
> [`research/llm_offensive_threats.md`](../research/llm_offensive_threats.md),
> [`research/security_coverage_gaps.md`](../research/security_coverage_gaps.md).
> Where this document and the intent artifact disagree, **the intent artifact wins** —
> this PRD describes *who* and *why*; the intent describes *exactly what* and *how verified*.

---

## 1. One-line summary

**Vault is an open-source security layer for the AI era**: a local-first credential vault for
developers who work with AI every day and need a tool that is verifiably safe against AI-era
threats — and simple enough to actually understand.

## 2. The problem

Developers in 2026 operate in a new threat environment, and the tools they use were not
designed for it:

1. **AI agents sit on the machine.** Coding agents read terminal output, files, and tool
   results. A systematic review found **every tested coding agent vulnerable to prompt
   injection** with adaptive attack success above 85% — any secret a model can read, an
   attacker can instruct it to leak ([threats §7](../research/llm_offensive_threats.md)).
2. **Attackers have frontier models in the loop.** AI-orchestrated campaigns have run
   80–90% of an attack lifecycle autonomously; malware now queries LLMs at runtime
   ([threats §2–§3](../research/llm_offensive_threats.md)). Assume the attacker has a model
   for offline cracking, personalized phishing, and exfiltration.
3. **Existing tools leak or demand trust.** LastPass stored URLs in plaintext (enabling
   precision phishing after the 2022 breach); `pass` leaks entry names in the filesystem and
   git history; KeePassXC defaults to Argon2d and leaves in-memory secrets unencrypted;
   cloud managers require trusting a vendor's infrastructure
   ([spec](../research/vault_spec.md), intent `problem:` block).
4. **Existing tools are too complex to evaluate.** A developer cannot easily answer "what
   exactly does this protect me from, and how do I check?" Vault answers it with a public,
   testable constraint list.

## 3. Product principles

1. **Assume the vault file is stolen on day one.** Everything follows from that.
2. **Model-blind by default.** No plaintext secret ever lands on a channel an LLM reads
   by default. Opt-outs are explicit and warned.
3. **Zero plaintext.** Every entry field — including URLs, titles, tags, timestamps — lives
   inside the encrypted payload.
4. **Security claims are testable.** Every property is a numbered constraint with a `test:`
   field; nothing is marketing.
5. **Simple beats clever.** One binary, one file, one command to install. Complexity users
   can't verify is risk, not protection.
6. **Never lock the user out.** Any-of-N unlock: hardware factors are additive, the password
   always works, losing a YubiKey never loses the vault.

## 4. Target users (personas)

| # | Persona | Situation | What they need from Vault |
|---|---------|-----------|---------------------------|
| P1 | **AI-assisted developer** | Runs coding agents (terminal + editor) daily; keeps API keys, DB passwords, tokens in `.env` files and shell history | Secrets the agent can *use the results of* but never *read*; safe defaults with zero configuration |
| P2 | **Local-first / self-hoster** | Distrusts cloud vendors after LastPass-class breaches; syncs dotfiles via Git/Syncthing | A single opaque blob that is safe on untrusted storage, with rollback detection |
| P3 | **Migrator from `pass` / KeePassXC** | Has an existing store; knows its leaks (plaintext filenames, Argon2d, memory) | One-command import, strictly stronger defaults, familiar CLI ergonomics |
| P4 | **Automation / CI user** | Needs secrets in scripts and headless environments | Explicit, warned, non-default plaintext paths (`--stdout`, export); deterministic non-interactive behavior (exit codes, no prompts when not a TTY) |
| P5 | **Security researcher / auditor** | Wants to verify claims before recommending | Public constraints with tests, fuzzed parsers, reproducible signed builds, coordinated disclosure |

## 5. Major use cases

Each use case lists the constraints (from `vault_intent.yaml`) that bind it. Acceptance
criteria live in the constraints' `test:` fields — they are not duplicated here.

### UC-1 · First-run: install and create a vault
**Persona:** all · **Constraints:** C20, C2, C4, C5, C7, C8

A developer installs with one command (`cargo install vault-cli`; static binary, no runtime
deps) and runs `vault init`. They choose a master password; Vault generates a random data
key, wraps it in a password stanza (Argon2id, m=64 MiB/t=3/p=4 by default), and writes a
single versioned file. First entry added in under 60 seconds and at most 5 prompts.

### UC-2 · Generate a credential that is provably strong
**Persona:** P1–P4 · **Constraints:** C26

`vault gen` produces a CSPRNG password (rejection-sampled, no modulo bias) — charsets
`alnum`/`ascii`/EFF-diceware words — with a documented bit count. Human- or LLM-invented
passwords are the anti-pattern: AI-assisted cracking recovered 87–88% of
Llama/DeepSeek-generated passwords ([threats §5.1](../research/llm_offensive_threats.md)).
On `vault add`, a user-supplied password below ~60 bits triggers a warning suggesting
`vault gen` (warn, never block).

### UC-3 · Store a secret
**Persona:** all · **Constraints:** C18, C19, C17, C11

`vault add NAME` stores title, username, password, URL, notes, tags, OTP secret, and
timestamps — **all** inside the AEAD payload. `strings vault.vlt` reveals nothing. Protected
fields (password, OTP) get a second inner-stream encryption layer. In memory, secrets live
only in zeroize-on-drop types.

### UC-4 · Retrieve a secret while an AI agent is watching (the flagship use case)
**Persona:** P1 · **Constraints:** C27, C13, C23

The developer has a coding agent attached to their terminal. They run
`vault get github-prod --field password`. The secret goes **to the OS clipboard, never to
stdout** — the agent's transcript of the session contains no plaintext. The clipboard
auto-clears after 30 s (configurable). Vault makes zero network calls, so there is no
side channel to any model or service. This is the model-blind delivery guarantee: *the
agent can be told the secret was delivered; it can never read it.*

### UC-5 · Use a secret in a script or CI (explicit, warned opt-out)
**Persona:** P4 · **Constraints:** C27, C21, SC5

`vault get NAME --stdout` prints the secret for piping — and prints a warning to stderr
("plaintext written to stdout; ensure no AI agent or untrusted process captures this
stream"). `vault export --format json` similarly requires a security warning. Plaintext
paths exist for humans and scripts; none of them are silent and none are the default.

### UC-6 · Find and manage entries day-to-day
**Persona:** all · **Constraints:** C21, C18 (via SC2), C25

`vault ls --search`, `vault edit`, `vault rm` (with confirmation). Search runs in-memory
over the decrypted payload after unlock — no plaintext index ever touches disk. An idle
session auto-locks after 5 minutes (configurable), zeroing all key material.

### UC-7 · Sync the vault over storage you don't trust
**Persona:** P2 · **Constraints:** C17, C16, C10, C9

The vault is one opaque blob, safe to put in Git, Dropbox, or Syncthing: the backend learns
only total size and modification time — not entry names, counts, or change patterns. A
monotonic version counter anchored in local (unsynced) state detects a sync backend serving
an old copy: on regression, Vault warns and aborts by default (exit code 2 when
non-interactive). No other free local manager detects whole-file rollback.

### UC-8 · Recover from a sync conflict
**Persona:** P2 · **Constraints:** C21, C16, SC3

Two machines wrote the vault concurrently. `vault merge OLD.vlt NEW.vlt` performs a manual,
unlocked merge. (Per-entry mergeable encryption is deliberately prohibited — deterministic
per-entry encryption enables leakage-abuse reconstruction; Grubbs et al. 2017.)

### UC-9 · Add a hardware factor — without lockout risk
**Persona:** P1, P2 · **Constraints:** C5, C6, C14, C15

The user enrolls a FIDO2 key (`hmac-secret` via libfido2), YubiKey challenge-response, TPM
PCR-sealed stanza, macOS Secure Enclave, or Windows DPAPI as an *additional* way to unlock.
Any single stanza unlocks (OR model); the password stanza always remains. Losing the
hardware never loses the vault. TPM PCR drift after a firmware update produces a clear
message and a `vault re-enroll-tpm` path, not a lockout.

### UC-10 · Open a stale or hostile vault file safely
**Persona:** all · **Constraints:** C2 (incl. ceiling), C7, C8, C9

Vault treats its own file as untrusted input. Bad magic → "not a vault file". Newer format
version → clear upgrade message. KDF params below the OWASP floor → prominent warning +
upgrade offer (never silent). KDF params absurdly *high* (a memory-exhaustion trap) →
rejected before allocation. Tampered KDF params and a wrong password both fail the stanza
unwrap with one intentionally ambiguous "invalid credentials or tampered header" — no oracle;
the data-key-keyed header HMAC then catches any other header tampering. Parsers are fuzzed in CI.

### UC-11 · Keep KDF cost calibrated as hardware improves
**Persona:** P2, P5 · **Constraints:** C2, C22, C8

`vault tune` benchmarks Argon2id on the current machine and recommends parameters targeting
~300 ms. `vault upgrade-kdf` re-derives in place. Parameters live in the file (never
compiled-in, never server-supplied — the LastPass anti-pattern), and the floor is enforced
on every open.

### UC-12 · Migrate from an existing manager
**Persona:** P3 · **Constraints:** C21 (import), C26

`vault import --format txt|json` (with pass/gopass and KeePassXC CSV paths on the roadmap,
M6/M9) moves an existing store into Vault in one command. Weak imported passwords trigger
the C26 entropy warning, nudging rotation via `vault gen`.

### UC-13 · Verify what you're running
**Persona:** P5 · **Constraints:** C24, C23, C3; release pipeline (M8)

Releases are reproducible, Sigstore/cosign-signed, with SLSA provenance
([VERIFYING_RELEASES](VERIFYING_RELEASES.md)). Dependencies are license-allowlisted and
`cargo audit`/`cargo deny` gated. `strace` shows zero network syscalls during operation.
Every security property can be checked against a numbered constraint with a test.

### UC-14 · Survive a compromised-adjacent machine
**Persona:** P1, P2 · **Constraints:** C11, C12, C25, C13

Not full malware-with-root resistance (out of scope — see
[THREAT_MODEL](THREAT_MODEL.md)), but meaningful hardening against the common cases:
secrets in mlock'd, zeroized memory; core dumps disabled; constant-time comparisons;
clipboard auto-clear; auto-lock on idle. A crashed process or a stolen swap file does not
hand over the keys.

### UC-15 · Report a vulnerability
**Persona:** P5 · **Reference:** [SECURITY.md](../SECURITY.md)

Private reporting via GitHub Security Advisories, 72 h acknowledgement, safe harbor,
90-day coordinated disclosure. Pre-1.0, an independent third-party audit gates v1.0 (M10).

### UC-16 · (Future, post-v1) An AI agent uses the vault *without ever seeing a secret*
**Persona:** P1 · **Constraints:** C27 forward constraint · **Status:** explicitly out of v1

v1 ships no agent interface. But C27 already binds any future one: an agentic/MCP interface
may deliver secrets only via model-blind channels (clipboard, OS keychain handoff, direct
field injection at the destination) — never as a tool result the model ingests. This is the
documented north star for the post-1.0 "bigger vision" (files, databases, application
secrets) in [ROADMAP](../ROADMAP.md).

### UC-17 · Quick-capture from a messy secrets file
**Persona:** P1, P3 · **Constraints:** C21, C26, C18, C19, C27

A developer has a `keys.txt` — a pile of API keys and tokens with no real structure (some
`key=value`, some bare lines, blocks split by blank lines or `---` rulers).
`vault import --format raw keys.txt` parses it leniently, classifies secret-vs-label lines by
entropy and known provider prefixes, and shows a **masked** interactive review (never the full
secret) so wrong guesses are cheap to fix before a single atomic save. Afterwards the keys are
findable via `vault ls --search` (UC-6) and retrievable to the clipboard via `vault get` (UC-4) —
the model-blind "easier than 1Password" on-ramp. The lenient sibling of UC-12; the entry's
optional `kind` (login/apikey/note) lets `get` surface the key directly. See
[spec UC-17](specs/UC-17-quick-capture-raw-import.md).

### UC-18 · (Future, post-v1) Use the vault through a fast, native UI
**Persona:** all (P1/P3 first) · **Constraints:** C20, C11, C12, C25, C27, C5 · **Status:** UI is post-v1; the core-API decision it needs is v1

A graphical or terminal front-end that is fast, simple, secure, and integrates nicely with the
host OS — **without forking the Rust security core**. Every UI is a thin client over `vault-core`
(the Signal `libsignal` / Mozilla UniFFI pattern): pure-Rust shells (`ratatui` TUI, then an `egui`
window) keep C20's single-binary/no-Node property and keep secrets inside the Rust boundary; a
native **SwiftUI** shell (linked via uniffi) delivers best-in-class macOS integration — Touch ID
and Secure Enclave unlock, which map directly to the **C5** keychain stanza. The cross-cutting
rule: **copy-not-display by default** (C27), on-screen reveal is opt-in, auth-gated, and time-boxed.
Electron is rejected (violates C20, ~10× the memory, unzeroable JS heap — the 1Password-8 lesson).
The only piece that lands in v1: making the CP-4 `vault-core` API UI-agnostic and FFI-ready so every
shell is a thin client. See [research/ui_architecture.md](research/ui_architecture.md) and
[spec UC-18](specs/UC-18-native-ui.md).

## 6. Out of scope for v1 (non-goals)

From the intent's `non_goals:` — hosted sync service, browser extension, GUI, team vaults,
custom crypto, and any LLM/agent inside the trust boundary. Residual risks accepted and
documented in [THREAT_MODEL](THREAT_MODEL.md): kernel-level compromise with root, TPM bus
attacks, social engineering of the user.

## 7. Success metrics (v1)

| Metric | Target | How measured |
|---|---|---|
| Install → first secret stored | < 60 s, ≤ 5 prompts | C20 integration test |
| Unlock latency (default KDF) | < 500 ms on 4-core/8 GiB | C22 benchmark in CI |
| Plaintext leakage from file | zero bytes of entry content | C18 `strings`/`xxd` tests |
| Secrets on LLM-readable default channels | zero | C27 integration tests |
| Constraint coverage | 27/27 PASS or justified NEEDS_REVIEW | IVD Rule 2 audit, [`tests/constraint_coverage.rs`](../tests/constraint_coverage.rs) |
| Parser robustness | no panics/OOM across fuzz corpus | `fuzz/` targets in CI |
| Independent audit | completed before v1.0 tag | M10 |

## 8. Release plan

Mapped to [ROADMAP](../ROADMAP.md): M2 file format → M3 crypto core → M4 memory hardening
→ M5 read/write + rollback → M6 CLI (UC-1…8, 10–12) → M7 hardware stanzas (UC-9) → M8
distribution & trust (UC-13) → M9 hardening backlog (C35+ Part-2 candidates from
[security_coverage_gaps](../research/security_coverage_gaps.md)) → M10 audit → v1.0.

## 9. Open questions

1. **Candidate constraints C28+** — ✅ resolved 2026-06-10 (intent v1.2.0): the high-severity
   batch was promoted — ANSI-safe output (A2→C28), export escaping (A3→C29), parser
   robustness (A4→C30), no-secrets-on-argv (B1→C31), atomic saves (C1→C32), clipboard
   concealment (B2→C33), signed releases (D1→C34); KDF ceiling (A1) and Unicode NFC (E2)
   folded into C2. The remaining gaps (B3, C2, C3, D2, E1) are the Part-2 backlog (C35+),
   each via its own ADR — see [ROADMAP](../ROADMAP.md).
2. **Import breadth at launch** — ship pass/KeePassXC importers in v1 (P3 acquisition) or
   defer to M9?
3. **Naming/positioning** — "credential vault" vs the broader "security layer for the AI
   era" as scope grows post-1.0 (files, databases, app secrets).
4. **Clipboard on Wayland/headless** — ✅ resolved 2026-06-10 (intent v1.3.0): C27 mandates
   refusal with exit code 7 and guidance toward `--stdout`; never a silent stdout fallback.
