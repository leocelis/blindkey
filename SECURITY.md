# Security Policy

Blindkey is a credential-protection tool. We take security reports seriously and practice
coordinated disclosure. Thank you for helping keep Blindkey and its users safe.

## Supported versions

Blindkey **1.0.0** is the current stable release — the CLI and desktop app work today and have
**not** had an independent third-party security audit (recommended before enterprise adoption; see
[THIRD_PARTY_AUDIT.md](docs/THIRD_PARTY_AUDIT.md)). **On-disk format v1 is stable** (see
[ADR-0005](docs/adr/0005-format-v1-freeze.md)). Security fixes land on `main` and are tagged from
there — see [docs/RELEASE.md](docs/RELEASE.md).

| Version | Supported |
|---------|-----------|
| `1.0.0` (latest) | ✅ — report against this tag or `main` |
| `0.1.0-alpha.*` | ⚠️ upgrade to 1.0.0; alpha vault files open without migration |
| Pre-release / dev builds | report against commit hash |

crates.io (`cargo install blindkey-cli --locked`) is optional and not published yet.

## Reporting a vulnerability

**Please do not open a public GitHub issue, pull request, or discussion for security
vulnerabilities.**

Report privately via **GitHub Security Advisories**:
👉 https://github.com/leocelis/blindkey/security/advisories/new

If you cannot use that channel, email **[leo@leocelis.com](mailto:leo@leocelis.com)** with subject
line `VAULT-SECURITY` (see [MAINTAINERS.md](MAINTAINERS.md)). GHSA supports private threads without encryption; if you
need encrypted intake, ask in your initial report and we will provide an age public key
(see [UC-15](docs/specs/UC-15-vulnerability-reporting.md)).

Please include:

- The affected component, commit, and platform.
- A description of the issue and its security impact.
- Reproduction steps or a proof of concept (the more concrete, the faster we can act).
- Any suggested remediation.

## What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement of your report | within **72 hours** |
| Initial assessment & severity triage | within **7 days** |
| Fix or mitigation plan communicated | within **14 days** |
| Coordinated public disclosure | by mutual agreement, default embargo **90 days** |

We will keep you updated, credit you (if you wish), and request a CVE for qualifying issues.

## Safe harbor

We will not pursue or support legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service
  interruption.
- Only interact with accounts/data they own or have explicit permission to test.
- Give us a reasonable time to remediate before public disclosure.

## Scope

**In scope:** the cryptographic core, file-format parser, KDF integration, memory handling,
stanza/hardware integration, CLI secret-handling (clipboard, stdout, argv), release/build
integrity, and dependency supply chain.

**Out of scope (documented residual risk — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)):**
physical bus-level attacks on a TPM, a fully compromised OS kernel with root, attacks requiring
the attacker to already have the unlocked master key, social-engineering of the human user, and
**sync/storage metadata** (blob size, mtime, save frequency on untrusted backends — C17 accepted
residual, not entry-level plaintext).

## Our commitments to security (defensive posture)

- **Memory-safe Rust**, `#![forbid(unsafe_code)]` outside a vetted crypto-FFI boundary.
- **Audited libraries only** — no custom cryptographic primitives.
- **`cargo audit` / `cargo deny` / `cargo vet`** on every push and PR (not just before release); advisory exemptions are documented per-ID with rationale in [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).
- **Fuzzed parsers** for all untrusted input.
- **Reproducible builds + checksums** — see [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md).
- **Release quality gate** before `1.0.0` — see [docs/AUDIT_READINESS.md](docs/AUDIT_READINESS.md)
  (`just audit-ready`).
- **Export compliance** — this distribution contains cryptographic software; see
  [docs/EXPORT_COMPLIANCE.md](docs/EXPORT_COMPLIANCE.md) before importing, possessing, or using it
  if your jurisdiction regulates encryption software.
