# Security Policy

Vault is a credential-protection tool. We take security reports seriously and practice
coordinated disclosure. Thank you for helping keep Vault and its users safe.

## Supported versions

Vault is **functional pre-1.0** — the CLI and desktop app work today, but the on-disk format may
still change before `1.0.0`. Signed GitHub Releases and crates.io (`cargo install vault-cli --locked`)
ship from tag push — see [docs/RELEASE.md](docs/RELEASE.md). Once we ship versioned releases,
this section will list supported version ranges. Until then, `main` is the development branch and
bug reports are welcome against it.

## Reporting a vulnerability

**Please do not open a public GitHub issue, pull request, or discussion for security
vulnerabilities.**

Report privately via **GitHub Security Advisories**:
👉 https://github.com/leocelis/vault/security/advisories/new

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
the attacker to already have the unlocked master key, and social-engineering of the human user.

## Our commitments to security (defensive posture)

- **Memory-safe Rust**, `#![forbid(unsafe_code)]` outside a vetted crypto-FFI boundary.
- **Audited libraries only** — no custom cryptographic primitives.
- **`cargo audit` / `cargo deny`** in CI; builds fail on High/Critical advisories.
- **Fuzzed parsers** for all untrusted input.
- **Reproducible builds + signed releases** (Sigstore/cosign + SLSA provenance) so you can verify
  what you run — see [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md).
- **Release quality gate** before `1.0.0` — see [docs/AUDIT_READINESS.md](docs/AUDIT_READINESS.md)
  (`just audit-ready`).
