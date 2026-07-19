# Blindkey documentation

Start here based on what you need:

| I want to… | Read |
|------------|------|
| Seal files for untrusted cloud storage | [CLI.md](CLI.md) (`blindkey seal` / `open` / `peek`) · [specs/UC-23-sealed-file-storage.md](specs/UC-23-sealed-file-storage.md) |
| Install or build | [INSTALL.md](INSTALL.md) |
| Use the CLI | [CLI.md](CLI.md) |
| Try a sample import | [../samples/README.md](../samples/README.md) |
| Sync to Drive / a VPS safely | [guides/sync-to-untrusted-storage.md](guides/sync-to-untrusted-storage.md) |
| Understand the threat model | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Read the crypto design | [CRYPTO.md](CRYPTO.md) |
| Read the file format | [FILE_FORMAT.md](FILE_FORMAT.md) |
| See system architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| See all 66 constraints + tests | [CONSTRAINT_INDEX.md](CONSTRAINT_INDEX.md) · [../blindkey_intent.yaml](../blindkey_intent.yaml) |
| Verify a release binary | [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md) |
| See what's shipped vs planned | [../ROADMAP.md](../ROADMAP.md) · [guides/hardware-factor-status.md](guides/hardware-factor-status.md) |
| Enterprise / fleet deployment | [ENTERPRISE_POSTURE.md](ENTERPRISE_POSTURE.md) · [guides/enterprise-deployment.md](guides/enterprise-deployment.md) |
| Agent / AI workflow (scaffold) | [AGENT_BROKER.md](AGENT_BROKER.md) · [specs/UC-16-agent-interface-future.md](specs/UC-16-agent-interface-future.md) |
| Contribute | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Report a security issue | [../SECURITY.md](../SECURITY.md) |
| Supply-chain policy & advisory exemptions | [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) |
| Export compliance (contains cryptography) | [EXPORT_COMPLIANCE.md](EXPORT_COMPLIANCE.md) |
| Contribute (sign-off / DCO) | [../CONTRIBUTING.md](../CONTRIBUTING.md) · [../DCO](../DCO) |
| Maintainer release gate | [AUDIT_READINESS.md](AUDIT_READINESS.md) · [RELEASE.md](RELEASE.md) |
| Commission third-party audit | [AUDIT_COMMISSION.md](AUDIT_COMMISSION.md) · [THIRD_PARTY_AUDIT.md](THIRD_PARTY_AUDIT.md) |

## Specs (design)

22 use-case specs live in [specs/](specs/README.md). They are the design source for implementation;
start with UC-01 (install) and UC-04 (model-blind retrieval) if you are new to the project.

## Architecture decisions

[adr/](adr/README.md) — accepted cryptographic and format decisions.

## Guides

| Guide | Topic |
|-------|-------|
| [sync-to-untrusted-storage.md](guides/sync-to-untrusted-storage.md) | One encrypted file on untrusted cloud storage |
| [hardware-factor-status.md](guides/hardware-factor-status.md) | Which hardware factors work in v1 vs deferred |
| [size-padding-padme.md](guides/size-padding-padme.md) | Optional Padmé padding for sync size privacy |
| [enterprise-deployment.md](guides/enterprise-deployment.md) | MDM env vars and fleet config |
| [accessibility.md](guides/accessibility.md) | Desktop GUI screen-reader spot-check |
