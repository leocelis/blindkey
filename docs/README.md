# Vault documentation

Start here based on what you need:

| I want to… | Read |
|------------|------|
| Install or build | [INSTALL.md](INSTALL.md) |
| Use the CLI | [CLI.md](CLI.md) |
| Try a sample import | [../samples/README.md](../samples/README.md) |
| Sync to Drive / a VPS safely | [guides/sync-to-untrusted-storage.md](guides/sync-to-untrusted-storage.md) |
| Understand the threat model | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Read the crypto design | [CRYPTO.md](CRYPTO.md) |
| Read the file format | [FILE_FORMAT.md](FILE_FORMAT.md) |
| See system architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| See all 60 constraints + tests | [CONSTRAINT_INDEX.md](CONSTRAINT_INDEX.md) · [../vault_intent.yaml](../vault_intent.yaml) |
| Verify a release binary | [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md) |
| See what's shipped vs planned | [../ROADMAP.md](../ROADMAP.md) · [../CHANGELOG.md](../CHANGELOG.md) |
| Enterprise / fleet deployment | [ENTERPRISE_POSTURE.md](ENTERPRISE_POSTURE.md) · [guides/enterprise-deployment.md](guides/enterprise-deployment.md) |
| Contribute | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Report a security issue | [../SECURITY.md](../SECURITY.md) |
| Maintainer release gate | [AUDIT_READINESS.md](AUDIT_READINESS.md) · [RELEASE.md](RELEASE.md) |

## Specs (design)

22 use-case specs live in [specs/](specs/README.md). They are the design source for implementation;
start with UC-01 (install) and UC-04 (model-blind retrieval) if you are new to the project.

## Architecture decisions

[adr/](adr/README.md) — accepted cryptographic and format decisions.

## Guides

| Guide | Topic |
|-------|-------|
| [sync-to-untrusted-storage.md](guides/sync-to-untrusted-storage.md) | One encrypted file on untrusted cloud storage |
| [enterprise-deployment.md](guides/enterprise-deployment.md) | MDM env vars and fleet config |
| [accessibility.md](guides/accessibility.md) | Desktop GUI screen-reader spot-check |
