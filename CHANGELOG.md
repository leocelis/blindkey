# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepablechangelog.com/en/1.1.0/), and the project aims to adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source project scaffolding: governance, security policy, CI/security automation,
  documentation skeleton, and the `vault-core` / `vault-cli` / `vault-hardware` workspace.
- Intent specification with 27 constraints across 10 groups ([vault_intent.yaml](vault_intent.yaml)),
  including AI-era hardening (CSPRNG generation `C26`, model-blind delivery `C27`).
- Research foundation: security spec, AI-era offensive-LLM threat landscape, and a security
  coverage-gap analysis ([research/](research/)).

### Notes
- This project is **pre-alpha**. No functional release exists yet; do not store real secrets.

[Unreleased]: https://github.com/leocelis/vault/commits/main
