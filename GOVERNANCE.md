# Governance

Blindkey is an open-source project run by its [maintainers](MAINTAINERS.md). This document describes
how decisions are made. It is intentionally lightweight; we will formalize it further as the
community grows.

## Principles

1. **Security over convenience.** When they conflict, the more secure option wins, and the tradeoff
   is documented (this is encoded in `constraint_satisfiability` in [blindkey_intent.yaml](blindkey_intent.yaml)).
2. **Decide before you build.** Significant design decisions are agreed (as a constraint or an ADR)
   *before* implementation.
3. **Everything verifiable.** Claims are backed by tests; decisions are backed by written rationale.
4. **Eyes beyond the code owner.** Sign-off from the code owner defined in CODEOWNERS is
   not independent review by itself. Crypto and format changes actively solicit external
   review as the community grows. **v1.0** requires the CP-7
   release quality gate (`just audit-ready` + IVD Rule 2 sweep) — see [ROADMAP.md](ROADMAP.md) M10.

## Decision tiers

| Change type | Process |
|-------------|---------|
| Docs, tests, refactors, non-security bugfixes | **Lazy consensus** — one approval, 24h for objections |
| New features / new constraints | Discussion → constraint added to `blindkey_intent.yaml` (with test) → one approval |
| **Cryptography, file format, KDF, release integrity** | **Code-owner sign-off required** (see CODEOWNERS) + an [ADR](docs/adr/); external review solicited per Principle 4 |
| Breaking format changes | Code-owner sign-off + ADR + `format_version` bump + migration plan |
| Adding/removing a maintainer | Code owner's decision |

## Architecture Decision Records

Hard-to-reverse decisions are captured as [ADRs](docs/adr/). An ADR is immutable once accepted;
to change a decision, write a new ADR that supersedes it.

## Changes to this document

Governance changes require code-owner sign-off and a CHANGELOG entry.
