# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-06-10

## Context

Vault makes hard-to-reverse decisions (cryptographic primitives, on-disk format) that future
contributors will need to understand and that must not be silently changed. We need a durable,
low-ceremony record of *why* each decision was made.

## Decision

We record significant decisions as **Architecture Decision Records** (ADRs) in `docs/adr/`, using
the lightweight format popularized by Michael Nygard. An ADR is **immutable once accepted**; to
change a decision, write a new ADR that supersedes the old one (and link them).

Decisions touching cryptography, the file format, KDF, or release integrity require an ADR plus
two-maintainer sign-off (see [GOVERNANCE.md](../../GOVERNANCE.md)).

## Consequences

- The reasoning behind security-critical choices is preserved and reviewable.
- Constraints in [vault_intent.yaml](../../vault_intent.yaml) reference ADRs for deeper rationale.
- Slightly more process for big decisions — intentional, given the domain.
