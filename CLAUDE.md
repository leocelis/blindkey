# Blindkey — agent instructions

This repo is built by two maintainers working in parallel lanes, each with an AI agent.
**Before doing any work, read [`cowork.yaml`](cowork.yaml)** — it defines the branch model,
path ownership, claim protocol, and the agent conduct rules (AG1–AG10). They are binding.

Order of authority: [`blindkey_intent.yaml`](blindkey_intent.yaml) (testable constraints C1–C66)
→ [`docs/specs/`](docs/specs/README.md) (designs per use case) → [`ROADMAP.md`](ROADMAP.md)
(critical path + sidequests) → [`cowork.yaml`](cowork.yaml) (process).

Non-negotiables (details in CONTRIBUTING.md and cowork.yaml):

- Read the relevant constraints and spec **before** implementing; include a
  PASS/FAIL/NEEDS_REVIEW constraint table in every PR that touches one.
- Never weaken a constraint to make code pass — conflicts become intent amendments.
- Secret-handling rules: no custom crypto, no `unsafe` outside the FFI module, no
  `Vec<u8>`/`String` for secrets, no `==` on secret bytes, no secrets on argv or in logs.
- `just check` green before every push; never force-push; changes to protected paths
  (see CODEOWNERS) always go via PR with code-owner approval.
- Do not commit/push without your maintainer's instruction in the session.
