# Sync guide — `--expect-min-version` + fleet provisioning (security-gap review P1)

> **Task:** Document `vault open --expect-min-version N` and a fleet provisioning example in
> `docs/guides/sync-to-untrusted-storage.md`.

## Problem (security-gap review gap)

C16 rollback detection relies on a **local, non-synced anchor**. On a **fresh machine** (no anchor
yet), any valid vault version is accepted — trust-on-first-use (TOFU). An attacker who serves an
**older but still valid** ciphertext to a newly provisioned laptop is **not** detected.

**Mitigation (a)** in intent C16: global flag `--expect-min-version N` sets a floor even when
`last_seen = 0`. Implementation: `floor = max(expect_min_version, last_seen)` in
`rollback_guard()`.

## Existing coverage (before this task)

| Artifact | Status |
|----------|--------|
| `rollback_guard()` + CLI global flags | Implemented |
| `cli.rs` integration test (TOFU + expect-min-version) | Implemented |
| Sync guide | One sentence (~line 59) |
| `CLI.md` | No global-flag section |
| Enterprise deployment guide | No fleet rollback section |

## Documentation requirements

1. **User guide** — expand rollback section:
   - When to use `--expect-min-version` vs anchor-only
   - Non-interactive behavior (exit **2**, pair with `--allow-rollback` only when intentional)
   - How an admin obtains **N** from a trusted machine (read local `.state` file)
2. **Fleet example** — copy-paste shell for MDM/CI provisioning a new host
3. **Cross-links** — `THREAT_MODEL.md`, `enterprise-deployment.md`, `CLI.md` global flags
4. **Constraint C16** — DOCUMENTATION test: sync guide + threat model mention TOFU + mitigation

## Flag semantics (verified in code)

| Flag | Scope | Effect |
|------|-------|--------|
| `--expect-min-version N` | Global | Floor for rollback check; applies on every open path |
| `--allow-rollback` | Global | Proceed after regression warning; anchor **not** lowered |

Exit code **2** when regression detected and not overridden (non-TTY or user declines).

## Admin workflow for **N**

1. On a **trusted** machine that already uses the vault normally, after any successful open:
   anchor file at platform path contains 8-byte little-endian `last_seen`.
2. Publish **N** via internal runbook (wiki, MDM env var `VAULT_EXPECT_MIN_VERSION`).
3. New machines: first headless open uses `--expect-min-version "$VAULT_EXPECT_MIN_VERSION"`.

Anchor path: `~/.local/share/vault/<vault_id_hex>.state` (Linux); see UC-07 §3.4.

## References

- `vault/vault_intent.yaml` C16
- `docs/specs/UC-07-untrusted-storage-sync.md` §3.4–3.5
- `docs/THREAT_MODEL.md` — fresh-device rollback residual risk
- `crates/vault-cli/tests/cli.rs` — `rollback` test
