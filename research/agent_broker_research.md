# S-13 Agent Broker — Research

> **Task:** First concrete step toward UC-16 — handle broker, `vault_use`, OS approval gate.

## Problem

**Malware / AI agent with shell while unlocked:** C27 stops *incidental* capture (stdout/clipboard
defaults) but a hostile same-user agent can run `blindkey get --stdout`. Card recommends **S-13 agent
broker with OS approval gate** as the product path.

## v1 posture

- v1 ships **no MCP server** — UC-16 remains design exploration for full surface.
- Card #847 P1 delivers a **scaffold**: opaque handles, local broker, status-only IPC, TTY approval,
  one injection path (child env).

## Architecture (option a subset)

| Component | Scaffold |
|-----------|----------|
| Handles | Random 32-hex id; entry+field+dest registered via `blindkey agent allow` |
| Broker | `blindkey agent run` — unlock vault, Unix socket, per-request thread |
| IPC | NDJSON: `{"op":"use","handle","dest"}` → `{"status":"ok\|denied\|..."}` |
| Approval | stderr prompt on broker TTY; `BLINDKEY_AGENT_AUTO_APPROVE=1` tests only |
| Injection | Spawn pre-registered command with `env_var=secret` |
| Audit | Append-only `agent-audit.jsonl` — metadata only (C23) |

## Explicit non-goals (this PR)

- MCP tool registration / Cursor integration
- HTTP proxy injection path
- Encrypted handle store
- GUI approval surface
- `vault_list` exposing entry taxonomy to models

## References

- `docs/specs/UC-16-agent-interface-future.md`
- `docs/adr/0006-agent-broker-scaffold.md`
- `vault/blindkey_intent.yaml` C27 forward constraint
- Card #847 — Runtime / Same-User Attacker
