# Agent broker (S-13 scaffold)

> **Status:** scaffold — not a full MCP integration. See [UC-16](specs/UC-16-agent-interface-future.md)
> and [ADR-0006](adr/0006-agent-broker-scaffold.md).

Use this when an **AI agent needs a credential applied** without reading it. The agent receives
**status only** (`ok`, `denied`, …) — never the secret (C27).

## Quick start

```sh
# 1. Register a handle (entry + env var + command the broker will spawn)
vault agent allow github --dest-env GITHUB_TOKEN --for-cmd ./scripts/deploy.sh

# 2. Start the broker (unlocks vault, listens on Unix socket)
vault agent run

# 3. From another terminal / future MCP adapter — request use
vault agent use <handle-id> --dest 'env:GITHUB_TOKEN:./scripts/deploy.sh'
```

Each `use` prompts on the **broker's TTY**: entry name, destination id, uses remaining.

## Ops during agent sessions

- Prefer **short auto-lock** and **lock-on-blur** (GUI) — see [enterprise-deployment.md](guides/enterprise-deployment.md).
- Do **not** leave `vault agent run` active unattended.
- Handles expire (1 h default) and have a use budget (10 default).

## Files (local only — C23)

| Path | Purpose |
|------|---------|
| `$XDG_DATA_HOME/vault/agent-handles.json` | Registered handles |
| `$XDG_DATA_HOME/vault/agent-audit.jsonl` | Use audit (no secrets) |
| `$XDG_RUNTIME_DIR/vault-agent.sock` | Broker socket |

Override data dir: `VAULT_AGENT_DATA_DIR` (tests).

## What this is not

- Not a replacement for `vault get` (human clipboard workflow).
- Not defense against a hostile agent that can already run `vault get --stdout`.
- Not MCP — wire your adapter to the same NDJSON protocol as `vault agent use`.
