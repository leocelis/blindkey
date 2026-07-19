# Agent broker (S-13 scaffold)

> **Status:** scaffold — not a full MCP integration. See [UC-16](specs/UC-16-agent-interface-future.md)
> and [ADR-0006](adr/0006-agent-broker-scaffold.md).

Use this when an **AI agent needs a credential applied** without reading it. The agent receives
**status only** (`ok`, `denied`, …) — never the secret (C27).

## Quick start

```sh
# 1. Register a handle (entry + env var + command the broker will spawn)
blindkey agent allow github --dest-env GITHUB_TOKEN --for-cmd ./scripts/deploy.sh

# 2. Start the broker (unlocks vault, listens on Unix socket)
blindkey agent run

# 3. From another terminal / future MCP adapter — request use
blindkey agent use <handle-id> --dest 'env:GITHUB_TOKEN:./scripts/deploy.sh'
```

Each `use` prompts on the **broker's TTY**: entry name, destination id, uses remaining.

## Ops during agent sessions

- Prefer **short auto-lock** and **lock-on-blur** (GUI) — see [enterprise-deployment.md](guides/enterprise-deployment.md).
- Do **not** leave `blindkey agent run` active unattended.
- Handles expire (1 h default) and have a use budget (10 default).

## Files (local only — C23)

| Path | Purpose |
|------|---------|
| `$XDG_DATA_HOME/blindkey/agent-handles.json` | Registered handles |
| `$XDG_DATA_HOME/blindkey/agent-audit.jsonl` | Use audit (no secrets) |
| `$XDG_RUNTIME_DIR/blindkey-agent.sock` | Broker socket |

Override data dir: `BLINDKEY_AGENT_DATA_DIR` (tests).

## MCP server (`blindkey mcp`)

For MCP clients (Claude Code, Cursor, …), `blindkey mcp` speaks JSON-RPC 2.0 over stdio and
exposes the broker as two tools — `list_handles` (metadata only) and `use_handle` (status only).
Credentials are injected at the destination and are never returned in a tool result (C27); the
secret type never enters the MCP layer, so that is a structural guarantee. Full design and the
headless-approval design decision: [docs/specs/UC-24](specs/UC-24-mcp-broker.md).

```jsonc
// Claude Code / Cursor MCP config
{ "mcpServers": { "blindkey": { "command": "blindkey", "args": ["mcp"] } } }
```

Because an MCP server runs headless (no TTY), `use_handle` returns `locked` until an approval
channel is chosen (UC-24 §4) — it never delivers a secret without a human in the loop.

## What this is not

- Not a replacement for `blindkey get` (human clipboard workflow).
- Not defense against a hostile agent that can already run `blindkey get --stdout`.
