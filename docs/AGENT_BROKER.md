# Agent broker (S-13 scaffold)

> **Status:** handle broker + MCP server both functional; live verification against a specific
> MCP client (Claude Code / Cursor) is still a tracked HITL step. See
> [UC-16](specs/UC-16-agent-interface-future.md), [UC-24](specs/UC-24-mcp-broker.md), and
> [ADR-0006](adr/0006-agent-broker-scaffold.md).

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

## ⚠️ `BLINDKEY_AGENT_AUTO_APPROVE` — test-only, never set this in real use

Setting `BLINDKEY_AGENT_AUTO_APPROVE=1` makes the broker approve every `use` **without** the
`[y/N]` terminal prompt. It exists only so the test suite and CI can drive the broker
non-interactively — it is **not** a supported deployment mode. Setting it in a real environment
removes the human-in-the-loop check this whole broker is built around: any handle a process (an
agent, a script, anything with your session) can reach becomes usable with zero confirmation. It
does not weaken §"What's structurally guaranteed" below — the secret still never returns through
the MCP/CLI response — but it does mean nobody is deciding whether *this particular use* should
happen. If you find yourself wanting to set it outside a test harness, what you actually want is
narrower, shorter-lived handles (`agent allow`'s TTL/use-count), not a way to stop being asked.

## What's structurally guaranteed vs. what's operational

- **Structural (true regardless of configuration):** the MCP/CLI response to a `use` request is
  always status-only (`ok`/`denied`/`locked`/…) — the secret type never enters that code path, so
  no misconfiguration can leak it *through the broker's response*. Verified in
  [docs/specs/UC-24](specs/UC-24-mcp-broker.md).
- **Not covered by that guarantee:** the **destination process itself** (the `--for-cmd` you
  registered) receives the real secret in its environment — that's the point, it needs it. "The
  agent never sees the secret" describes the AI agent driving the request, not every process
  downstream of your own configuration.
- **Operational, not structural:** whether a human actually reviews each use depends on running
  `blindkey agent run` interactively and not setting the flag above.

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
secret type never enters the MCP layer, so that is a structural guarantee. Full design:
[docs/specs/UC-24](specs/UC-24-mcp-broker.md).

```jsonc
// Claude Code / Cursor MCP config
{ "mcpServers": { "blindkey": { "command": "blindkey", "args": ["mcp"] } } }
```

Because an MCP server runs headless (no TTY), a *fresh* approval prompt can't fire inside it. So
`use_handle` delegates each request to an already-running `blindkey agent run` broker over the
same socket `blindkey agent use` speaks — the human approves on **that** broker's terminal, same
as any other use. Run `blindkey agent run` on a terminal before your MCP client needs to use a
handle. If no broker is listening, `use_handle` fails closed with `locked` — it never delivers a
secret without a human in the loop.

## What this is not

- Not a replacement for `blindkey get` (human clipboard workflow).
- Not defense against a hostile agent that can already run `blindkey get --stdout`.
