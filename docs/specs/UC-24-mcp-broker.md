# UC-24 — Serve the handle broker to MCP clients (`blindkey mcp`)

> **Tech spec** · Accepted (initial) v0.1 · initial server shipped · July 2026
> **Constraints:** C27 (model-blind delivery / status-only), C13 · extends UC-16 (agent interface)
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the intent wins.

## 1. Goal

Let an MCP client (Claude Code, Cursor, any MCP host) reach the Blindkey handle broker over the
Model Context Protocol, so an agent can *use* a credential at a pre-registered destination
without ever receiving the credential. This is the distribution surface (MCP registries) and the
flagship of the AI-agent positioning.

## 2. Transport & protocol

- JSON-RPC 2.0 over **stdio** (newline-delimited), launched as `blindkey mcp`.
- Methods: `initialize`, `ping`, `tools/list`, `tools/call`; notifications (no `id`) are
  acknowledged silently. `initialize` advertises protocolVersion `2024-11-05`, `serverInfo`, and
  a `tools` capability.
- Implementation is hand-rolled over `serde_json` (no MCP SDK) — a deliberately small trusted
  surface for a security tool. See [`crates/blindkey-agent/src/mcp.rs`](../../crates/blindkey-agent/src/mcp.rs).

## 3. Tools (both return status/metadata only — never a secret)

| Tool | Input | Result |
|---|---|---|
| `list_handles` | — | Handle **metadata**: id, entry title, field name, destination ids, uses remaining, expiry. Never the credential. |
| `use_handle` | `handle_id`, `destination_id` | **Status only** (`ok`/`denied`/`locked`/`expired`/`not_found`/`error`). The credential is injected at the destination out of band and is never in the tool result. |

**Structural guarantee (C27):** the MCP layer never holds a secret type. `use_handle` delegates
to a `UseExecutor` that returns a status-only `UseResponse`; the plaintext never crosses into the
MCP module, so "no secret in a tool result" is guaranteed by types, not a runtime scan. Tests in
`mcp.rs` assert the invariant (initialize/tools/list shape, metadata-only listing, status-only
use, unknown-method JSON-RPC error).

## 4. Open design decision — the headless-approval channel

An MCP server is spawned **headless by its client** (no controlling TTY), so the broker's
existing human-approval-at-terminal prompt cannot fire on a `use_handle`. The initial server
therefore ships a `NoApprovalExecutor` that returns **`locked`** rather than deliver a secret —
it never silently bypasses the human-in-the-loop. This is a safe default, not the final answer.

Candidate approval channels (to be decided before `use_handle` delivers):

1. **Pre-authorization by handle scope** — creation via `blindkey agent allow` *is* the approval;
   the handle's tight TTL + use-count + fixed destination bound the blast radius. Simplest; no
   interactive prompt at use time.
2. **OS notification with approve/deny** — a desktop notification (or the GUI) approves each use.
3. **Side-channel TTY / companion process** — the broker runs on a real TTY; the MCP server talks
   to it over the existing Unix socket, and approval happens there.

Choosing among these is a security decision (it defines what possession of a handle authorizes)
and is tracked as a follow-up issue. Until then, `use_handle` is deliberately inert.

## 5. Non-goals (this iteration)

- Windows transport (the broker is Unix-socket only; named-pipe transport is tracked separately).
- Delivering a secret headlessly (blocked on §4).
- Live end-to-end verification against a specific MCP client — a HITL step, tracked as an issue.

## 6. Client configuration (example)

```jsonc
// Claude Code / Cursor MCP config
{ "mcpServers": { "blindkey": { "command": "blindkey", "args": ["mcp"] } } }
```
