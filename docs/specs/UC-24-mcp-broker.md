# UC-24 — Serve the handle broker to MCP clients (`blindkey mcp`)

> **Tech spec** · Accepted v0.2 · headless delivery via companion broker shipped · July 2026
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

## 4. The headless-approval channel — decided: companion-process delegation

An MCP server is spawned **headless by its client** (no controlling TTY), so a fresh
approval-at-terminal prompt cannot fire inside `blindkey mcp` itself. Three channels were
weighed (pre-authorization by handle scope, OS notification, side-channel companion process);
**option 3 was chosen and shipped**: `use_handle` is delegated via [`BrokerProxyExecutor`] to the
already-running Unix-socket broker (`blindkey agent run`) over the **same protocol** the CLI's
`blindkey agent use` already speaks ([`crate::broker::client_use`]). The human runs
`blindkey agent run` once, interactively, on a real terminal; every use from then on — whether
from the CLI or from an MCP client through this executor — is approved on *that* terminal via the
broker's existing, already-tested [`crate::approval::prompt_use`]. No new approval logic exists;
this only wires two already-built, already-tested pieces together, and the secret itself never
enters the MCP module at any point (§3's structural guarantee is unaffected).

Why option 3 over the alternatives: pre-authorization (option 1) would make handle *creation*
double as approval of *every future use*, weakening the per-use human check this broker was
built around; OS notifications (option 2) add a spoofable, platform-specific surface. Delegating
to a real running broker keeps the exact security property (a human approves each use, on a real
TTY) while making headless delivery possible.

**Fail-closed by design:** if no broker is listening, `BrokerProxyExecutor` returns `Locked` with
guidance — identical behavior to the original `NoApprovalExecutor`, which remains in the crate
for callers that want an explicitly inert executor.

**Verified end-to-end** (real vault, real broker, real MCP process, driven over actual stdio
JSON-RPC): a registered handle's secret was delivered into a spawned destination process's
environment, while the MCP tool response carried no secret material at any point.

## 5. Non-goals (this iteration)

- Windows transport (the broker is Unix-socket only; named-pipe transport is tracked separately).
- Automated integration test spinning up `blindkey agent run` + `blindkey mcp` as real
  subprocesses in CI (the crate-level test fakes the broker's *response*, not the full process
  pair; the full pair was verified manually — see commit history).
- Live verification against a specific MCP client (Claude Code / Cursor) — a HITL step, tracked
  as an issue.

## 6. Client configuration (example)

```jsonc
// Claude Code / Cursor MCP config
{ "mcpServers": { "blindkey": { "command": "blindkey", "args": ["mcp"] } } }
```
