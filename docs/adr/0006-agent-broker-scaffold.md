# ADR-0006: Agent broker scaffold (S-13)

- **Status:** Accepted (scaffold)
- **Date:** 2026-06-26
- **Research:** [research/agent_broker_research.md](../research/agent_broker_research.md)
- **Card:** Trello (internal ref) — P1 S-13 agent broker

## Context

Same-user agents with shell access can invoke `vault get --stdout` while a vault session is
unlocked. C27's forward constraint requires any future agent interface to deliver secrets only
via model-blind channels. UC-16 explores a handle-based MCP broker; v1 ships no agent API.

security-gap review asks for the **first concrete step**: handle broker + OS approval gate.

## Decision

1. Add **`vault-agent`** crate — handle store, Unix-socket broker, status-only IPC, TTY approval,
   child-process env injection.
2. Expose **`vault agent`** CLI: `allow`, `list`, `revoke`, `run`, `use`.
3. **No MCP server** in this ADR — IPC protocol is the MCP integration point later.
4. **No plaintext** in broker responses (C27); audit log is metadata-only (C23).

## Consequences

- Agents must talk to a **running broker** with an unlocked vault — not raw `vault get`.
- Approval is **TTY-owned** by the broker process (headless agents need future work — UC-16 Q3).
- One injection path only (env spawn); HTTP proxy deferred.

## Non-goals

- Replacing clipboard-first human workflow (v1 default unchanged).
- Claiming defense against root/kernel attacker.
