# UC-16 — An AI Agent Uses the Vault Without Ever Seeing a Secret

> **Status: DESIGN EXPLORATION — post-v1, non-binding.**
> Nothing in this document is committed for v1. v1 ships **no** agent interface
> (intent `non_goals`; [ROADMAP](../../ROADMAP.md) "bigger vision"). Every section below is
> exploration, not design-of-record. The only binding text is C27's FORWARD CONSTRAINT, which
> any future implementation of these ideas must satisfy.

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-16 · **Constraints:** C27 (forward constraint); context: C13, C16, C23, C26
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals *(DESIGN EXPLORATION)*

**Problem statement.** Agents need credentials to do useful work — deploy with an API token,
run a migration with a DB password, log into a dashboard. But prompt injection makes handing an
agent plaintext unacceptable: the systematic review grounding this repo's threat model found
**every tested coding agent vulnerable, with adaptive attack success > 85%**, and production
agents from multiple vendors hijacked to exfiltrate credentials via poisoned PR titles, issues,
and comments ([threats §7](../../research/llm_offensive_threats.md)). An LLM cannot reliably
separate instructions from data; **any secret the model can read, an attacker can instruct it
to leak**. The v1 answer is refusal (option c). This document explores what a *useful* answer
could look like post-1.0 without weakening that property.

Goal of any future design, restated from C27: the agent can **cause a credential to be used**;
it can never **read** one. The LLM's context window is a public place.

## 2. Prior art *(DESIGN EXPLORATION)*

### 2.1 Open source / industry

- **1Password Secure Agentic Autofill** (cited by intent C27;
  [blog](https://1password.com/blog/closing-the-credential-risk-gap-for-browser-use-ai-agents),
  [developer docs](https://developer.1password.com/docs/agentic-autofill/)) — ✓ verified June
  2026: the agent drives a (remote/headless) browser and *requests* a login; 1Password matches
  the credential, prompts the **human on their 1Password desktop app** for each autofill
  request; on approval the credential travels over an encrypted channel (Noise-framework,
  forward-rotating key material) to a headless 1Password browser extension, which injects only
  the minimum required fields into the login form. "The AI agent and underlying LLM never need
  to see nor handle the credentials." Early access ran with Browserbase's Director agent.
  This is the closest production system to option (b) below.
- **MCP (Model Context Protocol)** — the natural transport for option (a); note the same repo
  research shows MCP tooling is also how *attackers* orchestrate agents
  ([threats §2](../../research/llm_offensive_threats.md)) — an MCP surface is attack surface.
- **OWASP LLM Top 10 (2025)** — LLM01 prompt injection as the head of the class; already in the
  research sources index.

### 2.2 Academic / standards

- **CaMeL — "Defeating Prompt Injections by Design"** (Google DeepMind,
  [arXiv:2503.18813](https://arxiv.org/abs/2503.18813)): ✓ verified — extracts control flow and
  data flow from the *trusted* user query so untrusted retrieved data can never alter program
  flow; attaches **capabilities** to values and enforces security policies at tool-call time;
  solves 77% of AgentDojo tasks *with provable security* (vs 84% undefended). Directly
  relevant: a vault handle is a capability; `vault_use` is a policy-enforced tool call.
- **Confused deputy** (Hardy, 1988, *ACM SIGOPS*): the classic frame for §6 — the broker is a
  deputy wielding authority (the credential) on behalf of a possibly-confused requester (the
  injected agent). Capability discipline, not identity checks, is the historical fix.
- Control/data-flow separation literature generally (taint tracking, information-flow control)
  — CaMeL is the modern agent-shaped instance; the design below borrows its stance: **the
  defense is structural, not model-behavioral**. We assume the model is compromised.

## 3. Proposed design *(DESIGN EXPLORATION — sketch of option (a))*

### 3.0 The three architecture options

| | Option | Essence | Verdict (exploratory) |
|---|---|---|---|
| (a) | **Handle-based MCP broker** | MCP server returns opaque handles; a local broker injects the real secret at the destination | most general; sketched below |
| (b) | **1Password-style agentic autofill** | agent drives a browser; human approves; extension injects; model blind | proven shape, but browser-scoped and needs an extension — a v1 non-goal |
| (c) | **Refusal** (v1 status quo) | vault not exposed to agents at all; human-in-the-loop clipboard only (C13/C27) | shipping today; the baseline every option must beat *without losing C27* |

### 3.1 Sketch: MCP tool surface (option a)

Two tools. Deliberately no third.

```
vault_list() -> [ { handle, label, destination_types } ]
    Redacted listing of entries the user has EXPLICITLY marked agent-visible
    (default: none — entry names are protected metadata, C17/C18; exposing the
    full taxonomy to a model is itself a leak).

vault_use(handle, destination) -> { ok | denied | expired }
    Asks the broker to inject the secret for `handle` at `destination`.
    Returns ONLY a status. Never field contents. Never error text that echoes
    secret material.
```

- A **handle** is an opaque, single-vault-scoped token (random ID; never derived from entry
  content), bound at creation to: an entry+field, an allowlist of destination types, a TTL,
  and a use budget. It is a *capability in the CaMeL sense* — possession authorizes asking,
  not receiving.
- `destination` must match an **allowlisted destination type** (§3.2) and a **pre-registered
  destination value** (e.g., the exact env var name + command, or the exact host). Free-form
  destinations from the agent are refused — the agent chooses *among* user-registered
  destinations; it never defines one.

**Why `vault_get`-returning-plaintext must never exist:** C27's forward constraint prohibits
returning plaintext "on any channel an LLM reads (including a tool result an agent ingests)".
A `vault_get` tool result lands verbatim in the model's context — from there, one successful
injection exfiltrates it (>85% adaptive success, §1). No rate limit, approval gate, or scope
helps once plaintext has entered the context window: **the context window is the leak**. This
is the one non-negotiable inherited from the intent; everything else in this spec is
adjustable.

### 3.2 Injection paths and their trust boundaries

| Destination type | Mechanism | Trust boundary analysis |
|---|---|---|
| **Child-process env** | broker spawns the target command itself, injecting `SECRET=...` into the child's environment; agent supplies only the (pre-registered) command identity | Secret exists in broker + child memory. Never in agent context, shell history, or argv (gap B1 honored). Boundary risks: child's own logging/error output may echo env; `/proc/<pid>/environ` readable by same-uid processes — same-uid malware is already partially out of scope ([THREAT_MODEL](../THREAT_MODEL.md)), but the agent must not be able to *read* the child's stdout if the child might echo the secret — broker pipes child output through a redaction filter or returns only exit status. |
| **HTTP header via local proxy** | broker runs a localhost proxy; agent sends requests *through* it with a placeholder header; proxy swaps in the real value and forwards over TLS to an allowlisted host | Secret exists in proxy memory and on the wire to the destination host (TLS). Boundary risks: agent controls the request *body and path* — see confused deputy (§6); host allowlist must be exact (no wildcard domains); proxy must strip the real header from any error/redirect echo back to the agent; CONNECT-style tunneling must be disabled (proxy must see and rewrite the request, and must refuse non-allowlisted hosts). |
| **Clipboard (human handoff)** | broker copies to OS clipboard exactly as `vault get` does today (C13 auto-clear; B2 transient-clipboard flags) | Secret reaches the human's paste target. Boundary risks: same as v1 — clipboard managers, cloud clipboard sync (gap B2). The *agent* gains nothing readable; this path is the degenerate case that already exists and is the fallback when no machine destination fits. |

In all three paths the broker is a separate local process holding the unlocked session; the MCP
server component never holds plaintext — it forwards requests to the broker over a local IPC
channel that the agent cannot impersonate (peer-credential checked socket).

### 3.3 Human approval gate (per use)

Every `vault_use` triggers an **OS-level prompt rendered by the broker** (native dialog or the
terminal the broker owns), showing: entry label, destination (resolved, not agent-supplied
text), requesting agent identity, and remaining budget/TTL. Approve = this one use.

- **Not agent-mediated:** the prompt must be unspoofable by the agent — it comes from the
  broker process on a surface the agent cannot draw on. An "approval" relayed through the
  agent's own chat UI is worthless (the model would be asked to confirm its own hijacking).
  This mirrors 1Password's choice to prompt on the user's *desktop app*, outside the agent.
- Optional `--session` grants (N uses / M minutes for one handle+destination) are an
  ergonomics escape hatch; default is per-use. The C25 auto-lock applies to the broker session.

### 3.4 Audit log (local only)

Append-only local log of every handle creation, use request, approval/denial, and injection —
timestamp, handle, destination, outcome. **Never the secret; never to the network (C23).**
Stored encrypted alongside the local state file (C16's XDG path), since use patterns are
metadata in the C17 sense. Purpose: after-the-fact detection of confused-deputy abuse (§6) and
input to rate-limit tuning.

## 4. Alternatives considered *(DESIGN EXPLORATION)*

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| (c) Refusal / clipboard-only (v1) | zero new attack surface; C27 trivially holds | agent workflows need a human for every secret touch | ✅ **v1 status quo; the bar to beat** |
| (a) Handle broker over MCP | general (env, HTTP, clipboard); capability discipline; per-use human gate | new trusted broker component; confused deputy residual (§6); real engineering | sketched here; candidate for post-1.0 |
| (b) 1Password-style autofill | production-proven shape; narrow, well-understood injection point | browser-scoped; requires an extension (v1 non-goal) and an approval surface app | pattern to copy *if/when* a browser surface exists |
| `vault_get` returning plaintext to the agent | trivial; what every naive MCP wrapper does | violates C27 forward constraint; >85% adaptive injection success ⇒ assume leaked | ❌ **prohibited, permanently** |
| Plaintext to agent with "redaction" / output filtering | cheap | filtering the model's *output* doesn't stop encoded/staged exfiltration; secret is already in context | ❌ |
| Model-behavioral defenses (system-prompt rules, classifiers) | no architecture change | exactly the class CaMeL exists to replace; porous by the repo's own research (§7, R6) | ❌ as a primary control; fine as defense-in-depth |
| Broker as cloud service | multi-device | violates local-first and C23 outright | ❌ |

## 5. Constraint compliance map *(DESIGN EXPLORATION — against C27's forward constraint)*

| Constraint | How the sketch satisfies it |
|---|---|
| C27 (forward) | no tool returns plaintext; delivery is clipboard / env-injection / proxy-injection — all model-blind channels named by the constraint ("direct field injection at the destination"); tool results are status codes only |
| C27 (no LLM in trust boundary) | the MCP server holds no plaintext; the broker holds the session and talks to the model only via status responses; the model remains *outside* the boundary |
| C13 / B2 | clipboard path reuses v1 clearing + transient flags unchanged |
| C17 / C18 | `vault_list` exposes only user-designated entries; default-empty; full taxonomy never offered to a model |
| C23 | broker/MCP are localhost-only; proxy egress goes only to user-allowlisted destination hosts as part of the *user's* requested operation — never vault-initiated telemetry; audit log never leaves the machine |
| C25 | broker session obeys auto-lock; locked broker fails all `vault_use` closed |
| C26 | unchanged; handles are random IDs from OsRng |

## 6. Threat analysis: what injection can still do *(DESIGN EXPLORATION)*

Handles do not end the game; they change it from *exfiltration* to **confused deputy**: a
hijacked agent can still *legitimately ask* for a credential to be used at an **allowed**
destination, with attacker-chosen surrounding parameters.

Concrete example (HTTP path): handle scoped to `api.github.com`, header injection approved by
a habituated user → injected agent crafts `POST /repos/attacker/exfil/issues` — the *token* is
never read, but it is *spent* on attacker-chosen actions at the allowed host. Env path
analogue: the pre-registered command runs in an attacker-arranged working directory or with
poisoned config so the legitimate child process misuses its secret.

| Residual risk | Mitigation in the sketch | Honest limit |
|---|---|---|
| Credential *use* at allowed destination for attacker goals | per-use human approval showing resolved destination + request summary (for HTTP: method+path shown in the prompt) | approval fatigue is real; a habituated click defeats it — UX research needed, not more crypto |
| Many small abuses under one session grant | TTL + use budget + rate limit per handle; audit log review | limits chosen by the user; defaults must be conservative |
| Destination confusion (lookalike host, wildcard) | exact-match host allowlist; no agent-defined destinations ever | DNS/hosts-file tampering is same-machine compromise — partially out of scope per threat model |
| Broker compromise | broker is small, separate, memory-hardened (C11/C12 disciplines apply to it) | a root attacker wins — already documented residual risk |
| Approval-prompt spoofing by the agent | OS-surface prompt owned by the broker; never rendered through the agent | terminal-only environments make an unspoofable surface genuinely hard — open question 3 |

The CaMeL result is the right calibration: structural defenses bought *provable* security on
77% of tasks, at a real utility cost vs 84% undefended. Expect the same shape here — a handle
broker will refuse some legitimate workflows. That cost is acceptable; C27 is not negotiable.

## 7. Open questions *(DESIGN EXPLORATION)*

1. **Approval-fatigue UX:** what request-preview granularity keeps per-use approval meaningful
   after the 50th prompt? (The known weak point of every human-in-the-loop design, including
   1Password's.)
2. **Handle lifecycle:** who creates handles — interactive `vault agent allow <entry> --dest ...`
   only? Can a handle survive a vault re-key (C4 password rotation)?
3. **Headless/terminal-only approval surface:** what is an unspoofable prompt on a machine
   where the agent owns the only TTY? (Candidate: require a second device or hardware-key tap
   — FIDO2 presence (C14 hardware) as the approval click.)
4. **Proxy depth for HTTP:** method+path preview vs full-body inspection vs CaMeL-style policy
   on request structure — where is the point of diminishing returns?
5. **Should `vault_list` exist at all**, or should agents reference only handles the user
   pasted into their prompt (zero discovery surface)?
6. **Intent integration:** if this is ever built, it needs its own intent artifact with
   constraints (C28+/G11-style) *before* code — per IVD Rule 1 and the repo's
   design-before-implementation discipline. This spec is input to that artifact, not a
   substitute for it.
