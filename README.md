<div align="center">

# 🔑 Blindkey

**The local-first credential vault your AI agents can use — but never see.**
**No server. No account. One encrypted file. 66 testable security constraints. Rust.**

Passwords. API keys. `.env` files. SSH and signing keys. Database URLs. The credentials your AI
coding agents touch every day.

[![CI](https://github.com/leocelis/blindkey/actions/workflows/ci.yml/badge.svg)](https://github.com/leocelis/blindkey/actions/workflows/ci.yml)
[![Scorecard](https://github.com/leocelis/blindkey/actions/workflows/scorecard.yml/badge.svg)](https://github.com/leocelis/blindkey/actions/workflows/scorecard.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-blue.svg)](rust-toolchain.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status: v1.0.0 / unaudited / format v1 stable](https://img.shields.io/badge/status-v1.0.0%20%2F%20unaudited%20%2F%20format%20v1%20stable-yellow.svg)](#project-status)

[Install](#install) · [Documentation](#documentation) · [Quickstart](#quickstart) · [Contributing](CONTRIBUTING.md) · [Support](SUPPORT.md)

</div>

> [!WARNING]
> **v1.0.0 — not independently third-party audited — keep your own backup of anything you store.**
> Blindkey is **functional**: cryptographic core implemented and tested, working CLI *and* desktop app.
> **On-disk format v1 is stable** ([ADR-0005](docs/adr/0005-format-v1-freeze.md)) — vault files from
> alpha releases open on 1.x without migration. See [ROADMAP.md](ROADMAP.md) and [SECURITY.md](SECURITY.md).

---

## Why Blindkey exists

Developers now work alongside AI agents that read their files, run their shells, and — if the
secret is sitting in a `.env` or an MCP config file — read their credentials too.
GitGuardian found **~24,000 secrets exposed in public MCP configuration files** on GitHub in
2026 (`claude_desktop_config.json`, `.cursor/settings.json`), over 2,100 of them still valid.
AI-assisted commits leak secrets at roughly **2x** the platform-wide baseline. The industry's own
answer to this is converging on one principle: **the agent should never hold or see the secret** —
something else should broker it in at the edge.

Blindkey is that something else, built local-first:

- **No server, no account, no proxy in the traffic path.** Other credential brokers for AI agents
  run as a cloud-platform service or a MITM HTTPS proxy that intercepts every request. Blindkey is
  one encrypted file plus a local broker — nothing to stand up, nothing to trust with your
  connection.
- **The agent gets a handle, not a secret.** `blindkey agent` hands out scoped handles; a human
  approves at the terminal; the secret is injected at the destination without the requesting
  process ever receiving the bytes (constraint C27; see [docs/AGENT_BROKER.md](docs/AGENT_BROKER.md)).
- **Every claim is a falsifiable constraint with a test**, not a trust-us page. If you can't tell
  *how* a tool protects you, you can't trust it — Blindkey's entire design is written down as
  constraints you can read in an afternoon.
- **Memory-hardened Rust core** (`zeroize` + `mlock`, `panic = "abort"`, no `unsafe` outside one
  designated FFI crate) — the secret doesn't linger in process memory after use either.

## What makes it different

| | Blindkey | Cloud/proxy agent brokers | Typical free password manager |
|---|---|---|---|
| Where secrets live | **One local encrypted file** | Cloud platform / intercepted at a proxy | Local or cloud, varies |
| Agent visibility | **Handle only — human-approved, model-blind delivery** | Proxy sees plaintext in transit | N/A — not agent-aware |
| Network dependency | **None — fully offline** | Requires the proxy/platform | Often cloud-synced |
| Plaintext metadata (URLs, titles, timestamps) | **None — all encrypted** | Varies | Often leaks at least some |
| KDF | **Argon2id, floor enforced on open** | N/A | Argon2d / PBKDF2; no floor check |
| In-memory secrets | **`zeroize` + `mlock`** | N/A | Often left in plaintext |
| How you verify the claims | **66 constraints** with distributed tests ([index](docs/CONSTRAINT_INDEX.md)) | Trust us | Trust us |

## How an agent uses a secret without seeing it

The whole point in one picture: the agent asks for a *handle*, a human approves at the terminal,
and Blindkey injects the secret into the destination — the agent process never receives the bytes.

```mermaid
sequenceDiagram
    participant Agent as AI agent
    participant Broker as blindkey agent (local broker)
    participant Human
    participant Vault as Encrypted vault (.vlt)
    participant Dest as Destination (env / subprocess / HTTP)

    Agent->>Broker: request handle "github" (never the secret)
    Broker->>Human: approve use of "github" for <cmd>? (TTY prompt)
    Human-->>Broker: approve (one use)
    Broker->>Vault: unlock + read secret (in-process, zeroized after)
    Broker->>Dest: inject secret at the edge
    Broker-->>Agent: status only (approved / denied) — no secret
    Note over Agent,Dest: The agent orchestrates the task — the plaintext never crosses into it.
```

No proxy sits in your network path, no plaintext is intercepted in transit, and nothing is
stored on a server — the secret lives in one local file and is delivered model-blind (C13, C27).

## Architecture

Small, auditable crates with a hard security boundary: all secret-touching code lives in
`blindkey-core`, and the only `unsafe` in the tree is the OS-hardening FFI in `blindkey-sys`.

```mermaid
flowchart TD
    subgraph Frontends
        CLI[blindkey-cli<br/>the `blindkey` binary]
        TUI[blindkey-tui<br/>terminal UI]
        GUI[blindkey-gui<br/>desktop app]
        AGENT[blindkey-agent<br/>handle broker + MCP]
    end
    CORE[blindkey-core<br/>crypto · format · envelope · memory · rollback · sealed]
    SYS[blindkey-sys<br/>mlock · setrlimit — the only `unsafe`]
    HW[blindkey-hardware<br/>YubiKey · FIDO2 · TPM]
    CLIP[blindkey-clip<br/>clipboard concealment]

    CLI --> CORE
    TUI --> CORE
    GUI --> CORE
    AGENT --> CORE
    CORE --> SYS
    CLI --> HW
    GUI --> HW
    CLI --> CLIP
    GUI --> CLIP

    style CORE fill:#1f6feb,color:#fff
    style SYS fill:#8957e5,color:#fff
```

## Install

**Fastest path** — download from [GitHub Releases](https://github.com/leocelis/blindkey/releases), verify SHA256SUMS, `chmod +x`, move to PATH.

Prebuilt binaries today: **macOS x86_64 only** (`v1.0.0`). Linux, Windows, and Apple Silicon: build from source ([docs/INSTALL.md](docs/INSTALL.md)).

```sh
# Example (macOS x86_64) — see docs/VERIFYING_RELEASES.md
curl -LO https://github.com/leocelis/blindkey/releases/download/v1.0.0/blindkey-x86_64-apple-darwin
curl -LO https://github.com/leocelis/blindkey/releases/download/v1.0.0/SHA256SUMS.txt
shasum -a 256 -c SHA256SUMS.txt
chmod +x blindkey-x86_64-apple-darwin && sudo mv blindkey-x86_64-apple-darwin /usr/local/bin/blindkey
```

**Build from source** (contributors):

```sh
git clone https://github.com/leocelis/blindkey.git && cd blindkey
./scripts/setup-rust.sh && ./scripts/install.sh   # → ~/.local/bin/blindkey
```

Or `cargo install --git https://github.com/leocelis/blindkey.git --tag v1.0.0 --locked blindkey-cli`

Full options: [docs/INSTALL.md](docs/INSTALL.md)

## Quickstart

Downloaded the binary and don't have the repo cloned? Create the sample file first:

```sh
cat > keys.txt <<'EOF'
github=synthetic-example-token-do-not-use
EOF
```

(Cloned the repo? Use the bundled `samples/keys.txt` instead — same format.)

```sh
blindkey init
blindkey import --format raw --yes keys.txt   # synthetic sample — safe to try
blindkey ls
blindkey get github                           # copies to clipboard (model-blind)
blindkey gen --length 24
blindkey add myservice                        # interactive — no secrets on argv
```

Real output from the flow above (secrets shown only because `--stdout` was passed explicitly;
the default is a model-blind clipboard copy):

```console
$ blindkey init
  Created vault at ~/.blindkey/vault.vlt

$ blindkey import --format raw --yes keys.txt
  Parsed 2 entries (0 blocks skipped):
    github                       ghp_…real (30)
    openai                       sk-p…real (26)
  Imported 2 entries into ~/.blindkey/vault.vlt

$ blindkey ls
  github
  openai

$ blindkey gen --length 24
  %L1H*$b)!*:m#[D4ErQ&yqk6
  (157 bits of entropy)

$ blindkey get github --stdout    # default is clipboard; --stdout shown here for illustration
  WARNING: plaintext written to stdout; ensure no AI agent or untrusted process captures this stream.
  ghp_synthetic_example_not_real
```

Desktop app (build from source — no prebuilt GUI binary yet, see [#status](#project-status)):
`cargo run -p blindkey-gui` — drag `samples/keys.txt` onto the window to import.

## Documentation

| Topic | Doc |
|-------|-----|
| Doc hub (start here) | [docs/README.md](docs/README.md) |
| Install & build | [docs/INSTALL.md](docs/INSTALL.md) |
| CLI reference | [docs/CLI.md](docs/CLI.md) |
| Agent broker | [docs/AGENT_BROKER.md](docs/AGENT_BROKER.md) |
| Threat model | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Cryptography | [docs/CRYPTO.md](docs/CRYPTO.md) |
| File format | [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| 66 security constraints | [blindkey_intent.yaml](blindkey_intent.yaml) · [test index](docs/CONSTRAINT_INDEX.md) |
| Use-case specs (22) | [docs/specs/](docs/specs/README.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Release verification | [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md) |

Design at a glance: XChaCha20-Poly1305 STREAM · Argon2id · age-style multi-stanza envelope ·
encrypt-then-MAC · **zero network, zero telemetry**.

## Project status

- ✅ Research + 66-constraint intent (v1.8.0) + CP-7 sweep (60/60 PASS on the v1.0 set)
- ✅ CLI, TUI, desktop GUI on shared `blindkey-core`
- ✅ Quality gate: local `just check` / `just audit-ready`; [GHA CI](.github/workflows/ci.yml) on push
- ✅ **v1.0.0** — first stable release; format v1 frozen ([ADR-0005](docs/adr/0005-format-v1-freeze.md))
- 🟡 `blindkey mcp` — initial MCP server (status-only `list_handles` + `use_handle`); headless-approval delivery is the tracked next step ([UC-24](docs/specs/UC-24-mcp-broker.md))
- ⏳ Hardware FFI polish, sync/merge, optional third-party audit — [ROADMAP.md](ROADMAP.md)

## Repository layout

```
blindkey/
├── crates/
│   ├── blindkey-core/      # crypto, format, envelope, memory, rollback
│   ├── blindkey-cli/       # the `blindkey` binary
│   ├── blindkey-gui/       # egui desktop app
│   ├── blindkey-tui/       # ratatui terminal UI
│   ├── blindkey-agent/     # handle-based broker for AI agents (scaffold)
│   ├── blindkey-clip/      # clipboard concealment
│   ├── blindkey-sys/       # mlock, setrlimit — only `unsafe` boundary
│   └── blindkey-hardware/  # YubiKey CR (CLI); FIDO2/TPM mocks — see docs/guides/hardware-factor-status.md
├── docs/                # specs, threat model, CONSTRAINT_INDEX
├── samples/             # synthetic keys.txt for import demo
├── research/            # security research behind the design
└── blindkey_intent.yaml    # constraint specification (source of truth)
```

## Community

- **Questions:** [GitHub Discussions](https://github.com/leocelis/blindkey/discussions)
- **Bugs:** [issue tracker](https://github.com/leocelis/blindkey/issues) · **Security:** [SECURITY.md](SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) · [GOVERNANCE.md](GOVERNANCE.md)

Maintained by [Leo](MAINTAINERS.md) and [Juan](MAINTAINERS.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE). See [COPYRIGHT](COPYRIGHT).
