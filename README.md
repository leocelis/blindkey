<div align="center">

# 🔐 Vault

**Security for the AI era — a zero-plaintext, local-first vault for the secrets developers actually have.**

Passwords. API keys. `.env` files. SSH and signing keys. Database URLs. The credentials your AI tools can see.

[![CI](https://github.com/leocelis/vault/actions/workflows/ci.yml/badge.svg)](https://github.com/leocelis/vault/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status: v1.0.0 / unaudited / format v1 stable](https://img.shields.io/badge/status-v1.0.0%20%2F%20unaudited%20%2F%20format%20v1%20stable-yellow.svg)](#project-status)

[Install](#install) · [Documentation](#documentation) · [Quickstart](#quickstart) · [Contributing](CONTRIBUTING.md) · [Support](SUPPORT.md)

</div>

> [!WARNING]
> **v1.0.0 — not independently third-party audited — keep your own backup of anything you store.**
> Vault is **functional**: cryptographic core implemented and tested, working CLI *and* desktop app.
> **On-disk format v1 is stable** ([ADR-0005](docs/adr/0005-format-v1-freeze.md)) — vault files from
> alpha releases open on 1.x without migration. See [ROADMAP.md](ROADMAP.md) and [SECURITY.md](SECURITY.md).

---

## Why Vault exists

Developers now work alongside AI agents that can read their files, run their shells, and touch
their credentials. The threat model changed — the tools didn't. Vault is built for the people
who feel that gap:

- **Current managers fall short on the AI-era threat model.** LastPass shipped plaintext URLs
  and 1-iteration KDFs; `pass` leaks every entry name through filenames and git history;
  KeePassXC defaulted to Argon2d and doesn't encrypt secrets in memory. And in 2025 we saw the
  first AI-*orchestrated* credential-harvesting campaigns and malware that calls an LLM at
  runtime. (See [research/llm_offensive_threats.md](research/llm_offensive_threats.md).)
- **Current managers are too complex to *understand*.** If you can't tell *how* a tool protects
  you, you can't trust it. Vault's entire design is written down as **falsifiable constraints**
  you can read in an afternoon — every security claim has a test.

Vault's bet: be **verifiably more secure than anything free** *and* **simple enough that a
developer who is nervous about AI exposure can actually adopt it.**

## What makes it different

| | Vault | Typical free manager |
|---|---|---|
| Plaintext metadata (URLs, titles, timestamps) | **None — all encrypted** | Often leaks at least some |
| KDF | **Argon2id, floor enforced on open** | Argon2d / PBKDF2; no floor check |
| Unlock model | **Multi-stanza unlock** — password always works; optional **YubiKey or keyfile 2FA** on CLI/GUI ([hardware status](docs/guides/hardware-factor-status.md); FIDO2/TPM/SE deferred) | Single factor |
| In-memory secrets | **`zeroize` + `mlock`** | Often left in plaintext |
| Whole-file rollback by a sync backend | **Detected** (monotonic counter) | Undetected |
| AI-era hardening | **CSPRNG generation + model-blind delivery** | Not designed for it |
| How you verify the claims | **66 constraints** with distributed tests ([index](docs/CONSTRAINT_INDEX.md)) | Trust us |

## Install

**Fastest path** — download from [GitHub Releases](https://github.com/leocelis/vault/releases), verify SHA256SUMS, `chmod +x`, move to PATH.

Prebuilt binaries today: **macOS x86_64 only** (`v1.0.0`). Linux, Windows, and Apple Silicon: build from source ([docs/INSTALL.md](docs/INSTALL.md)).

```sh
# Example (macOS x86_64) — see docs/VERIFYING_RELEASES.md
curl -LO https://github.com/leocelis/vault/releases/download/v1.0.0/vault-x86_64-apple-darwin
curl -LO https://github.com/leocelis/vault/releases/download/v1.0.0/SHA256SUMS.txt
shasum -a 256 -c SHA256SUMS.txt
chmod +x vault-x86_64-apple-darwin && sudo mv vault-x86_64-apple-darwin /usr/local/bin/vault
```

**Build from source** (contributors):

```sh
git clone https://github.com/leocelis/vault.git && cd vault
./scripts/setup-rust.sh && ./scripts/install.sh   # → ~/.local/bin/vault
```

Or `cargo install --git https://github.com/leocelis/vault.git --tag v1.0.0 --locked vault-cli`

Full options: [docs/INSTALL.md](docs/INSTALL.md)

## Quickstart

```sh
vault init
vault import --format raw --yes samples/keys.txt   # synthetic sample — safe to try
vault ls
vault get github                                   # copies to clipboard (model-blind)
vault gen --length 24
vault add myservice                                # interactive — no secrets on argv
```

Desktop app: `cargo run -p vault-gui` — drag `samples/keys.txt` onto the window to import.

## Documentation

| Topic | Doc |
|-------|-----|
| Doc hub (start here) | [docs/README.md](docs/README.md) |
| Install & build | [docs/INSTALL.md](docs/INSTALL.md) |
| CLI reference | [docs/CLI.md](docs/CLI.md) |
| Threat model | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Cryptography | [docs/CRYPTO.md](docs/CRYPTO.md) |
| File format | [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| 60 security constraints | [vault_intent.yaml](vault_intent.yaml) · [test index](docs/CONSTRAINT_INDEX.md) |
| Use-case specs (22) | [docs/specs/](docs/specs/README.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Release verification | [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md) |

Design at a glance: XChaCha20-Poly1305 STREAM · Argon2id · age-style multi-stanza envelope ·
encrypt-then-MAC · **zero network, zero telemetry**.

## Project status

- ✅ Research + 66-constraint intent (v1.8.0) + CP-7 sweep (60/60 PASS on the v1.0 set)
- ✅ CLI, TUI, desktop GUI on shared `vault-core`
- ✅ Quality gate: local `just check` / `just audit-ready`; [GHA CI](.github/workflows/ci.yml) on push
- ✅ **v1.0.0** — first stable release; format v1 frozen ([ADR-0005](docs/adr/0005-format-v1-freeze.md))
- ⏳ Hardware FFI polish, sync/merge, optional third-party audit — [ROADMAP.md](ROADMAP.md)

## Repository layout

```
vault/
├── crates/
│   ├── vault-core/      # crypto, format, envelope, memory, rollback
│   ├── vault-cli/       # the `vault` binary
│   ├── vault-gui/       # egui desktop app
│   ├── vault-tui/       # ratatui terminal UI
│   ├── vault-clip/      # clipboard concealment
│   ├── vault-sys/       # mlock, setrlimit — only `unsafe` boundary
│   └── vault-hardware/  # YubiKey CR (CLI); FIDO2/TPM mocks — see docs/guides/hardware-factor-status.md
├── docs/                # specs, threat model, CONSTRAINT_INDEX
├── samples/             # synthetic keys.txt for import demo
├── research/            # security research behind the design
└── vault_intent.yaml    # constraint specification (source of truth)
```

## Community

- **Questions:** [GitHub Discussions](https://github.com/leocelis/vault/discussions)
- **Bugs:** [issue tracker](https://github.com/leocelis/vault/issues) · **Security:** [SECURITY.md](SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) · [GOVERNANCE.md](GOVERNANCE.md)

Maintained by [Leo](MAINTAINERS.md) and [Juan](MAINTAINERS.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE). See [COPYRIGHT](COPYRIGHT).
