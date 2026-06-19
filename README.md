<div align="center">

# 🔐 Vault

**Security for the AI era — a zero-plaintext, local-first vault for the secrets developers actually have.**

Passwords. API keys. `.env` files. SSH and signing keys. Database URLs. The credentials your AI tools can see.

[![CI](https://github.com/leocelis/vault/actions/workflows/ci.yml/badge.svg)](https://github.com/leocelis/vault/actions/workflows/ci.yml)
[![Dependency audit](https://github.com/leocelis/vault/actions/workflows/audit.yml/badge.svg)](https://github.com/leocelis/vault/actions/workflows/audit.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/leocelis/vault/badge)](https://securityscorecards.dev/viewer/?uri=github.com/leocelis/vault)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status: functional / pre-1.0 / unaudited](https://img.shields.io/badge/status-functional%20%2F%20pre--1.0%20%2F%20unaudited-yellow.svg)](#project-status)

</div>

> [!WARNING]
> **Pre-1.0 and not yet independently audited — keep your own backup of anything you store.**
> Vault is now **functional**: the cryptographic core is implemented and tested, and there's a
> working CLI *and* a desktop app (create/unlock, import a `keys.txt`, search, copy, edit, 2FA
> codes, auto-lock). What it has **not** had is an independent third-party security audit, and the
> on-disk format may still change before 1.0. Use it, kick the tyres, report issues — just don't
> make it the *only* copy of an irreplaceable secret yet. See [ROADMAP.md](ROADMAP.md).

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
| Unlock model | **Any-of-N stanzas** (password + hardware + OS keystore) | Single factor |
| In-memory secrets | **`zeroize` + `mlock`** | Often left in plaintext |
| Whole-file rollback by a sync backend | **Detected** (monotonic counter) | Undetected |
| AI-era hardening | **CSPRNG generation + model-blind delivery** | Not designed for it |
| How you verify the claims | **60 constraints** with distributed tests ([index](docs/CONSTRAINT_INDEX.md)) | Trust us |

## Design at a glance

- **Cipher:** XChaCha20-Poly1305 in STREAM mode (64 KiB chunks, tag-verified before release).
- **KDF:** Argon2id (default m=64 MiB, t=3, p=4), with an enforced minimum floor *and* a maximum
  ceiling against hostile files.
- **Envelope:** age-style multi-stanza — a random per-vault data key wrapped by any of: password
  (always present), FIDO2/PRF, YubiKey, TPM, macOS Secure Enclave, Windows DPAPI. Lose a hardware
  factor, keep your vault.
- **Format:** versioned, KDBX-4-style header integrity (SHA-256 + keyed HMAC), encrypt-then-MAC body.
- **Everything encrypted:** one opaque blob, safe to sync over Git / Syncthing / Dropbox.
- **Zero network. Zero telemetry. Ever.**

Full rationale: [docs/CRYPTO.md](docs/CRYPTO.md) · Format: [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md)
· Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · The constraints: [vault_intent.yaml](vault_intent.yaml)

## Quickstart

```sh
# Build from source (not yet published to crates.io); produces one static binary, no runtime deps.
cargo build --release -p vault-cli
alias vault=target/release/vault

vault init                      # create a vault (prompts for a master password)
vault import --format raw --yes keys.txt   # migrate a messy keys.txt (use --yes when piped)
vault gen --length 24           # generate a CSPRNG password…
vault gen --words 8             # …or a diceware passphrase
vault add github                # add an entry (no secrets on the command line)
vault get github                # copy password to clipboard (auto-clears in 30s)
vault otp github                # copy the current 2FA code (if the entry has a 2FA secret)
vault ls --search git           # search after unlock (in-memory only)
vault tune                      # benchmark Argon2id and recommend KDF params
vault pad on                    # hide the file's exact size on untrusted storage (Padmé)
```

### Desktop app *(works today, locally)*

There is a simple, fast, pure-Rust **desktop window app** (`vault-gui`) over the same core — create
or unlock a vault, **drag a `keys.txt` onto the window** (or pick one) to import with a masked
review, **type to search**, and **copy** a password that stays **shadowed** on screen (the secret is
never rendered; the clipboard auto-clears). You can add, edit, change, and delete entries.

```sh
cargo run -p vault-gui          # launch the window
./scripts/bundle-macos.sh       # macOS: build a double-clickable target/Vault.app
```

It shares one vault with the CLI/TUI at `~/.vault/vault.vlt`, auto-locks when idle, and shows live
2FA codes. (Functional but not yet independently audited — see the warning above.)

Secrets are **never** passed as command-line arguments, and `vault get` delivers to the clipboard
by default so an AI agent watching stdout can't scrape them. To be precise about the boundary:
this defends against *incidental* capture (a secret landing in an agent's transcript); a hostile
agent with shell access to an unlocked session is same-user malware, bounded — not eliminated — by
auto-lock and clipboard concealment. See [docs/CLI.md](docs/CLI.md) and the
[threat model](docs/THREAT_MODEL.md).

## Project status

Vault follows **Intent-Verified Development**: the design is captured as testable constraints
*before* code. We are here:

- ✅ Research foundation — [research/](research/)
- ✅ Intent specification — [vault_intent.yaml](vault_intent.yaml) (60 constraints, 15 groups, v1.7.0)
- ✅ Open-source scaffolding — this repository
- ✅ **Core implementation** — encrypted format, Argon2id, in-memory protection, rollback
  detection, CLI **and** desktop app (CI green on Linux/macOS/Windows; see [ROADMAP.md](ROADMAP.md))
- ⏳ Remaining features — hardware-backed unlock polish, sync/merge (see the roadmap)
- ⏳ **1.0 release** — format freeze + broader constraint test coverage

## Repository layout

```
vault/
├── crates/
│   ├── vault-core/      # crypto, format, envelope, memory, rollback (the security core)
│   ├── vault-cli/       # the `vault` binary
│   ├── vault-tui/       # ratatui terminal UI (thin shell)
│   ├── vault-gui/       # egui desktop window (thin shell)
│   ├── vault-sys/       # OS calls (mlock, setrlimit) — the only `unsafe` boundary
│   └── vault-hardware/  # optional FIDO2 / TPM / OS-keystore stanzas
├── docs/                # architecture, threat model, file format, crypto rationale, ADRs
├── research/            # the security research this design is built on
├── fuzz/                # cargo-fuzz harnesses for the untrusted-input parsers
├── benches/             # benchmark notes (C22 via `vault tune`)
├── tests/               # (reserved — integration tests live in crate `tests/` dirs)
└── vault_intent.yaml    # the constraint specification — the source of truth
```

## Contributing

We'd love help — see [CONTRIBUTING.md](CONTRIBUTING.md) and our [governance model](GOVERNANCE.md).
Found a vulnerability? **Do not open a public issue** — follow [SECURITY.md](SECURITY.md).

Maintained by [Leo](MAINTAINERS.md) and [Juan](MAINTAINERS.md).

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
See [LICENSE](LICENSE) and [COPYRIGHT](COPYRIGHT).
