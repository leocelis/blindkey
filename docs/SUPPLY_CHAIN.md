# Supply-chain policy & advisory exemptions

Blindkey is a credential-protection tool, so its dependency surface is part of its
threat model. This document is the public, version-controlled record of **how** we
vet dependencies and **why** any `cargo audit` / `cargo deny` advisory is exempted.

## Gates

Every push and PR runs (see [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)):

- `cargo audit` — RustSec advisory database (config: [`.cargo/audit.toml`](../.cargo/audit.toml))
- `cargo deny check` — advisories + licenses + bans + sources ([`deny.toml`](../deny.toml))
- `cargo vet` — per-crate vetting of the dependency tree ([`supply-chain/`](../supply-chain/))
- a reproducible-build check that asserts the release binary is byte-identical

License policy is permissive-only (`MIT`, `Apache-2.0`, `ISC`, `BSD-2/3-Clause`,
`Unicode`); `openssl`/`openssl-sys` are banned from the tree; only crates.io is an
allowed source.

## The security boundary

The crates that hold or touch secret material — `blindkey-core`, `blindkey-cli`,
`blindkey-sys`, `blindkey-hardware`, `blindkey-clip`, `blindkey-agent` — carry **no
exempted advisories**. Their audit is clean. Exemptions, when they exist, are confined
to the optional desktop GUI (`blindkey-gui`) and its windowing/dialog stack, which is
not on the CLI's path.

## Current exemptions

Each exemption is scoped to a single RUSTSEC ID with a stated reason and a removal
trigger. Blanket ignores are never used.

### RUSTSEC-2026-0194 / RUSTSEC-2026-0195 — `quick-xml` < 0.41

- **Advisory:** memory-exhaustion and quadratic-time denial of service when parsing
  **malicious/untrusted XML** with `quick-xml`'s `NsReader`.
- **Why it is not reachable in Blindkey:** `quick-xml` enters the tree **only** through
  [`wayland-scanner`](https://crates.io/crates/wayland-scanner), a **build-time
  proc-macro**. It parses the *trusted, vendored Wayland protocol XML* that ships with
  the Wayland crates in order to generate Rust bindings at compile time. Blindkey never
  feeds runtime or untrusted XML to `quick-xml` — it never calls into `quick-xml` at
  runtime at all. The dependency reaches only `blindkey-gui` on Linux/Wayland; the
  security core, CLI, and `blindkey-sys` do not depend on it
  (`cargo tree -i quick-xml` confirms).
- **Why not just upgrade:** there is no upstream fix path today. `wayland-scanner` at
  its latest release (`0.31.10`) still pins `quick-xml 0.39`; bumping the GUI stack
  (`eframe`, `winit`) does not move it.
- **Removal trigger:** when the Wayland crates bump `quick-xml` to `>= 0.41`, drop both
  IDs from [`.cargo/audit.toml`](../.cargo/audit.toml) and [`deny.toml`](../deny.toml)
  and let the upgrade flow through.

## Non-blocking advisories

`cargo audit` also reports informational **warnings** (unmaintained / unsound) for
GUI-only transitive crates such as `paste`, `ttf-parser`, `lru`, and `memmap2`. These
are warnings, not build failures, and — like the exemptions above — sit in the desktop
GUI dependency tree, outside the security boundary. They are tracked here for
transparency and revisited whenever the GUI stack is upgraded.

## Review cadence

Exemptions are reviewed on every dependency bump (Dependabot opens weekly PRs for
`cargo` and `github-actions`) and, at the latest, at each release. An exemption that no
longer has a live advisory behind it is removed the same day it is noticed.
