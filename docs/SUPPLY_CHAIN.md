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

### RUSTSEC-2024-0436 (`paste`) / RUSTSEC-2026-0192 (`ttf-parser`) — unmaintained

- **Advisory:** "no longer maintained" notices — not vulnerabilities, no known exploit.
- **Why exempted:** both are desktop-GUI-only transitive crates (`ttf-parser` = egui text
  rendering; `paste` = a compile-time token-pasting helper), reached only through
  `blindkey-gui`. The CLI and security core never pull them. `cargo deny` treats
  unmaintained advisories as errors by default; these are `ignore`d in `deny.toml` with
  this rationale.
- **Removal trigger:** the GUI stack (`egui`/`eframe`) drops them or they gain a
  maintained successor.

### RUSTSEC-2021-0154 — `fuser` < 0.16 (unsound)

- **Advisory:** fuser passed a NULL operation list to libfuse3's `fuse_session_new`,
  causing an uninitialized read and a leak inside `libfuse.so`.
- **Why it is not reachable in Blindkey:** the call is only in fuser's `src/mnt/fuse3.rs`,
  compiled only when its build script selects the `libfuse3` mount implementation (the
  `libfuse` feature on a non-macOS host). Blindkey builds Linux with
  `default-features = false` (pure-Rust `fusermount` path) and macOS `macos-fuse` against
  macFUSE, which fuser builds as `libfuse2`. Neither compiles `fuse3.rs`. `fuser` reaches
  only `blindkey-fuse` (volume mount), never the security core.
- **Do not enable `fuser`'s `libfuse` feature on Linux.** That is the libfuse3 path the
  advisory covers. Workspace `Cargo.toml` keeps `default-features = false`; the Linux
  target dep is `fuser.workspace = true` only. Guarded by
  `crates/blindkey-fuse/tests/fuser_feature_guard.rs`. If that guard fails, drop the
  advisory ignore until the feature graph is fixed or `fuser >= 0.16` is adopted.
- **Why not just upgrade:** `fuser` 0.16 changes the filesystem API that `blindkey-fuse`
  implements; that move belongs with a FUSE adapter change tested on Linux and macFUSE.
- **Removal trigger:** when `blindkey-fuse` moves to `fuser >= 0.16`, drop the ID from
  [`.cargo/audit.toml`](../.cargo/audit.toml) and [`deny.toml`](../deny.toml).

### Optional `macos-fuse` CI coverage

GitHub-hosted macOS runners do not install macFUSE, so the main CI matrix excludes
`--features macos-fuse` (ADR-0010). `scripts/check_macos_fuse.sh` (and `just macos-fuse-check`)
runs clippy + tests with that feature when `fuse.pc` / `osxfuse.pc` is present, and prints
SKIP otherwise. Wire a self-hosted runner with macFUSE to get continuous coverage.

## License allow-list — GUI-only additions

The desktop GUI's windowing/clipboard/text stack pulls a few permissive and
weak-copyleft licenses beyond MIT/Apache-2.0. They are allowed in `deny.toml`, apply
only to `blindkey-gui`'s transitive tree, and impose no obligation on Blindkey's own
MIT-or-Apache-2.0 source:

| License | Crates | Nature |
|---|---|---|
| `BSL-1.0` (Boost) | `clipboard-win`, `error-code` | Permissive, OSI-approved |
| `Zlib` | `foldhash`, `slotmap` | Permissive, OSI-approved |
| `MPL-2.0` (Mozilla) | `nucleo-matcher` | File-scoped copyleft; obligation is limited to modifications of the MPL files themselves, which Blindkey does not make (dependency-only) |
| `OFL-1.1`, `LicenseRef-UFL-1.0` | `epaint_default_fonts` only (per-crate exception) | Font licenses for egui's embedded default fonts; both permit embedding and redistribution with the software |

## Non-blocking advisories

`cargo audit` also reports informational **warnings** (unsound) for the GUI-only
transitive crates `lru` and `memmap2`. These are warnings, not build failures, sit in
the desktop GUI dependency tree outside the security boundary, and are revisited
whenever the GUI stack is upgraded.

## Windows

Blindkey is Unix-first. The agent broker (`blindkey-agent`) is Unix-socket only (guarded
by a `compile_error!` off Unix) and the CLI depends on it, so the full workspace does not
yet build on Windows. CI runs a dedicated Windows job over the **portable security core**
(`blindkey-core`, `blindkey-sys`, `blindkey-clip`, `blindkey-hardware`) so the crypto,
format, memory-hardening, and hardware layers are verified on Windows every push;
`mlock`/`RLIMIT_CORE` degrade to documented `cfg(not(unix))` no-ops.

## Review cadence

Exemptions are reviewed on every dependency bump (Dependabot opens weekly PRs for
`cargo` and `github-actions`) and, at the latest, at each release. An exemption that no
longer has a live advisory behind it is removed the same day it is noticed.
