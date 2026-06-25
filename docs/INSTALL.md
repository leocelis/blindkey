# Installation

> **Status:** functional pre-1.0 — build from source, `cargo install vault-cli`, or download
> [signed GitHub Releases](https://github.com/leocelis/vault/releases) after tagging.
> crates.io publish runs automatically via Trusted Publishing on tag push
> ([CRATES_IO_TRUSTED_PUBLISHING.md](CRATES_IO_TRUSTED_PUBLISHING.md)).

## Quick install (recommended)

From a clone of this repo:

```sh
git clone https://github.com/leocelis/vault.git
cd vault
./scripts/setup-rust.sh    # once: project-scoped toolchain in ./.toolchain
./scripts/install.sh       # builds release binary → ~/.local/bin/vault
```

Ensure `~/.local/bin` is on your `PATH`.

## Install from crates.io

After the first manual publish + Trusted Publishing setup:

```sh
cargo install vault-cli --locked
```

Verify release binaries with [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md) — that path is stronger than `cargo install` alone.

## Install from Git without cloning

```sh
cargo install --git https://github.com/leocelis/vault.git --locked vault-cli
```

## Build from source (manual)

```sh
cd vault
. scripts/dev-env.sh       # activate ./.toolchain (or use your own Rust 1.96+)
cargo build --release -p vault-cli
# Binary at target/release/vault
```

### Fully static Linux build

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
ldd target/x86_64-unknown-linux-musl/release/vault   # → "not a dynamic executable"
```

## Pre-built binaries

When available, download from [GitHub Releases](https://github.com/leocelis/vault/releases), then
**verify the signature and checksum** before running — see [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md).

## Supported platforms

`x86_64-unknown-linux-musl` · `aarch64-apple-darwin` · `x86_64-apple-darwin` ·
`x86_64-pc-windows-msvc`.

## Optional hardware features

FIDO2 / TPM / OS-keystore stanzas are behind the `vault-hardware` crate's feature flags and may
require system libraries (e.g. `libfido2`). They are **optional** — the password stanza always works.

## Desktop app (`vault-gui`)

Build the windowed app (egui/eframe, glow renderer — UC-20):

```sh
cargo build --release -p vault-gui
# Binary at target/release/vault-gui
```

### Linux GUI dependencies

`vault-gui` uses native file dialogs (`rfd`) via **xdg-desktop-portal**. Install a portal backend
before building or running on Linux:

```sh
# Debian/Ubuntu (GTK portal)
sudo apt install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libssl-dev xdg-desktop-portal-gtk zenity

# Fedora (KDE portal alternative)
sudo dnf install gtk3-devel openssl-devel xdg-desktop-portal-kde zenity
```

CI installs the GTK stack — package list is in the block above.

### Enterprise / fleet deployment

For managed installs (custom vault path, config directory, forced lock-on-blur), see
[guides/enterprise-deployment.md](guides/enterprise-deployment.md) and
[ENTERPRISE_POSTURE.md](ENTERPRISE_POSTURE.md).

### Renderer upgrade path (eframe ≥ 0.34)

The workspace pins **glow** for smaller binaries and lower idle RAM on weak hardware. If you bump
eframe to ≥0.34 and switch to **wgpu**, set `desired_maximum_frame_latency: Some(1)` in
`NativeOptions::wgpu_options` — see [UC-20 spec](specs/UC-20-desktop-gui-hardening.md) §3.1.

## Pre-1.0 caution

Vault has **not** had an independent third-party security audit. Keep a **separate backup** of
anything you store — `vault init` writes an initial `vault.vlt.bak`, and `vault import` backs up
the previous generation before overwriting.
