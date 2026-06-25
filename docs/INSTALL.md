# Installation

> **Status:** functional pre-1.0 — build from source, install from git, or download a
> [GitHub Release](https://github.com/leocelis/vault/releases) binary with SHA-256 checksums.

## Quick install (recommended)

From a clone of this repo:

```sh
git clone https://github.com/leocelis/vault.git
cd vault
./scripts/setup-rust.sh    # once: project-scoped toolchain in ./.toolchain
./scripts/install.sh       # builds release binary → ~/.local/bin/vault
```

Ensure `~/.local/bin` is on your `PATH`.

## Install from Git (no clone)

```sh
cargo install --git https://github.com/leocelis/vault.git --locked vault-cli
```

Pin a release tag for reproducibility:

```sh
cargo install --git https://github.com/leocelis/vault.git --tag v0.1.0-alpha.2 --locked vault-cli
```

## Install from crates.io

When published (maintainer manual step — see [CRATES_IO_TRUSTED_PUBLISHING.md](CRATES_IO_TRUSTED_PUBLISHING.md)):

```sh
cargo install vault-cli --locked
```

Until then, use git install or a GitHub Release binary.

## GitHub Releases

Download `vault-<arch>-<platform>` from [Releases](https://github.com/leocelis/vault/releases),
verify with [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md), then:

```sh
chmod +x vault-x86_64-apple-darwin   # example
sudo mv vault-x86_64-apple-darwin /usr/local/bin/vault
```

## Build from source (manual)

```sh
cd vault
. scripts/dev-env.sh       # activate ./.toolchain (or Rust 1.96+)
cargo build --release -p vault-cli
# Binary at target/release/vault
```

Reproducibility check: `./scripts/reproducible-build.sh`

## Desktop app (`vault-gui`)

```sh
cargo run -p vault-gui
# macOS app bundle:
./scripts/bundle-macos.sh    # → target/Vault.app
```

### Linux GUI dependencies

`vault-gui` uses native file dialogs via **xdg-desktop-portal**:

```sh
# Debian/Ubuntu (GTK portal)
sudo apt install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libssl-dev xdg-desktop-portal-gtk zenity

# Fedora (KDE portal alternative)
sudo dnf install gtk3-devel openssl-devel xdg-desktop-portal-kde zenity
```

Package list above is the canonical GTK stack for Linux builds.

### Enterprise / fleet deployment

See [guides/enterprise-deployment.md](guides/enterprise-deployment.md) and
[ENTERPRISE_POSTURE.md](ENTERPRISE_POSTURE.md).

## Pre-1.0 caution

Vault has **not** had an independent third-party security audit. Keep a **separate backup** of
anything you store.
