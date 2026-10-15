# Installation

> **Status:** v1.1.0 — build from source, install from git, or download a
> [GitHub Release](https://github.com/leocelis/blindkey/releases) binary with SHA-256 checksums.
> Start with the short **Developers** box in the [root README](../README.md#developers-recommended).

## Quick install (developers)

From a clone of this repo:

```sh
git clone https://github.com/leocelis/blindkey.git
cd blindkey
./scripts/setup-rust.sh    # once: project-scoped toolchain in ./.toolchain
./scripts/install.sh       # builds release CLI → ~/.local/bin/blindkey
```

Ensure `~/.local/bin` is on your `PATH`.

**Prebuilt CLI (`v1.1.0`):** macOS and Linux, `x86_64` and `aarch64` — see [GitHub Releases](#github-releases).  
**Windows / GUI:** build from source (Unix-first broker; no notarized `.app` yet).

## Install from Git (no clone)

```sh
cargo install --git https://github.com/leocelis/blindkey.git --locked blindkey-cli
```

Pin a release tag for reproducibility:

```sh
cargo install --git https://github.com/leocelis/blindkey.git --tag v1.1.0 --locked blindkey-cli
```

## Install from crates.io

When published (maintainer manual step — see [CRATES_IO_TRUSTED_PUBLISHING.md](CRATES_IO_TRUSTED_PUBLISHING.md)):

```sh
cargo install blindkey-cli --locked
```

Until then, use git install or a GitHub Release binary.

## GitHub Releases

Download `blindkey-<arch>-<platform>` from [Releases](https://github.com/leocelis/blindkey/releases),
verify with [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md), then:

```sh
chmod +x blindkey-x86_64-apple-darwin   # example — macOS x86_64
sudo mv blindkey-x86_64-apple-darwin /usr/local/bin/blindkey
```

## Build from source (manual)

```sh
cd blindkey
. scripts/dev-env.sh       # activate ./.toolchain (or Rust 1.96+)
cargo build --release -p blindkey-cli
# Binary at target/release/blindkey
```

Reproducibility check: `./scripts/reproducible-build.sh`

## Desktop app (`blindkey-gui`)

No notarized Mac download yet (Apple Developer ID required for Gatekeeper-clean distribution). Developers:

```sh
cargo run -p blindkey-gui
# macOS: optional unsigned local .app (Gatekeeper may warn)
./scripts/bundle-macos.sh    # → target/Blindkey.app ; open target/Blindkey.app
```

**Blindfolder (sync-folder `.vltd`):** Create volume into Dropbox/Drive/iCloud → **Open Blindfolder** → edit the local folder → **Eject**. Do not Mount the sync-path file. Spec: [UC-30](specs/UC-30-volume-working-copy.md).

The GUI crate enables egui’s `default_fonts` feature (readable labels with
`eframe` `default-features = false`). If glyphs ever render blank on a host,
file an issue — optional follow-up is embedding a known TTF via egui font APIs.

### Linux GUI dependencies

`blindkey-gui` uses native file dialogs via **xdg-desktop-portal**:

```sh
# Debian/Ubuntu (GTK portal)
sudo apt install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libssl-dev xdg-desktop-portal-gtk zenity

# Fedora (KDE portal alternative)
sudo dnf install gtk3-devel openssl-devel xdg-desktop-portal-kde zenity
```

Package list above is the canonical GTK stack for Linux builds.

### Linux runtime hardening (gap B3)

Blindkey marks itself **non-dumpable** at startup (`PR_SET_DUMPABLE`, `RLIMIT_CORE=0`,
`coredump_filter=0`). Under the default **Yama** `ptrace_scope`, same-uid malware cannot
`ptrace`-attach or read `/proc/<pid>/mem` while vault runs.

Fleet admins may tighten further (optional):

```sh
# /etc/sysctl.d/99-vault-ptrace.conf — restrict ptrace to CAP_SYS_PTRACE holders
kernel.yama.ptrace_scope = 2
sudo sysctl --system
```

`ptrace_scope=1` (restrict unrelated processes — typical distro default) is sufficient for vault's
own hardening. macOS has no equivalent; see [THREAT_MODEL.md](THREAT_MODEL.md) residual risks.

### Memory locking (`mlock`) and containers (C12)

While a vault is **unlocked**, decrypted entry data is held in RAM. Blindkey calls `mlock(2)` to keep
those pages **off swap** (constraint C12). If locking fails — common in **Docker**, **Podman**, and
**Kubernetes** default seccomp profiles return **EPERM** — vault prints **one warning per process**
and **continues** (never aborts). Secrets may then appear in swap if the host uses unencrypted swap.

**Production recommendation:** install vault **on the host** (`./scripts/install.sh` or a release
binary) for irreplaceable secrets. Containers are fine for CI fixtures or low-value test vaults.

**Linux — check your limit:**

```sh
ulimit -l          # locked memory (KiB); "unlimited" or ≥ vault size is ideal
grep VmLck /proc/self/status   # while vault is unlocked — should be > 0 when mlock works
```

**Docker (if you must run in a container):**

```sh
docker run --rm -it \
  --cap-add=IPC_LOCK \
  --ulimit memlock=-1:-1 \
  -v "$HOME/.vault:/vault:rw" \
  vault:local blindkey ls /vault/test.vlt
```

**Kubernetes (illustrative — adjust for your policy):**

```yaml
securityContext:
  capabilities:
    add: ["IPC_LOCK"]
```

Even with `IPC_LOCK`, some runtimes still deny `mlock`; treat a stderr `mlock failed` warning as
**degraded mode** — see [specs/UC-14-runtime-hardening.md](specs/UC-14-runtime-hardening.md) §3.2 and
[THREAT_MODEL.md](THREAT_MODEL.md) (swap / hibernation residual).

**What mlock does not fix:** suspend-to-disk / hibernation writes all of RAM; use encrypted swap or
disable hibernation on secret-handling machines.

### Enterprise / fleet deployment

See [guides/enterprise-deployment.md](guides/enterprise-deployment.md) and
[ENTERPRISE_POSTURE.md](ENTERPRISE_POSTURE.md).

## Security caution

Blindkey has **not** had an independent third-party security audit. Keep a **separate backup** of
anything you store. On-disk format v1 is stable ([ADR-0005](adr/0005-format-v1-freeze.md)).
