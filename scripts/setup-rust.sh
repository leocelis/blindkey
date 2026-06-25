#!/usr/bin/env sh
# One-time setup: install the pinned Rust toolchain INTO this project, never machine-wide.
#
# Why: a vault is a security tool; its build environment should be reproducible and self-contained,
# not entangled with whatever Rust happens to be in your home directory. This installs rustup with
# RUSTUP_HOME / CARGO_HOME pointed at ./.toolchain (git-ignored) and --no-modify-path so it does NOT
# touch ~/.rustup, ~/.cargo, or your shell profiles. The exact version + components come from
# rust-toolchain.toml (single source of truth). Official guidance:
#   https://rust-lang.github.io/rustup/installation/index.html  (RUSTUP_HOME / CARGO_HOME)
#   https://rust-lang.github.io/rustup/installation/other.html  (--no-modify-path)
#
# Usage:  ./scripts/setup-rust.sh   then   . scripts/dev-env.sh   (or use direnv)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export RUSTUP_HOME="$ROOT/.toolchain/rustup"
export CARGO_HOME="$ROOT/.toolchain/cargo"

if [ -x "$CARGO_HOME/bin/rustup" ]; then
  echo "Project toolchain already present at $ROOT/.toolchain"
else
  echo "Installing project-scoped Rust into $ROOT/.toolchain (nothing machine-wide)…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none
fi

# rust-toolchain.toml selects the version (1.96.0) and components (rustfmt, clippy) on first use.
"$CARGO_HOME/bin/rustup" show

cat <<EOF

Done. The toolchain lives in ./.toolchain (git-ignored). Activate it in your shell with:

    . scripts/dev-env.sh        # source it (do not execute)

or, if you use direnv, just 'cd' into the repo (an .envrc is provided). Then: just check
EOF
