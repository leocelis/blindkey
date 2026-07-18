#!/usr/bin/env bash
# Build blindkey-cli from this repo and install the binary to ~/.local/bin (or $INSTALL_DIR).
# Usage (from repo root):  ./scripts/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f scripts/dev-env.sh ]]; then
  # shellcheck source=/dev/null
  . scripts/dev-env.sh
fi

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

echo "install: building blindkey-cli (release)…"
cargo build --release -p blindkey-cli

BIN="$ROOT/target/release/blindkey"
install -m 755 "$BIN" "$INSTALL_DIR/blindkey"

echo "install: installed to $INSTALL_DIR/blindkey"
echo "install: ensure $INSTALL_DIR is on your PATH"
"$INSTALL_DIR/blindkey" --version 2>/dev/null || true
