#!/usr/bin/env bash
# Clippy/test the optional macOS FUSE feature when macFUSE headers are present.
# GitHub-hosted runners do not install macFUSE (ADR-0010); this script exits 0
# with SKIP there so CI stays green, and exercises the real path on a maintainer
# machine (or self-hosted runner) that has fuse.pc / osxfuse.pc.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

has_fuse=0
if command -v pkg-config >/dev/null 2>&1; then
  if pkg-config --exists fuse 2>/dev/null || pkg-config --exists osxfuse 2>/dev/null; then
    has_fuse=1
  fi
fi

if [[ "$has_fuse" -ne 1 ]]; then
  echo "check_macos_fuse: SKIP (no fuse.pc / osxfuse.pc — install macFUSE to cover --features macos-fuse)"
  exit 0
fi

echo "check_macos_fuse: clippy + tests with --features macos-fuse"
cargo clippy -p blindkey-fuse -p blindkey-gui -p blindkey-cli \
  --features macos-fuse --all-targets -- -D warnings
cargo test -p blindkey-fuse -p blindkey-gui -p blindkey-cli --features macos-fuse
echo "check_macos_fuse: PASS"
