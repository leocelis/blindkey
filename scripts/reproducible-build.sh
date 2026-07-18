#!/usr/bin/env bash
# Build the `blindkey` CLI binary twice with deterministic flags and assert the two are byte-identical
# (reproducible builds — constraints C24/C34). A reproducible binary lets anyone rebuild from source
# and confirm a published release matches it, defeating a tampered-binary supply-chain attack.
#
# Determinism levers: SOURCE_DATE_EPOCH (no embedded build time), --remap-path-prefix (no absolute
# source/registry paths in the binary), CARGO_INCREMENTAL=0, and `--locked` (pinned Cargo.lock).
# The release profile already pins codegen-units=1 + strip=symbols (see the root Cargo.toml).
set -euo pipefail
cd "$(dirname "$0")/.."

# Use the project-scoped toolchain if present, so local and CI agree.
if [ -d .toolchain ]; then
  export RUSTUP_HOME="$PWD/.toolchain/rustup" CARGO_HOME="$PWD/.toolchain/cargo"
  export PATH="$CARGO_HOME/bin:$PATH"
fi

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
export CARGO_INCREMENTAL=0
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$PWD=/blindkey --remap-path-prefix=$cargo_home=/cargo"

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}

build_hash() {
  local target_dir="$1"
  rm -rf "$target_dir"
  CARGO_TARGET_DIR="$target_dir" cargo build --release --locked -p blindkey-cli >/dev/null 2>&1
  sha "$target_dir/release/blindkey"
}

echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "Building pass 1…"; h1=$(build_hash target-repro-1)
echo "Building pass 2…"; h2=$(build_hash target-repro-2)
rm -rf target-repro-1 target-repro-2

echo "pass 1: $h1"
echo "pass 2: $h2"
if [ "$h1" = "$h2" ]; then
  echo "OK: the blindkey binary is reproducible (identical SHA-256)."
  exit 0
else
  echo "FAIL: builds are not byte-identical."
  exit 1
fi
