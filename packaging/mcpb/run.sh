#!/bin/sh
# Launcher for the Blindkey MCP bundle: run the release binary for this OS and CPU.
set -eu
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) bin=blindkey-aarch64-apple-darwin ;;
  Darwin-x86_64) bin=blindkey-x86_64-apple-darwin ;;
  Linux-aarch64 | Linux-arm64) bin=blindkey-aarch64-unknown-linux-gnu ;;
  Linux-x86_64) bin=blindkey-x86_64-unknown-linux-gnu ;;
  *) echo "blindkey: unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
exec "$dir/$bin" "$@"
