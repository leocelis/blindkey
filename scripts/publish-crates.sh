#!/usr/bin/env bash
# Publish workspace crates to crates.io in dependency order (UC-13 §3.6 Trusted Publishing).
# Requires CARGO_REGISTRY_TOKEN (from rust-lang/crates-io-auth-action in CI).
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  echo "FAIL: CARGO_REGISTRY_TOKEN is not set"
  exit 1
fi

PACKAGES=(blindkey-sys blindkey-core blindkey-hardware blindkey-clip blindkey-cli)

publish_one() {
  local pkg=$1
  local attempt=0
  until cargo publish --locked -p "$pkg"; do
    attempt=$((attempt + 1))
    if (( attempt >= 12 )); then
      echo "FAIL: cargo publish -p $pkg failed after $attempt attempts"
      return 1
    fi
    echo "Index not ready for $pkg — retry in 45s ($attempt/12)…"
    sleep 45
  done
}

for pkg in "${PACKAGES[@]}"; do
  echo "==> Publishing $pkg"
  publish_one "$pkg"
done
echo "OK: all crates published"
