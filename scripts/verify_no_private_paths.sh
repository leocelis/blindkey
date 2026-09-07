#!/usr/bin/env bash
# Fail if this public OSS tree names private vault / home paths.
# Naming the private path in a "✓ none" checklist is still a leak.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Contiguous private-tree tokens. This script is excluded from the scan.
# literal private path needles below are intentional gate detectors — not product docs.
PATTERN='limitless/|workspace/ledger|ledger/tenants|tenants/leocelis|/Users/leocelis'

hits="$(
  rg -nE "$PATTERN" "$ROOT" \
    --glob '!.git/**' \
    --glob '!**/target/**' \
    --glob '!**/node_modules/**' \
    --glob '!**/.venv*/**' \
    --glob '!**/Cargo.lock' \
    --glob '!scripts/verify_no_private_paths.sh' \
    2>/dev/null || true
)"

if [[ -n "$hits" ]]; then
  echo "FAIL: private vault/home path leak in Blindkey OSS tree"
  echo "$hits"
  exit 1
fi

echo "verify_no_private_paths: PASS"
exit 0
