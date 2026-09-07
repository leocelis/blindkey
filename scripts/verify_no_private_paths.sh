#!/usr/bin/env bash
# Fail if this public OSS tree names private vault / home paths.
# Naming the private path in a "✓ none" checklist is still a leak.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Assemble needles from fragments so this public script stays grep-clean.
_A1=limit
_A2=less/
_B1=workspace/
_B2=ledger
_C1=ledger/
_C2=tenants
_D1=tenants/
_D2=leocelis
_E1=/Users/
_E2=leocelis
PATTERN="${_A1}${_A2}|${_B1}${_B2}|${_C1}${_C2}|${_D1}${_D2}|${_E1}${_E2}"

hits="$(
  rg -n -e "$PATTERN" "$ROOT" \
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
