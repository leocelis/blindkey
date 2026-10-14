#!/usr/bin/env bash
# Fail if this public OSS tree names private vault / home paths.
# Naming the private path in a "✓ none" checklist is still a leak.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Assemble needles from fragments so this public script stays grep-clean.
# Bare word, case-insensitive: naming the vault in prose leaks it as much as a path.
_A1=limit
_A2=less
_B1=workspace/
_B2=ledger
_C1=ledger/
_C2=tenants
_D1=tenants/
_D2=leocelis
_E1=/Users/
_E2=leocelis
# Short maintainer home dirs; fixtures use /Users/x/ and /home/x/ instead.
_F1='/(Users|home)/'
_F2=leo/
PATTERN="${_A1}${_A2}|${_B1}${_B2}|${_C1}${_C2}|${_D1}${_D2}|${_E1}${_E2}|${_F1}${_F2}"

# git grep ships with every clone, so the gate cannot silently skip when a tool is
# missing. --untracked also covers new files not yet added; .gitignore'd paths
# (target/, .toolchain/) are never published and are skipped.
# Exit 0 = hits, 1 = no hits, anything else = the scan itself failed (fail closed).
status=0
hits="$(
  git -C "$ROOT" grep -n -I -i -E --untracked -e "$PATTERN" -- . \
    ':!Cargo.lock' \
    ':!scripts/verify_no_private_paths.sh'
)" || status=$?

if [[ "$status" -gt 1 ]]; then
  echo "FAIL: leak scan could not run (git grep exit $status)"
  exit 2
fi

if [[ -n "$hits" ]]; then
  echo "FAIL: private vault/home path leak in Blindkey OSS tree"
  echo "$hits"
  exit 1
fi

echo "verify_no_private_paths: PASS"
exit 0
