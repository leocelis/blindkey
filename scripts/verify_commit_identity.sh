#!/usr/bin/env bash
# Fail if commits in a range use a machine-local author/committer email (@*.local).
# Public git history should not embed workstation hostnames.
#
# Usage:
#   ./scripts/verify_commit_identity.sh              # tip commit only
#   ./scripts/verify_commit_identity.sh FROM TO      # FROM..TO (exclusive FROM)
#
# Does not rewrite history. Commits already on main with a bad address stay;
# this gate blocks new ones. Pair with DCO (Signed-off-by) on PRs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

scan_log() {
  # Args are passed straight to `git log`.
  local bad=0
  local line sha rest ae ce addr
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sha="${line%% *}"
    rest="${line#* }"
    ae="${rest%% *}"
    ce="${rest#* }"
    addrs=("$ae")
    [[ "$ce" != "$ae" ]] && addrs+=("$ce")
    for addr in "${addrs[@]}"; do
      if [[ "$addr" == *.local ]]; then
        echo "FAIL: commit $sha uses machine-local email: $addr"
        echo "  Use a public-safe address (e.g. the address in MAINTAINERS.md) and git commit -s."
        bad=1
      fi
    done
  done < <(git log --format='%H %ae %ce' "$@")
  return "$bad"
}

label=""
if [[ $# -eq 0 ]]; then
  label="HEAD"
  if ! scan_log -1 HEAD; then
    exit 1
  fi
elif [[ $# -eq 2 ]]; then
  FROM="$1"
  TO="$2"
  if [[ "$FROM" =~ ^0+$ ]]; then
    label="$TO"
    if ! scan_log -1 "$TO"; then
      exit 1
    fi
  else
    label="${FROM}..${TO}"
    if ! scan_log "${FROM}..${TO}"; then
      exit 1
    fi
  fi
else
  echo "usage: $0 [FROM TO]" >&2
  exit 2
fi

echo "verify_commit_identity: PASS ($label)"
exit 0
