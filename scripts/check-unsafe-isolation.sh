#!/usr/bin/env bash
# Verify the unsafe-isolation invariant (CONTRIBUTING.md / C25):
#   ONLY `blindkey-sys` may contain `unsafe`, and every other crate declares
#   `#![forbid(unsafe_code)]`.
#
# This is belt-and-braces: `forbid(unsafe_code)` already makes any `unsafe` a compile error, but
# this guard pins the attribute in place so it can't be silently removed in a future refactor.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. Every crate except blindkey-sys must declare #![forbid(unsafe_code)] in its entry file.
for crate in crates/*/; do
  name=$(basename "$crate")
  [ "$name" = "blindkey-sys" ] && continue
  entry=""
  for f in src/lib.rs src/main.rs; do
    [ -f "$crate$f" ] && entry="$crate$f" && break
  done
  if [ -z "$entry" ]; then
    echo "?? $name: no src/lib.rs or src/main.rs found"
    continue
  fi
  if ! grep -q '#!\[forbid(unsafe_code)\]' "$entry"; then
    echo "FAIL $name: missing #![forbid(unsafe_code)] in $entry"
    fail=1
  fi
done

# 2. No `unsafe` keyword (as code) anywhere outside blindkey-sys. Excludes the forbid attribute,
#    line/doc comments, and SAFETY notes.
matches=$(grep -rn --include='*.rs' '\bunsafe\b' crates --exclude-dir=blindkey-sys \
  | grep -v 'forbid(unsafe_code)' \
  | grep -vE ':[[:space:]]*//' \
  | grep -vi 'safety' || true)
if [ -n "$matches" ]; then
  echo "FAIL: 'unsafe' found outside blindkey-sys:"
  echo "$matches"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "OK: unsafe is isolated to blindkey-sys; every other crate forbids it."
fi
exit "$fail"
