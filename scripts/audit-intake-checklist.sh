#!/usr/bin/env sh
# Pre-audit intake checklist — verifies repo is ready to send to a third-party auditor.
# Usage:
#   ./scripts/audit-intake-checklist.sh          # fast: docs + structure
#   ./scripts/audit-intake-checklist.sh --gate   # slow: also runs audit-readiness.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_GATE=0
if [ "${1:-}" = "--gate" ]; then
  RUN_GATE=1
fi

if [ -f "$ROOT/scripts/dev-env.sh" ]; then
  # shellcheck disable=SC1091
  . "$ROOT/scripts/dev-env.sh"
fi

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

ok() {
  echo "OK: $*"
}

echo "==> Third-party audit intake checklist (security-gap review P1)"

# TA-01: format freeze ADR
grep -q "Status:\*\* Accepted" docs/adr/0005-format-v1-freeze.md \
  || fail "ADR-0005 format freeze not accepted"
ok "ADR-0005 format v1 freeze accepted"

# TA-03: constraint index present and reports 60 PASS
grep -q "60" docs/CONSTRAINT_INDEX.md || fail "CONSTRAINT_INDEX.md missing 60-constraint reference"
grep -q "PASS" docs/CONSTRAINT_INDEX.md || fail "CONSTRAINT_INDEX.md missing PASS evidence"
ok "CONSTRAINT_INDEX.md present"

# TA-04: threat model
test -f docs/THREAT_MODEL.md || fail "THREAT_MODEL.md missing"
grep -q "Explicitly out of scope" docs/THREAT_MODEL.md || fail "THREAT_MODEL missing residual section"
ok "THREAT_MODEL.md present"

# Commission pack
test -f docs/AUDIT_COMMISSION.md || fail "AUDIT_COMMISSION.md missing"
grep -q "Scope statement" docs/AUDIT_COMMISSION.md || fail "AUDIT_COMMISSION incomplete"
ok "AUDIT_COMMISSION.md present"

# Core artefacts auditors need
for f in \
  vault_intent.yaml \
  docs/FILE_FORMAT.md \
  docs/CRYPTO.md \
  docs/specs/UC-04-model-blind-retrieval.md \
  docs/specs/UC-10-hostile-file-parsing.md \
  docs/specs/UC-14-runtime-hardening.md \
  research/security_coverage_gaps.md; do
  test -f "$f" || fail "missing artefact: $f"
done
ok "core audit artefacts on disk"

# Fuzz harness (C30)
test -d fuzz || fail "fuzz/ directory missing"
ok "fuzz targets directory present"

COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "==> Commit under review: $COMMIT"
echo "    Tag auditors should use: v1.0.0 (when published)"

if [ "$RUN_GATE" = "1" ]; then
  echo "==> Running CP-7 release gate (audit-readiness.sh)…"
  ./scripts/audit-readiness.sh
else
  echo "==> Skipping release gate (pass --gate to run audit-readiness.sh)"
fi

echo "OK: audit intake checklist passed — ready to attach docs/AUDIT_COMMISSION.md to RFP"
