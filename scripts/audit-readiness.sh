#!/usr/bin/env sh
# CP-7 release quality gate — release search benches + lint + supply-chain.
# Usage: ./scripts/audit-readiness.sh   (from repo root; activate toolchain first)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/dev-env.sh" ]; then
  # shellcheck disable=SC1091
  . "$ROOT/scripts/dev-env.sh"
fi

echo "==> Release search benchmarks (C38, C59)"
cargo test -p vault-core --release latency

echo "==> Sealed throughput bench (UC-23 / A23, release only)"
export VAULT_SEAL_BENCH_MIN_MIB_S="${VAULT_SEAL_BENCH_MIN_MIB_S:-20}"
cargo test -p vault-core --release c63_sealed_throughput_release_bench c63_rss_ceiling_large_on_disk_seal -- --nocapture

echo "==> Workspace tests"
cargo test --workspace --quiet

echo "==> Format check"
cargo fmt --all -- --check

echo "==> Clippy (-D warnings)"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> Supply chain"
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
  cargo audit
else
  echo "WARN: cargo-audit not installed — skip"
fi
if command -v cargo-deny >/dev/null 2>&1 || cargo deny --version >/dev/null 2>&1; then
  cargo deny check
else
  echo "WARN: cargo-deny not installed — skip"
fi
if command -v cargo-vet >/dev/null 2>&1 || cargo vet --version >/dev/null 2>&1; then
  cargo vet
else
  echo "WARN: cargo-vet not installed — skip (cargo install cargo-vet --locked)"
fi

echo "OK: release quality gate passed"
