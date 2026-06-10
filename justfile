# Vault developer task runner — https://github.com/casey/just
# `just` with no args lists tasks. Each task maps to what CI enforces.

# List available tasks.
default:
    @just --list

# Format, lint (warnings = errors), and test — the pre-PR gate.
check: fmt-check clippy test

# Format the code.
fmt:
    cargo fmt --all

# Verify formatting (CI).
fmt-check:
    cargo fmt --all -- --check

# Lint with clippy; deny warnings (constraint-grade strictness).
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Run the test suite.
test:
    cargo test --all-features --workspace

# Supply-chain checks: advisories + licenses + bans (constraints C3, C24).
audit:
    cargo audit
    cargo deny check

# Optional deeper dependency vetting (constraint C39 candidate).
vet:
    cargo vet

# Generate a CycloneDX SBOM for a release.
sbom:
    cargo cyclonedx --format json

# Smoke-run the fuzz targets (constraint C31 candidate). Requires `cargo install cargo-fuzz`.
fuzz target="header_parse":
    cargo +nightly fuzz run {{target}} -- -max_total_time=30

# Run benchmarks (e.g. KDF unlock timing, constraint C22).
bench:
    cargo bench

# Build the release binary (static target documented in docs/INSTALL.md).
build-release:
    cargo build --release --locked

# Everything CI runs.
ci: check audit
