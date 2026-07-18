# UC-13 — Verify What You're Running

> **Tech spec** · Accepted v0.2 · partially implemented pre-1.0 · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-13 · **Constraints:** C24, C23, C3; milestone M8; coverage-gaps D1/D2
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

A security tool you can't verify is a security tool you have to trust
([VERIFYING_RELEASES](../VERIFYING_RELEASES.md)). This spec turns the M8 milestone into an
implementation plan with four verifiable properties for every tagged release:

1. **Reproducible:** anyone can rebuild the published binary bit-for-bit from the tag.
2. **Signed:** every artifact carries a Sigstore cosign keyless signature tied to *our*
   release workflow's OIDC identity.
3. **Attested:** SLSA build provenance states which workflow, at which commit, built it.
4. **Inventoried:** the binary itself embeds its full dependency list (cargo-auditable), plus
   a CycloneDX SBOM file per release.

Threat countered (coverage-gap D1): a compromised CI runner, release account, or download
channel ships a backdoored binary. This is the distribution analogue of C9's header HMAC —
integrity the user checks without trusting the channel.

## 2. Prior art

### 2.1 Open source

- **ripgrep** ([RELEASE-CHECKLIST.md](https://github.com/BurntSushi/ripgrep/blob/master/RELEASE-CHECKLIST.md)):
  ✓ verified — signed git tags + per-artifact SHA-256 checksums generated in the release CI
  (checksums added via [PR #2168](https://github.com/BurntSushi/ripgrep/pull/2168)). No cosign,
  no SLSA. Lesson: checksums alone authenticate *integrity*, not *origin* — an attacker who can
  swap the binary can swap the checksum file on the same release page.
- **age / rage:** ✓ verified — the age spec keeps signing out of scope
  ([FiloSottile/age#51](https://github.com/FiloSottile/age/issues/51); minisign/signify are the
  recommended companions). [rage releases](https://github.com/str4d/rage/releases) ship
  tarballs/zips/`.deb`s with SHA-256 checksums and GPG-verified tags; no documented detached
  artifact signatures. Lesson: even excellent crypto projects under-invest here; tag signatures
  don't protect the *artifacts*.
- **sigstore-rs** ([github.com/sigstore/sigstore-rs](https://github.com/sigstore/sigstore-rs)):
  ✓ verified — the Rust sigstore client crate self-describes as **experimental**. We therefore
  use the cosign *CLI* for verification rather than linking sigstore-rs into anything.
- **cargo-auditable** ([rust-secure-code/cargo-auditable](https://github.com/rust-secure-code/cargo-auditable)):
  ✓ verified — `cargo auditable build --release` embeds the dependency list in a dedicated
  section of the binary; readable by `cargo audit bin`, trivy, `rust-audit-info` (JSON) and
  `auditable2cdx` (CycloneDX).
- **crates.io Trusted Publishing**
  ([RFC 3691](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html),
  [crates.io docs](https://crates.io/docs/trusted-publishing)): ✓ verified — GA July 2025;
  OIDC-authenticated publishing from a pinned repo+workflow, ~30-minute tokens via
  `rust-lang/crates-io-auth-action`, no long-lived API token to steal.

### 2.2 Academic / standards

- **reproducible-builds.org** — definitions and the
  [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/) spec for
  clamping embedded timestamps.
- **Rust RFC 3127 "trim-paths"** ([RFC text](https://rust-lang.github.io/rfcs/3127-trim-paths.html)):
  ✓ verified June 2026 — **still unstable**. Tracking: [rust-lang/rust#111540](https://github.com/rust-lang/rust/issues/111540),
  [cargo#12137](https://github.com/rust-lang/cargo/issues/12137); rustc's `--remap-path-scope`
  stabilization is in flight ([rust#147611](https://github.com/rust-lang/rust/pull/147611)).
  Until stable we use `--remap-path-prefix` (stable since 1.26) via `RUSTFLAGS`.
- **SLSA v1.0** ([slsa.dev](https://slsa.dev/spec/v1.0/faq)) — provenance levels; the GitHub
  generic generator yields SLSA Build L3.
- **OpenSSF Scorecard** — optional external measurement; not wired (no GitHub Actions).

## 3. Proposed design

> **Implementation note (2026-06-25):** Shipping today: maintainer-local builds
> (`scripts/reproducible-build.sh`), SHA-256 checksums, signed git tags, manual `cargo publish`
> ([RELEASE.md](../RELEASE.md)). Minimal GHA CI mirrors `just check` on push.
> Cosign OIDC, SLSA attestations, Scorecard, and Dependabot are deferred; verification today is
> checksum + reproducible build + signed tag.

### 3.1 Reproducible builds

| Lever | Mechanism | Status |
|---|---|---|
| Toolchain pinned | `rust-toolchain.toml` (already in repo) — exact channel/version, no "stable" drift | ✅ scaffolded |
| Dependency graph pinned | `cargo build --locked`; `Cargo.lock` committed (C3) | ✅ |
| Timestamps | export `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)` in the release job | add |
| Build-path leakage | `RUSTFLAGS="--remap-path-prefix=$PWD=/build"` (stable); migrate to `trim-paths = "all"` in the release profile **when RFC 3127 stabilizes** | add |
| Vendored source | attach `cargo vendor`-produced `vault-<tag>-vendor.tar.gz` (+ checksum) to each release, so rebuilds need no live crates.io | add |
| Build environment | document exact image (`ubuntu-24.04`, musl target) + a `just reproduce` recipe that reruns the canonical command and diffs hashes | add |

Per-platform honesty: the `x86_64-unknown-linux-musl` static binary (C20) is the canonical
reproducibility target. macOS and Windows builds are *best-effort* reproducible (Apple
code-signing and MSVC PE timestamps introduce nondeterminism); the docs say so explicitly
rather than overclaiming. Known upstream issues are tracked at
[rust#129080](https://github.com/rust-lang/rust/issues/129080).

### 3.2 Signing pipeline (deferred — cosign OIDC)

**Future enhancement:** Sigstore cosign keyless signing tied to a CI workflow OIDC identity.
Not shipped — releases use signed git tags + SHA-256 checksums today ([RELEASE.md](../RELEASE.md)).

### 3.3 SLSA provenance (deferred)

**Future enhancement:** in-toto attestations via `slsa-verifier`. Not shipped in v1 pre-alpha.

### 3.4 SBOM (decision: cargo-auditable, plus CycloneDX file)

**Decision: build release binaries with `cargo auditable build --release --locked ...`.**
The dependency inventory then travels *inside the artifact users actually run* — it cannot be
lost, swapped, or forgotten the way a sidecar SBOM file can, and `cargo audit bin vault` /
trivy can scan a downloaded binary directly against RustSec. Cost: a few KiB of compressed
section data; no runtime effect. Additionally emit `vault-<tag>.cdx.json` per release via
`auditable2cdx` (single source of truth: the binary's own embedded list) for SBOM-consuming
tooling. `cargo-sbom`/`cargo-cyclonedx` were considered (see §4).

### 3.5 Supply-chain gates (local)

| Gate | Where | Property |
|---|---|---|
| `cargo-deny` (advisories, licenses, bans, sources) | `just audit` + [`deny.toml`](../../deny.toml) | C24 license allowlist; openssl banned; crates.io-only sources |
| `cargo-audit` | `just audit` / `just audit-ready` | C3/C24: fail on High/Critical RustSec advisories |
| `cargo vet` | SECURITY.md commitment, M9 | reviewed-dependency gating (gap D2) |

### 3.6 crates.io publishing trust

- **Who can publish:** crate owners only — restricted to the maintainers
  ([MAINTAINERS.md](../../MAINTAINERS.md)); reserve the `blindkey-cli`/`blindkey-core` names early.
- **Publish path:** manual `cargo publish --locked` from a maintainer machine after
  `just audit-ready` passes — see [CRATES_IO_TRUSTED_PUBLISHING.md](../CRATES_IO_TRUSTED_PUBLISHING.md).
- **The provenance gap, stated honestly:** crates.io does **not** yet attach or verify
  cryptographic provenance/signatures on crate files — RFC 3691 lists sigstore-style provenance
  as a *future possibility*, and the cargo/sigstore RFC ([rfcs#3403](https://github.com/rust-lang/rfcs/pull/3403))
  is unmerged. So `cargo install blindkey-cli` is trust-on-registry. Mitigations we control:
  trusted-publishing (constrains *who/where* publishes), `--locked` publishes from the tagged
  commit, and documenting that the *verifiable* path is the signed GitHub release artifact;
  `cargo install` is the convenient path (C20), not the maximally-verified one.

### 3.7 Binary transparency (Rekor)

Keyless signatures are logged in the public Rekor transparency log; `cosign verify-blob`
checks log inclusion. Consequence for users: a signature that verifies but has no public log
entry is a red flag; consequence for maintainers: *we can monitor Rekor for signatures claiming
our workflow identity* — a signing-identity compromise becomes publicly observable. Document a
`rekor-cli search --artifact <file>` recipe in VERIFYING_RELEASES as the fourth check.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Maintainer-held GPG/minisign key | offline key possible; no Sigstore dependency | long-lived secret to protect/rotate; key distribution problem; rage/ripgrep show artifact signing then often lapses | ❌ keyless cosign instead |
| sigstore-rs in-process signing | pure Rust | crate self-described experimental; signing belongs in CI, not the product (C23) | ❌ cosign CLI in CI |
| cargo-sbom / cargo-cyclonedx sidecar only | simple; standard formats | SBOM separable from artifact; nothing embedded in the running binary | ❌ alone; ✅ CycloneDX *derived from* cargo-auditable data |
| cargo-auditable embedded inventory | inventory inseparable from binary; `cargo audit bin`/trivy scan downloads directly | adds a build wrapper to the release job; nightly `-Z sbom` precision still pending | ✅ **chosen** |
| Wait for stable `trim-paths` before shipping releases | cleaner config | blocks M8 on upstream timeline | ❌ `--remap-path-prefix` now, migrate later |
| Reproducibility for all 4 targets as a hard gate | strongest claim | macOS/MSVC nondeterminism outside our control | ❌ musl target canonical; others best-effort, documented |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C24 | `cargo audit` + `cargo deny` gate every release; license allowlist enforced (`deny.toml`); MSRV pinned; SBOM makes the audited tree externally checkable |
| C23 | verification is entirely user-side tooling; the shipped binary gains no network code — cargo-auditable adds inert data only (`strace` test from C23 still applies to release binaries) |
| C3 | `Cargo.lock` + `--locked` pin all crypto deps; embedded inventory proves *which* audited library versions are in the binary users run |
| C20 | the canonical reproducible artifact is the static musl binary; `ldd` check runs in the release job |
| (gap D1) | reproducible + cosign-signed + SLSA-attested releases close the "verify the artifact" gap |
| (gap D2) | cargo-auditable + CycloneDX per release; cargo-vet adoption tracked for M9 |

## 6. Test plan

- **CI (release workflow, dry-run on `workflow_dispatch`):** build twice in two fresh runners
  from the same tag; assert identical SHA-256 for the musl binary (reproducibility smoke test).
- **CI:** `cosign verify-blob` and `slsa-verifier verify-artifact` run *inside the pipeline*
  against the just-produced artifacts before the release is published — a release that fails
  its own verification instructions never ships.
- **CI:** `cargo audit bin dist/vault-x86_64-unknown-linux-musl` exits 0 (embedded inventory
  present and advisory-clean); `auditable2cdx` output validates as CycloneDX.
- **CI:** assert the SLSA subjects input is non-empty (regression test for the
  `outputs.hashes` fix in §3.2).
- **INTEGRATION (docs):** a clean container following VERIFYING_RELEASES verbatim ends with
  all checks passing — the doc is itself a test script (`just verify-release <tag>`).
- **C23 regression:** run the C23 `strace` network test against the *release* binary, not just
  the dev build.

## 7. Open questions

1. Pin third-party actions by commit SHA (Scorecard will flag tag-pinned `actions/checkout@v4`
   etc.) — adopt SHA-pinning repo-wide in M8?
2. Vendor tarball size vs value: ship per release, or only per minor version?
3. Publish the verification policy as a cosign `--certificate-identity` *exact* string instead
   of regexp once the workflow path is frozen?
4. Adopt GitHub artifact attestations (`actions/attest-build-provenance`) in addition to the
   SLSA generator, or keep one provenance mechanism to reduce confusion?
5. When RFC 3127 stabilizes: switch `RUSTFLAGS` remapping to `trim-paths` in `Cargo.toml`
   release profile and re-baseline reproducibility hashes.
