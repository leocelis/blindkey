# Third-Party Audit — Commission Pack

> **Audience:** maintainers commissioning an external review.
> **Status:** ready to send RFP after `v1.0.0` tag (format freeze ✅, CP-7 gate ✅).
> **Research:** [research/third_party_audit_research.md](../research/third_party_audit_research.md)

Vault v1.0 does **not** require a third-party audit to ship ([THIRD_PARTY_AUDIT.md](THIRD_PARTY_AUDIT.md)).
This pack exists so the audit can be commissioned **before enterprise marketing**.

---

## 1. Verify prerequisites (automated)

From repo root with toolchain active:

```sh
./scripts/audit-intake-checklist.sh        # file + doc checks
./scripts/audit-intake-checklist.sh --gate # also runs audit-readiness.sh (slow)
```

All checks must pass on the **exact git commit** you give the auditor (tag `v1.0.0` when cut).

---

## 2. Scope statement (paste into RFP)

**Product:** Vault — local-first, zero-plaintext credential vault (Rust). Model-blind secret delivery for the AI-era threat model.

**Review goal:** Find exploitable flaws in the security-critical path before wide production adoption. Map findings to constraint IDs in [`vault_intent.yaml`](../vault_intent.yaml) or documented residual risks in [`THREAT_MODEL.md`](THREAT_MODEL.md).

### In scope

| # | Area | Start here |
|---|------|------------|
| 1 | On-disk format & hostile-input parsers | [`FILE_FORMAT.md`](FILE_FORMAT.md), `crates/vault-core/src/format/`, `fuzz/` |
| 2 | KDF, envelope, stanzas | [`CRYPTO.md`](CRYPTO.md), `crates/vault-core/src/crypto/`, `envelope/` |
| 3 | Memory & runtime hardening | [`specs/UC-14-runtime-hardening.md`](specs/UC-14-runtime-hardening.md), `vault-sys` |
| 4 | Model-blind delivery & argv hygiene | [`specs/UC-04-model-blind-retrieval.md`](specs/UC-04-model-blind-retrieval.md), `vault-cli`, `vault-clip` |
| 5 | Hardware factor boundary (mock + subprocess paths) | [`specs/UC-09-hardware-factors.md`](specs/UC-09-hardware-factors.md), `vault-hardware` |
| 6 | Desktop shell boundary | `crates/vault-gui/` — must not implement crypto |
| 7 | Release integrity | [`VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md), `scripts/reproducible-build.sh`, C34 |

### Out of scope

- Hosted cloud sync, team/org vaults, browser extension (intent `non_goals`)
- Live libfido2 / TPM 2.0 FFI (mocks and `ykman` subprocess only in v1)
- S-13 agent broker ([`specs/UC-16-agent-interface-future.md`](specs/UC-16-agent-interface-future.md)) — design exploration only
- Social engineering, physical coercion, fully compromised kernel while unlocked (see threat model)

---

## 3. Artefact bundle for auditors

Provide read access to the tagged repo plus this reading order:

1. [`vault_intent.yaml`](../vault_intent.yaml) — 60 falsifiable constraints
2. [`CONSTRAINT_INDEX.md`](CONSTRAINT_INDEX.md) — test map
3. [`THREAT_MODEL.md`](THREAT_MODEL.md) — in/out of scope adversaries
4. [`research/security_coverage_gaps.md`](../research/security_coverage_gaps.md) — Part 2 backlog (known partials)
5. [`research/llm_offensive_threats.md`](../research/llm_offensive_threats.md) — AI-era threat grounding
6. ADRs in [`adr/`](adr/README.md) — especially [0005 format freeze](adr/0005-format-v1-freeze.md)
7. UC specs: UC-04, UC-09, UC-10, UC-14 (linked above)

**Build & test commands:**

```sh
. scripts/dev-env.sh
just check              # fmt + clippy + tests
just audit-ready        # CP-7 release gate
just fuzz               # optional; requires cargo-fuzz + nightly
```

---

## 4. Vendor selection criteria

| Must have | Nice to have |
|-----------|--------------|
| Prior password-manager or KDF-focused audit | Rust fuzzing / hostile-file review |
| Rust memory-safety review experience | Fixed-scope quote for ~2–4 engineer-weeks |
| Accepts embargo + coordinated disclosure ([SECURITY.md](../SECURITY.md), UC-15) | OSS-friendly engagement model |

**Precedent:** KeePassXC independent audit (2023) — Argon2id recommendation cited in constraint C2.

---

## 5. Expected deliverables

1. Written report with severity-rated findings (Critical / High / Medium / Low / Informational)
2. Each finding mapped to a constraint ID **or** an explicit residual-risk entry for THREAT_MODEL
3. Proof-of-concept or reproduction steps for exploitable issues
4. Re-test confirmation after maintainer fixes before public disclosure
5. Optional executive summary (1 page) — not for marketing until published

---

## 6. Commissioning checklist (execution)

- [ ] Run `./scripts/audit-intake-checklist.sh --gate` on release commit
- [ ] Record commit hash: `git rev-parse HEAD`
- [ ] Shortlist 2–3 vendors; request fixed-scope quotes against §2 scope
- [ ] Execute NDA
- [ ] Grant private repo access or tarball at tagged commit
- [ ] Kickoff call: walk through threat model + constraint index
- [ ] Receive draft report under embargo
- [ ] Triage via [UC-15](specs/UC-15-vulnerability-reporting.md); patch on `main`
- [ ] Publish advisory + update SECURITY.md supported versions
- [ ] **Only then** use “independently audited” in marketing copy

---

## 7. Post-audit disclosure

Follow [`specs/UC-15-vulnerability-reporting.md`](specs/UC-15-vulnerability-reporting.md):

- Private intake: [GitHub Security Advisories](https://github.com/leocelis/vault/security/advisories/new)
- CVE request for qualifying issues
- Update [`CONSTRAINT_INDEX.md`](CONSTRAINT_INDEX.md) if new constraints or test gaps emerge

---

## Related

- [THIRD_PARTY_AUDIT.md](THIRD_PARTY_AUDIT.md) — policy (optional audit)
- [AUDIT_READINESS.md](AUDIT_READINESS.md) — automated CP-7 gate (not a substitute for human review)
- [ENTERPRISE_POSTURE.md](ENTERPRISE_POSTURE.md) — when audit matters for adoption
