# Padmé size-padding exploration — Research (security-gap review P3, S-12)

> **Task:** Evaluate PURBs/Padmé for sync size-leak reduction; ship optional, default-off.

## Problem (UC-07 §3.1)

A single `.vlt` on untrusted storage leaks **exact blob size** (≈ entry count) and **mtime**.
Padmé (PoPETS 2019 / PURBs) buckets plaintext length so only `O(log log L)` bits of length
significance remain, at ≤ ~12 % overhead (decreasing with size).

## Exploration verdict (2026-06-26)

| Question | Answer |
|----------|--------|
| Does Padmé fit v1 format? | **Yes** — padding after inner `END` marker, inside AEAD; `pad_mode` byte in inner TLV |
| Default in v1? | **No** — `PadMode::None`; explicit opt-in (`vault pad on`, GUI "Pad size") |
| Does it hide mtime/frequency? | **No** — size channel only |
| v2 default-on? | **Deferred** — needs constraint promotion + adversary model (UC-07 §7 open Q4) |

## Implementation (shipped pre–security-gap review)

- `vault-core/src/pad.rs` — `padme()`, `PadMode`, unit tests
- `Vault::padding()` / `set_padding()` — sticky policy, re-save applies bucket
- CLI: `vault pad on|off`
- GUI: "Pad size" checkbox

## When to enable

Sync to Dropbox/Drive/Git where a passive observer should not infer entry count from file size.
Accept ≤12 % storage overhead. Does **not** replace strong master password or backup discipline.

## v2 promotion criteria (not met yet)

1. Intent constraint + CP-7 test path for default-on policy
2. Longitudinal adversary analysis (per-user size history on backends with version retention)
3. Maintainer sign-off per GOVERNANCE.md

## References

- Nikitin et al., arXiv:1806.03160 (Padmé / PURBs)
- `docs/specs/UC-07-untrusted-storage-sync.md` §3.2
- `docs/guides/size-padding-padme.md` (user guide)
