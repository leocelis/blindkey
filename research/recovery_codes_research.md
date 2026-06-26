# Recovery codes at init — Research (security-gap review P2)

> **Task:** Optional offline recovery-code stanza at `vault init` (gap C3).

## Problem (gap C3)

Password-only vaults have no escape hatch if the master password is forgotten — by design there is
no server reset. 2FA enrollment already prints a recovery code; password-only init did not.

## Decision

| Choice | Rationale |
|--------|-----------|
| Second `PASSWORD` stanza (OR envelope) | Reuses C5 wrap recipe; `--recovery` unlock path already exists |
| Try all password stanzas on open | Master + recovery can coexist; first match wins with ambiguous auth |
| Opt-in at init | TTY confirm or `--with-recovery-code`; never silent |
| CSPRNG 24 alnum (~143 bits) | Same `recovery_code()` helper as YubiKey/keyfile enroll (C26) |
| Blunt no-reset copy | User must acknowledge lose-both-secrets risk |

## Not in scope

- Password hint / escrow / server recovery
- Replacing forgotten master without prior recovery enrollment
- Third `PASSWORD` stanza (max one recovery)

## References

- `research/security_coverage_gaps.md` C3
- `docs/specs/UC-01-install-and-init.md` §7 Q4
- `docs/specs/UC-09-hardware-factors.md` §3.5 (2FA recovery precedent)
- `Vault::add_recovery_stanza`, `Vault::has_recovery_stanza`
