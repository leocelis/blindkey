# ADR-0004: Header and block HMACs keyed from the data key; master_seed bound to body writes

- **Status:** Accepted
- **Date:** 2026-06-26
- **Deciders:** maintainers (Gate 0 G0.2)
- **Constraints:** C4, C5, C8, C9, C10

## Context

C9/C10 originally keyed the header HMAC and the per-block HMACs from the Argon2id-derived
`master_key`. Two defects:

1. **Hardware-only unlocks cannot verify.** The C5 OR-model lets a FIDO2/TPM/keystore stanza
   unlock without a password, so `master_key` is never derived on that path — the integrity
   layer was unverifiable for every non-password unlock (UC-10 §7).
2. **Header-only saves were self-contradictory.** SC6's original resolution had a password
   rotation rewrite the header with a fresh `master_seed` while leaving the body untouched —
   but `master_seed` salts the C10 block-HMAC keys, and `master_key` itself changes with the
   password, so every stored block HMAC would have failed on the next open. As specified,
   password rotation bricked the vault.

## Decision

Key both HMACs from the **data key**, which every unlock path reaches and which never changes
(C4):

```
header_hmac key = HKDF-SHA-256(ikm=data_key, salt=b"",                          info="vault-header-hmac-v2")
block_hmac  key = HKDF-SHA-256(ikm=data_key, salt=block_index_u64_LE||master_seed, info="vault-block-hmac-v2")
```

(The `-v2` info strings retire the master_key-keyed `-v1` derivations entirely.)

Bind `master_seed` regeneration to **body-writing saves** (same rule as `nonce_prefix`,
ADR-0003), so header-only rewrites leave the stored block HMACs valid. The C5 YubiKey challenge
(= `master_seed`) therefore also rotates per body write, with graceful staleness per G0.7.

Verification order becomes: keyless `header_hash` → C2 KDF bounds → stanza unwrap →
data-key-keyed `header_hmac` → block HMACs → STREAM tags. Error semantics split in two stages:
a wrong password and tampered KDF params both fail the stanza's Poly1305 tag with one
indistinguishable error ("invalid credentials or tampered header"); a `header_hmac` failure
after a successful unwrap is unambiguous tampering ("header tampered") — the factor was valid,
so no oracle is created.

KDF-downgrade defense is preserved without the master_key keying: lowered params change the
Argon2id output, so the derived wrapping key fails the password stanza's AEAD tag before any
payload work. The header HMAC authenticates what the stanza tag does not cover (`master_seed`,
`nonce_prefix`, stanza extras, `vault_id`).

## Alternatives rejected

- **Skip header-HMAC verification on hardware-only unlocks** — silently weaker integrity on
  exactly the paths marketed as the highest-security option.
- **Derive a parallel HMAC key per stanza type** — N key paths to audit, interop-fragile, and
  still leaves the master_seed/header-only-save contradiction unfixed.
- **Recompute all block HMACs on every header-only save** — turns O(1) password rotation into a
  full-file rewrite, contradicting C4's design goal and test.

## Consequences

- Password rotation is a true header-only rewrite: the entire body — ciphertext **and** block
  HMACs — stays byte-identical (C4's test now asserts exactly this).
- `vault upgrade-kdf` is explicitly a full body-writing save (G0.3) — it was never a header-only
  op once these rules exist, and the version bump closes its rollback blind spot.
- `error.rs` carries two variants (`HeaderAuth`, `HeaderTampered`); exit code 5 covers the
  ambiguous stanza-step failure (C21 map).
