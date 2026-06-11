# UC-09 — Add a hardware factor without lockout risk

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-9 · **Constraints:** C5, C6, C14, C15
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Enroll FIDO2, YubiKey challenge-response, TPM 2.0, macOS Secure Enclave, or Windows DPAPI as an
*additional* way to unlock — never the only way. This spec covers: the enrollment/management CLI,
per-type stanza design (drawing on `research/vault_spec.md` §4 and Q4), unlock ordering and
fallback, stanza removal and its interaction with `master_seed` rotation, and per-factor threat
notes. The OR-envelope itself (C5) is recapped, not redesigned.

Out of scope: browser WebAuthn (prohibited path, C6/C14), PIV/PGP smartcards, and remote
attestation.

## 2. Prior art

### 2.1 Open source

| Source | What we take |
|---|---|
| age (C2SP) multi-recipient stanzas | The any-of-N wrapped-key envelope C5 already adopts |
| KeePassXC YubiKey support (KeePassX PR #52 lineage) | Challenge = master seed from the header, rotated per save → replayed old responses can't unlock newer files (`research/vault_spec.md` §4) |
| libfido2 (Yubico/OpenBSD) | The raw CTAP2 `hmac-secret` path (C14); standard cross-platform CTAP2 library |
| tpm2-tools / tss-esapi | `tpm2_create --sealing-input` + `tpm2_policypcr` + `tpm2_unseal` flow (C15) |
| systemd-cryptenroll | Convention of binding LUKS keys to **PCR 7** (Secure Boot cert state) because it survives routine kernel/firmware updates better than PCR 0/2/4 ([Arch manual](https://man.archlinux.org/man/systemd-cryptenroll.1), verified June 2026) — adopted as our default policy in §3.4 |

### 2.2 Academic / standards

- **W3C WebAuthn Level 3 §10.1.4** (`prf` extension = browser surface of CTAP2 `hmac-secret`).
- **Yubico PRF developer guides** — "treat the 32-byte PRF output as IKM, not a final key";
  browser path pre-hashes the salt (`SHA-256("WebAuthn PRF" || 0x00 || salt)`), raw CTAP2 does
  not — the two paths produce *different* secrets from the same authenticator, so we standardize
  on raw CTAP2 only (C6 rationale).
- **TCG TPM 2.0 Library Specification** / kernel.org TPM docs — PCR sealing semantics and the
  bus-attack caveat ("most TPM functionality can be controlled by an attacker who has access to
  the bus") that C15 requires us to document.
- **Apple Platform Security guide** — SE keys are device-bound and non-extractable ("software can
  request encryption and decryption operations with hardware keys, it can't extract the keys").
- **MSDN DPAPI / CNG** — DPAPI binds to user SID + machine ("usually must be done on the same
  computer"); `CRYPTPROTECT_LOCAL_MACHINE` lets *any* local user decrypt → forbidden here.

## 3. Proposed design

### 3.1 OR-envelope recap (C5)

Every stanza independently wraps the same 32-byte `data_key`:

```
wrapping_key     = HKDF-SHA-256(ikm = <stanza secret>, salt = vault_id, info = <type label>)
wrapped_data_key = XChaCha20-Poly1305-Seal(wrapping_key, wrap_nonce[24], data_key)   → 48 bytes
```

Any single valid stanza unlocks. The password stanza is **mandatory and irremovable** — every
hardware factor is additive, so a lost/broken/re-flashed device kills one stanza, never the
vault. Max 8 stanzas, `stanza_data_len ≤ 4096` (C5/C8).

### 3.2 CLI surface

```
vault enroll fido2 [--rp-id vault.local]     # touch to enroll
vault enroll yubikey [--slot 2]
vault enroll tpm  [--pcrs 7]                 # alias: vault enroll-tpm   (C21 name preserved)
vault enroll keychain                        # macOS Secure Enclave
vault enroll dpapi                           # Windows, current user scope
vault re-enroll tpm                          # alias: vault re-enroll-tpm (C21/C15)
vault stanzas list                           # types + enrollment dates, no secrets
vault stanzas remove <type>[#index]          # password removable: NO (hard error, C5)
```

All enrollment commands require a full unlock first (the data key must be in memory to wrap).
Enrollment is a vault **save**: stanza appended, `master_seed` rotated, header re-HMAC'd. C21
names only `enroll-tpm`/`re-enroll-tpm`; the generalized `vault enroll <type>` / `vault stanzas`
surface is additive and needs a C21 amendment (§7). `vault stanzas list` output (one line per
stanza): type, created-at, type-specific public hint (FIDO2 rp_id, YubiKey slot, TPM PCR set) —
never key material.

### 3.3 Per-type stanza design

All `extra` bytes below live in the stanza record after `wrap_nonce[24] || wrapped_key[48]` (C5).

**FIDO2 (type 2 · `info="vault-hw-wrap-v1"` · C6/C14).** Raw CTAP2 `hmac-secret` via libfido2 —
never the browser path. Enrollment: `fido2_cred_new` with `rp_id` (default `"vault.local"`),
store `credential_id`. Unlock: assertion with
`salt = SHA-256(vault_id || b"fido2-hw-v1")` → 32-byte PRF output → **HKDF, never used raw**.

```rust
struct Fido2Extra {           // serialized LE, bounded parse (FILE_FORMAT.md rules)
    credential_id_len: u16, credential_id: Vec<u8>,   // ≤ 1023
    rp_id_len: u8,          rp_id: String,            // UTF-8
    salt_hash: [u8; 32],    // SHA-256(vault_id || b"fido2-hw-v1"), per C14, precomputed
}
```

Requires user presence (touch); PIN/UV honored if the authenticator enforces it. Wrong device →
"no matching FIDO2 credential" (C14 test), proceed to next stanza.

**YubiKey HMAC-SHA1 CR (type 3 · `info="vault-yk-wrap-v1"` · C5).** Challenge is the header
`master_seed`; the 20-byte response is hashed — `yk_ikm = SHA-256(response)` — before HKDF
(avoids zero-padding bias, C5). Because `master_seed` rotates on every body-writing save (C8), the stanza must be
**re-wrapped at save time**, which needs the device present:

- Device present at save → recompute response for the new seed, re-wrap, store
  `challenge = master_seed` in `extra`. Replay property holds: an old response can't unlock the new file.
- Device absent → keep the old wrap and its old `challenge[32]` in `extra` (unlock still works;
  the stanza answers to its stored challenge, not the rotated header seed) and print
  `WARNING: yubikey stanza not refreshed (key absent); insert it and save to restore challenge rotation.`

`extra = { slot: u8 (1|2), challenge: [u8; 32] }`. The graceful-staleness design was ADOPTED
into C5 on 2026-06-10 (Gate 0 G0.7, intent v1.4.0), with `yubikey_strict` / `--strict-yubikey` opting into the abort-on-absent behavior —
originally flagged in §7, now resolved.

**TPM 2.0 (type 4 · `info="vault-tpm-wrap-v1"` · C15).** Seal a 32-byte CSPRNG `tpm_ikm` (not
the data key itself — keeps the C5 recipe uniform) to a PCR policy via tss-esapi/tpm2-tools.
**Default policy: PCR 7 (Secure Boot certificate state), SHA-256 bank.** Rationale: PCR 7
changes only when Secure Boot keys/policy change, not on routine kernel updates — far fewer
spurious re-enrollments than PCR 0/2/4 (systemd-cryptenroll convention, §2.1); `--pcrs` allows
stricter sets. `extra = { pcr_bank: u8, pcr_mask: u32, sealed_blob_len: u16, sealed_blob }`.
On PCR-mismatch unseal failure, emit verbatim (C15): `TPM stanza failed (PCR mismatch — firmware
or kernel may have changed). Run 'vault re-enroll-tpm' or unlock with password.`
`vault re-enroll tpm`: unlock via any *other* stanza → fresh `tpm_ikm`, re-seal to current PCRs,
replace stanza, save. `--help` text must contain "PCR", "firmware", "re-enroll" (C15 test).

**macOS Secure Enclave (type 5 · `info="vault-mac-wrap-v1"`).** Enrollment: create a P-256 key
*inside* the SE (`kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`),
generate `se_ikm[32]` from OsRng, wrap it with `SecKeyCreateEncryptedData`
(`eciesEncryptionCofactorX963SHA256AESGCM`), store the ECIES blob in `extra` with the keychain
application tag. Unlock: `SecKeyCreateDecryptedData` (Touch ID / Face ID via LAContext when the
access control demands it) → `se_ikm` → HKDF. The SE private key never leaves the enclave;
moving the disk to another machine leaves the blob undecryptable — convenience stanza only.

**Windows DPAPI (type 6 · `info="vault-win-wrap-v1"`).** `dpapi_ikm[32]` from OsRng,
`CryptProtectData` with **user scope** (never `CRYPTPROTECT_LOCAL_MACHINE` — any local user could
decrypt) and `vault_id` as `pbOptionalEntropy`; blob in `extra`. Unlock: `CryptUnprotectData` →
HKDF. Survives the user's password changes (DPAPI credential history); dies with the user
profile/machine. CNG Platform Crypto (TPM-backed, `MS_PLATFORM_CRYPTO_PROVIDER`) is the stronger
sibling — deferred (§7).

### 3.4 Unlock priority and fallback

Try cheap/silent factors first, loud ones with consent, password last:

```
1. dpapi      silent                     (Windows)
2. keychain   biometric prompt, fast     (macOS)
3. tpm        silent                     (Linux/Windows)
4. fido2      only if a device with a matching credential_id is enumerated;
              then prompt on stderr: "Touch your security key… (Enter to skip)"
5. yubikey    only if a YubiKey is enumerated; same prompt pattern
6. password   no-echo prompt (always present, always last)
```

Rules: device *detection* is quiet (enumerate, no touch/no UI); the vault never blocks on a
hardware touch without a stderr line and a skip path; any stanza failure (missing device, PCR
mismatch, AEAD open failure on `wrapped_key`) logs one stderr line and falls through. Every
unwrap is verified by the Poly1305 tag on `wrapped_key` — a wrong factor cannot yield a wrong
data key silently. `--stanza <type>` forces a single path (CI: `--stanza password` +
`--password-fd`). Non-TTY: skip steps 4–5 prompts entirely; silent factors still run.

### 3.5 Stanza removal and master_seed rotation

`vault stanzas remove <type>` requires unlock; rewrites the header without the stanza; the save
rotates `master_seed` (C8). Effects worth documenting to the user:

- Removal protects **future** files. Old blobs in backend history (UC-07 §3.1) still carry the
  removed stanza; a *compromised* (not merely lost) factor can unlock those copies. The honest
  remedy is data-key rotation (`vault rotate-data-key`, coverage-gap C2 proposal) which re-seals
  the payload so old wraps open an obsolete key — print this hint on every removal.
- YubiKey removal also ends challenge rotation; FIDO2/SE/TPM removal leaves device-side residue
  (a resident credential, an SE key, a TPM object) that `remove` deletes best-effort and reports.
- Removing the password stanza: hard error (C5), no flag.

### 3.6 Threat notes per factor

| Factor | Lost device | Compromise resistance | Out of scope |
|---|---|---|---|
| FIDO2 | Stanza dead, vault fine (password path) | Seed never leaves the secure element; per-credential | Authenticator firmware bugs |
| YubiKey CR | Same | Response replay blunted by seed rotation (when refreshed) | HMAC-SHA1 secret extraction via physical attack |
| TPM | Machine loss = stanza loss | Software-only attackers; PCR 7 detects boot-policy change | **Bus attacks (SPI sniffing, TPM Genie) — explicitly not mitigated (C15b, THREAT_MODEL.md)** |
| Secure Enclave | Device-bound by design | Survives AP kernel compromise per Apple's guarantee | Apple platform trust itself |
| DPAPI | Profile/machine loss = stanza loss | Same-user-credential boundary only — weakest factor; convenience tier | Other-user/admin on same machine (admin can often access DPAPI masterkeys) |

In every row the failure mode is *stanza dead, not vault dead* — the C5 invariant this UC exists
to preserve.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Composite key (password ⊕ hardware required together) | Stronger single path | Lost factor = lost vault; violates C5/`prohibitions` | **Prohibited** |
| Browser WebAuthn PRF instead of libfido2 | No C dependency | Different salt transform → secrets incompatible with raw CTAP2; needs a browser | **Prohibited** (C6/C14) |
| Wrap data_key directly inside TPM/SE (no ikm indirection) | One less step | Breaks the uniform C5 recipe; ties wrapped_key size/format to each backend's blob format | Reject |
| PCR 0+2+4+7 default for TPM | Detects more boot changes | Re-enroll on every kernel/firmware update; C15's brittleness warning becomes the common case | Reject as default; allow via `--pcrs` |
| YubiKey strict mode (refuse save without device) | Pure C5 replay property | Bricks saves when the key is in a drawer | ✅ Adopted as `yubikey_strict` config / `--strict-yubikey` (C5/G0.7); graceful remains the default |
| CNG/TPM instead of DPAPI on Windows | Hardware-bound | More moving parts; DPAPI is the documented C5 type 6 | DPAPI v1, CNG candidate v2 |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C5 | All five types use the exact HKDF(ikm, salt=vault_id, info=label) + XChaCha20 wrap recipe and the stanza record layout; password stanza mandatory and irremovable; ≤ 8 stanzas; YubiKey ikm = SHA-256(response); graceful staleness is now C5's specified default (G0.7), strict mode opt-in |
| C6 | FIDO2 = raw CTAP2 hmac-secret via libfido2 only; salt = SHA-256(vault_id ‖ "fido2-hw-v1"); PRF output is IKM into HKDF, never a key |
| C14 | Stanza stores credential_id, rp_id, salt_hash exactly as specified; wrong-device → "no matching FIDO2 credential", no crash |
| C15 | PCR policy + re-enroll command + verbatim PCR-mismatch message; bus-attack limitation documented in §3.6 and `--help` text carries "PCR"/"firmware"/"re-enroll" |

## 6. Test plan

1. **UNIT:** per-type HKDF vectors — known ikm + vault_id → expected wrapping_key for each info
   label; raw prf_output ≠ wrapping_key (C6 test).
2. **UNIT:** `Fido2Extra`/TPM/YK extra parsers — bounded, no panic on truncated/oversized input
   (fuzz corpus shared with the header fuzzer).
3. **INTEGRATION (mock libfido2):** enroll → reopen with same authenticator → unlock; different
   credential_id → "no matching FIDO2 credential" then password fallback succeeds (C5/C14).
4. **INTEGRATION (mock TPM):** seal at PCR=X, mutate to Y → exact C15 message, then password
   fallback; `re-enroll tpm` → unlock at Y succeeds.
5. **INTEGRATION (YubiKey mock):** save with device present → `extra.challenge == master_seed`,
   old response fails on new file; save with device absent → warning emitted, unlock via stored
   challenge still works.
6. **INTEGRATION:** `stanzas remove fido2` → vault reopens by password; removal of password →
   hard error; removal prints the rotate-data-key hint.
7. **INTEGRATION (ordering):** non-TTY with FIDO2 enrolled but absent → no touch prompt appears;
   exit follows password/`--password-fd` path.
8. **DOC test:** `vault enroll tpm --help` contains "PCR", "firmware", "re-enroll" (C15).

## 7. Open questions

1. **C21 amendment** — ✅ Resolved 2026-06-10 (intent v1.4.0): C21 now specifies `vault stanzas list|add|remove` (intent previously
   names only `enroll-tpm`/`re-enroll-tpm`); keep the hyphenated forms as permanent aliases.
2. **YubiKey graceful staleness vs. strict C5 wording** — ✅ Resolved 2026-06-10 (G0.7): the stored-challenge design
   (this spec) is C5's specified behavior; strict device-at-save is the `yubikey_strict` opt-in.
3. **DPAPI optional entropy** — using `vault_id` as `pbOptionalEntropy` is public knowledge
   (it's in the header); is a per-enrollment CSPRNG entropy value stored… where? (Storing it in
   `extra` is circular.) Likely answer: vault_id is fine — DPAPI's boundary is the user
   credential, entropy only de-dupes scope — but confirm before implementing.
4. **Biometric gating policy for SE** — require user presence on every unlock
   (`kSecAccessControlUserPresence`) or allow silent when the session is already authenticated?
5. **Stanza re-wrap on `upgrade-kdf`** — KDF upgrade rewraps the password stanza; confirm
   hardware stanzas are untouched (they don't depend on Argon2id) and tested as such.
