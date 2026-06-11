# UC-11 — Keep KDF Cost Calibrated

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-11 · **Constraints:** C2, C22, C8 (touches C4, C9, C16)
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

KDF cost decays: the same Argon2id parameters get cheaper to attack every hardware generation, and
LastPass proved that parameters which are never recalibrated rot into negligence (1-iteration
PBKDF2, never migrated — crackable for $15). This spec covers: the `vault tune` benchmark
algorithm targeting **300 ms ± 100 ms**, the `vault upgrade-kdf` re-wrap flow (password stanza
only; payload ciphertext untouched per C4), floor enforcement on every open, the progress-indicator
design for derivations > 300 ms, and the reference-hardware definition that makes C22 testable in
CI. Out of scope: the floor/ceiling *parsing* mechanics (UC-10 §3.3), hardware-stanza rotation.

## 2. Prior art

### 2.1 Open source

- **KeePassXC**: its database security settings include a decryption-time benchmark that picks KDF
  parameters to hit a user-chosen unlock delay — the closest existing `tune` analogue, and the tool
  whose [Molotnikov audit (2023)](https://keepassxc.org/blog/2023-04-15-audit-report/) fixed our
  Argon2id choice.
- **libsodium `crypto_pwhash`**: ships fixed `OPSLIMIT_/MEMLIMIT_{INTERACTIVE,MODERATE,SENSITIVE}`
  presets rather than runtime calibration — the design we improve on, since presets go stale with
  hardware ([libsodium docs](https://doc.libsodium.org/password_hashing/default_phf)).
- **argon2-cffi**: documents choosing parameters by the RFC 9106 procedure and provides RFC-9106
  profiles — practitioner precedent for measure-then-pin (already the source for the "250–500 ms is
  community convention, not OWASP" correction in
  [research/vault_spec.md §2](../../research/vault_spec.md)).
- **palant.info LastPass analyses (2022)**: the cracking-economics table (C2 rationale) that makes
  "calibrated and floor-enforced" a product requirement, not a nicety.

### 2.2 Academic / standards

- **RFC 9106 §4 (“Parameter Choice”)**: the normative procedure — maximize memory first within the
  budget, then choose passes to fill the time budget. §3.1's algorithm is this procedure made
  executable.
- **Biryukov, Dinu, Khovratovich — “Argon2: New Generation of Memory-Hard Functions for Password
  Hashing and Other Applications”, IEEE Euro S&P 2016**: why memory, not time, is the
  attacker-cost lever — justifying "grow m before t".
- **OWASP Password Storage Cheat Sheet**: the floor (m=19 MiB, t=2, p=1) and the equivalence
  ladder; C2 deliberately keeps t ≥ 2 even at higher memory.

## 3. Proposed design

### 3.1 `vault tune` — benchmark algorithm

Runtime of Argon2id is, to first order, linear in `m · t` for fixed `p` (memory-fill bound — RFC
9106 / Argon2 paper), so proportional scaling converges in one or two steps; a binary search over
m would spend strictly more derivations for the same answer (§4).

```text
TARGET = 300 ms, TOL = 100 ms                 # C22: "300ms ± 100ms"
p = clamp(physical_cores, 1, 4)               # default p=4 cap: diminishing returns, laptop-friendly
t = 3                                         # C2 default; varied only at the memory bounds
m = 65_536 KiB (64 MiB)                       # start at the C2 default
m_max = min(C2 ceiling 4 GiB, total_RAM / 4) # never recommend params that gag the host
m_min = 19_456 KiB                            # C2 floor

repeat up to 6 iterations:
    ms = median of 3 timed Argon2id derivations            # throwaway password + salt,
         (1 untimed warm-up first, buffers zeroized)       # never the real ones
    if |ms − TARGET| ≤ TOL: done
    m' = clamp(m × TARGET / ms, m_min, m_max), rounded down to a 1024-KiB multiple, m' ≥ 8·p KiB
    if m' ≠ m:        m = m'                               # RFC 9106: memory first
    elif m == m_max and ms < TARGET − TOL: t += 1          # pinned at max memory → buy time cost
    elif m == m_min and ms > TARGET + TOL and t > 2: t −= 1  # floor-bound slow machine
    else: done                                              # bounds + t exhausted; report best

print:
  recommended: m=<KiB> (<MiB> MiB)  t=<t>  p=<p>     measured: <ms> ms
  current vault: m=… t=… p=…  →  run `vault upgrade-kdf --tuned` to apply
```

Properties: every recommendation already satisfies the C2 floor and C2 ceiling by construction;
`tune` is read-only (recommends, never applies); the C22 test "output contains `ms` and three
numeric values" is the literal last line. The measured throughput (`KiB·t per ms`) is cached in the
local state file for the §3.4 estimator.

### 3.2 `vault upgrade-kdf` — re-wrap flow

Re-derives the **password stanza only**. The data key does not change, so the payload is untouched
(C4: O(1) password-path rotation).

1. Prompt for the master password (the operation *requires* the password path — hardware stanzas
   neither need nor get re-wrapping, since their IKM is not Argon2id-derived).
2. Open the vault through the full UC-10 verification pipeline with the **old** params; unwrap the
   data key.
3. Select new params: `--tuned` (re-runs §3.1), explicit `--m/--t/--p` (validated against floor and
   ceiling), or the compiled current defaults. Note the C8 nuance: compiled defaults are legal as a
   *write-time recommendation*; they are never used to *interpret* an existing file.
4. Derive `master_key' = Argon2id(password, argon2id_salt, new params)` — the salt is **kept**:
   C8 fixes it at creation ("generated ONCE… MUST NOT be regenerated"), and it is already unique
   per vault (see §7 Q1).
5. Re-wrap: `wrapping_key' = HKDF(master_key', salt=vault_id, info="vault-pw-wrap-v1")`; seal the
   unchanged data key with a **fresh 24-byte nonce** → new 48-byte `wrapped_key`.
6. Rebuild the header: new m/t/p, new password stanza, fresh `master_seed` and `nonce_prefix`
   (this is a body-writing save — C8/C1), other stanzas byte-identical. Recompute `header_hash`
   and `header_hmac` (the HMAC key derives from the unchanged data key — G0.2; the value changes
   because the header bytes changed).
7. **G0.3 (intent v1.4.0): `upgrade-kdf` is a FULL body-writing save.** `vault_version`
   increments (C16), the body is re-encrypted under the fresh
   `payload_key' = HKDF(data_key, salt=new nonce_prefix)` (C1), and every HmacBlockStream MAC is
   recomputed (data-key-keyed with the new `master_seed` salt — C10). This closes the rollback
   blind spot: a backend serving the pre-upgrade file now fails the C16 version check (§7 Q2,
   resolved). The data key itself never changes (C4).
8. Atomic save (UC-03 §3.6: flock, temp, fsync, rename, `.bak`). `vault_version` does **not**
   increment — this is a header-only operation (UC-03 §3.7; consequence in §7 Q2).
9. Confirm on stderr: `KDF upgraded: m=… t=… p=… (was m=… t=… p=…)`. The old params exist nowhere
   in the new file (C2 test).

Failure atomicity: any error before step 8's rename leaves the original file intact — a
half-upgraded vault cannot exist on disk.

### 3.3 Floor enforcement on open (recap + non-interactive policy)

Per C2 and UC-10 step 6: params below floor ⇒ stderr WARNING containing
`below minimum recommended`, an explicit confirmation before deriving, and an upgrade offer after
successful unlock. This spec adds the non-interactive rule, mirroring C16's pattern: when stdin is
not a TTY, do not prompt — abort with exit code 2 and the warning on stderr;
`--allow-weak-kdf` proceeds explicitly. Above floor but below the *current compiled
recommendation*: one-line stderr notice (`tip: vault tune`), no prompt — nagging is rationed so the
warning channel keeps meaning (and C2's exact-floor test expects *no warning*).

### 3.4 Progress indicator (> 300 ms ⇒ spinner)

- **Estimate before deriving**: `est_ms = (m_kib × t) / throughput`, with `throughput` (KiB·t/ms)
  cached in the local state file from the last `tune`/open on this machine; first run assumes a
  conservative default so the spinner appears rather than not.
- If `est_ms > 300`: write `Deriving key… ⠋` to **stderr** (never stdout — stdout stays clean for
  scripts and the C27 channel discipline), animated only when stderr is a TTY; when it isn't, emit
  the static line `Deriving key (~Nms)…` once, so the C22 "non-empty progress indicator on stderr"
  test passes in both modes.
- The spinner clears (`\r\x1b[2K`, our own bytes, not attacker-influenced) before any subsequent
  output; measured duration updates the cached throughput after every real derivation, keeping the
  estimator honest as the machine ages.

### 3.5 Reference hardware and CI

C22's numbers are meaningless without a fixed yardstick. Definition (documented in CI workflow and
README):

| Property | Reference value |
|---|---|
| CPU | x86_64, ≥ 4 cores available to the process |
| RAM | ≥ 8 GiB |
| CI runner | a pinned GitHub-hosted Linux runner class meeting the above, recorded (`nproc`, `/proc/meminfo`) in the job log of every benchmark run |
| Benchmark statistic | median of 3 derivations, 1 warm-up discarded |
| Gates | default-params derivation: 200 ms ≤ median < 500 ms (C2/C22) · `vault tune` on the runner recommends params whose measured time ∈ [200, 400] ms · spinner appears when a 350 ms derivation is forced |

Shared-runner jitter is real: the gate uses the median, retries once on a > 500 ms outlier with a
loud annotation, and the job uploads measured numbers as an artifact so drift is visible over time
rather than only at failure.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| binary search over m | no linearity assumption | Argon2id *is* ~linear in m·t; ~2× the derivations (each costing real seconds) for identical output | Rejected |
| fix m, search t | t is integer, simple | inverts RFC 9106 §4 (memory first); attacker cost scales with memory, so trading m for t weakens the recommendation | Rejected — t moves only at the m bounds |
| auto-apply tune on every open | never stale | surprise multi-second opens; silent param churn on shared vaults; C8's file-authoritative spirit is "explicit writes" | Rejected — `tune` recommends, `upgrade-kdf` applies |
| libsodium-style fixed presets | zero code | presets rot (the LastPass failure mode generalized); C22 demands per-machine calibration | Rejected |
| rotate `argon2id_salt` during upgrade-kdf | fresh-salt hygiene | C8: salt "generated ONCE at vault creation; MUST NOT be regenerated"; rotation buys nothing (salt already unique per vault) and risks multi-stanza assumptions | Rejected — intent wins (§7 Q1) |
| increment `vault_version` on upgrade-kdf | rollback-protects the upgrade | counter lives inside the payload (C16/C18) ⇒ incrementing forces a payload rewrite, breaking C4's byte-identity test | Rejected for v1 — gap recorded in §7 Q2 |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C2 | floor checked on every open with warn + prompt + upgrade offer (§3.3); `upgrade-kdf` re-derives at validated params, old params absent from the new header (§3.2 step 9); tune never recommends below floor |
| C22 | tune targets 300 ± 100 ms (§3.1) and prints m, t, p with measured ms; spinner on stderr for > 300 ms derivations (§3.4); < 500 ms gate on the §3.5 reference runner |
| C8 | params read verbatim from the file on open; compiled defaults only ever *written* (§3.2 step 3); `argon2id_salt` immutable, `master_seed` regenerated on body-writing saves (C8/G0.2), `vault_id` untouched |
| C4 (touched) | data key unchanged through upgrade; the body IS re-encrypted under a fresh payload key (full save, G0.3) — C4's byte-identical test applies to password rotation, not `upgrade-kdf` |
| C9 (touched) | `header_hmac` recomputed over the new header bytes; its key derives from the data key (G0.2) and is unchanged — KDF tampering is caught by the re-wrapped password stanza's tag |
| C16 (touched) | `upgrade-kdf` increments `vault_version` (full save, G0.3) — rollback of a KDF upgrade is detected; §7 Q2 resolved |

## 6. Test plan

From the intent `test:` blocks: C2's CI timing bound, floor-warning trio, exact-floor no-warning,
and `upgrade-kdf` old-params-gone integration test; C22's benchmark gate, `tune` output-format
test, and progress-indicator assertion; C8's salt-stable / master_seed-fresh save pair; C4's
payload-byte-identity re-wrap test.

Spec-specific additions:

1. **Convergence unit**: mock the Argon2id timer with synthetic linear (and mildly non-linear)
   cost models across "hardware" from Raspberry-Pi-slow to workstation-fast; assert §3.1 terminates
   ≤ 6 iterations with a result in [200, 400] ms or pinned at a bound with the best achievable
   value.
2. **Bounds unit**: on a mocked 2 GiB-RAM host, assert `m_max = 512 MiB` (RAM/4) and the
   recommendation respects it; assert `m' ≥ 8·p` always holds.
3. **Upgrade atomicity**: SIGKILL during §3.2 steps 4–7; assert the original vault opens with the
   old params; after a completed run, assert the new vault opens and the `.bak` opens with old
   params.
4. **Hardware-stanza preservation**: vault with password + mocked FIDO2 stanza; `upgrade-kdf`;
   assert the FIDO2 stanza bytes are unchanged and still unlock (C5 OR-model intact).
5. **Full-save refresh**: after upgrade, assert `vault_version` incremented, every block HMAC
   differs (new `master_seed` salt), AND the block ciphertext differs (new `nonce_prefix` → new
   payload key) — full-save semantics per G0.3.
6. **Non-interactive floor**: pipe stdin from `/dev/null` against a below-floor vault; assert exit
   code 2, warning on stderr, no prompt; assert `--allow-weak-kdf` proceeds.
7. **Estimator honesty**: corrupt the cached throughput to a wild value; assert the next open still
   shows/clears the indicator correctly and rewrites a sane cache.

## 7. Open questions

1. **Salt rotation on `upgrade-kdf`**: C8's "never regenerated" language predates this flow. Fresh
   salt per KDF re-derivation is standard hygiene elsewhere; here it is redundant (per-vault unique
   salt, single password stanza) but harmless. Keeping it immutable is the intent-compliant choice
   — if rotation is ever wanted, the intent must change first.
2. **Rollback of a KDF upgrade is undetected** — ✅ Resolved 2026-06-10 (Gate 0 G0.3, intent
   v1.4.0): `upgrade-kdf` is a full body-writing save that increments `vault_version`, so C16
   detects a backend serving the pre-upgrade file. (A header-generation counter in the anchor
   remains a Part-2 idea for header-only operations such as password rotation.)
3. **Should `tune` also benchmark p > 4** on big desktops? Marginal: parallelism mostly trades
   latency, not attacker cost. Defer unless reference numbers say otherwise.
4. **CI runner drift**: if the pinned runner class changes hardware, the C22 gate may flap —
   re-baseline procedure (who, how) belongs in CONTRIBUTING.md before M8.
