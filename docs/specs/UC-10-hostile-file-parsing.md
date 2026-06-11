# UC-10 — Open a Stale or Hostile Vault File Safely

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-10 · **Constraints:** C2, C7, C8, C9 · **C2 ceiling** (was gap A1) · **C28** ANSI sanitization (was gap A2) — both promoted 2026-06-10
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

The vault treats its own file as untrusted input — it arrives via sync backends, restores, and
imports an attacker may control. This spec covers: parser hardening (bounded reads, length caps, no
allocation before validation), the exact verification order on open, the KDF parameter **ceiling**
(gap A1 — folded into C2 as the ceiling, 2026-06-10), the ambiguous-error policy, sanitization
of attacker-controlled bytes echoed to a terminal (C28, was gap A2), and the fuzzing
strategy for the targets already scaffolded in [`fuzz/`](../../fuzz/). Out of scope: the payload
TLV parser (UC-03 §3.2, which runs post-authentication), rollback handling (C16, UC-7).

Goals: a crafted file can never cause a panic, hang, over-read, or unbounded allocation; an
expensive Argon2id run never starts before its parameters are range-checked; tampering and a wrong
password are indistinguishable to an observer of the error channel; nothing the attacker wrote
reaches a terminal unescaped.

## 2. Prior art

### 2.1 Open source

- **KDBX 4** ([spec](https://keepass.info/help/kb/kdbx_4.html);
  [palant.info](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/)): the
  two-layer header integrity (keyless SHA-256, then keyed HMAC) and its verification order —
  C9 adapts it (our HMAC keys from the data key per G0.2, so every unlock path verifies), and this spec inserts the ceiling check into that order.
- **libgcrypt/cryptsetup Argon2 overflow fix**
  ([gcrypt-devel](https://www.mail-archive.com/gcrypt-devel@gnupg.org/msg00128.html)): the KiB→bytes
  conversion *"can cause integer overflow on 64-bit platforms"* — the direct precedent for C2's
  checked arithmetic (already analyzed in
  [security_coverage_gaps.md §A1](../../research/security_coverage_gaps.md)).
- **CVE-2025-55754 (Apache Tomcat)**: ANSI escape injection that could seed a malicious command
  into the admin's clipboard — the precedent class (CWE-150) for C28.
- **age / rage** ([C2SP spec](https://github.com/C2SP/C2SP/blob/main/age.md),
  [str4d/rage](https://github.com/str4d/rage)): a header grammar with explicit size discipline;
  rage's parser is fuzzed — the bar `vault-core`'s parser matches.
- **cargo-fuzz / libFuzzer, OSS-Fuzz**: the harness model already scaffolded in
  [`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets/) (`header_parse`, `stanza_parse`, `block_stream`).

### 2.2 Academic / standards

- **RFC 9106 (Argon2)**: parameter semantics and bounds; requires `m ≥ 8·p` KiB — a validity check
  we enforce alongside the ceiling.
- **NIST SP 800-38D** and **RFC 8439**: the authenticated-decryption discipline ("no plaintext
  before tag") that the verification order extends to the whole file.
- **CWE-150** (Improper Neutralization of Escape Sequences) — the weakness class behind §3.5.
- **OWASP Password Storage Cheat Sheet**: the *floor* the ceiling complements (C2).

## 3. Proposed design

### 3.1 Parser hardening strategy

Normative bounds (constants already in `vault-core`):

| Field | Bound | Source |
|---|---|---|
| fixed header prefix | exactly 100 bytes | C8 layout |
| `stanza_count` | 1 ..= 8 | C5 / `format::MAX_STANZAS` |
| `stanza_data_len` | 72 ..= 4096 | C5 (wrap_nonce 24 + wrapped_key 48 minimum) / `MAX_STANZA_DATA_LEN` |
| total header (prefix + stanzas + 64 tag bytes) | ≤ **32,972 bytes** = 100 + 8×(1+4+4096) + 64 | derived — the absolute read budget |
| block `size` field | 0 ..= 1,048,576 | C10 / `BLOCK_SIZE` |
| whole-file size sanity | ≥ 241 bytes (minimal valid vault, UC-01 §3.5) | derived |

Rules, in order of importance:

1. **No allocation before validation.** The parser reads the 100-byte fixed prefix into a stack
   array, validates magic/version/`kdf_algorithm`/`stanza_count`, and only then reads stanza
   records one at a time — each `stanza_data_len` checked against both its cap and the remaining
   input *before* its buffer is reserved. Nothing ever allocates from an attacker-supplied length
   without these checks. The 32,972-byte header budget bounds total parser memory regardless of
   file size.
2. **Checked arithmetic everywhere.** All size math uses `checked_add`/`checked_mul` (u64);
   overflow ⇒ `Error::HeaderCorrupt`. Clippy's `arithmetic_side_effects` lint is enabled for
   `format/`.
3. **Bounded reads, never `read_to_end`** on the body: blocks stream through a fixed 1 MiB buffer.
4. **Total parse, no panics.** Every parse function returns `Result`; `#![forbid(unsafe_code)]`
   already holds for the crate; `unwrap`/`expect`/indexing-without-check are denied by lint in
   `format/`.
5. **Reject, don't repair.** Trailing garbage after the final size=0 block, duplicate stanza types
   beyond layout rules, or `stanza_count=0` are hard errors — no best-effort recovery on a
   security-bearing format.

### 3.2 Verification order on open

Matches [FILE_FORMAT.md](../FILE_FORMAT.md) "verification order", with the ceiling inserted; each
step's cost is bounded before the attacker can spend ours:

| # | Check | Cost | Failure → error |
|---|---|---|---|
| 1 | magic = `56 4C 54 00` | 4 B compare | `not a vault file` (C7) |
| 2 | `format_version ≤ 1` (u16 LE) | trivial | `created by a newer version…` (C7) |
| 3 | fixed prefix fields: `kdf_algorithm = 1`, `1 ≤ stanza_count ≤ 8` | trivial | `unsupported KDF algorithm` / `header corrupt` |
| 4 | stanza records, bounded per §3.1 | ≤ 32,972 B | `vault header is corrupt` |
| 5 | `header_hash` = SHA-256 of bytes so far | one hash, keyless | `vault header is corrupt` (C9 step 1) |
| 6 | **KDF floor & ceiling** (§3.3) — *before any Argon2id allocation* | trivial | below floor: warn + prompt (C2); above ceiling/overflow: `KDF parameters exceed safe limits…` (C2) |
| 7 | Argon2id with the file's params (password path) | the only expensive step — cost now bounded by step 6 | — |
| 8 | stanza unwrap (Poly1305-authenticated) | trivial | **`invalid credentials or tampered header`** (C9 step 3, §3.4 — wrong password and tampered KDF params land here, indistinguishably) |
| 9 | `header_hmac` (data-key-keyed, G0.2) via `subtle::ConstantTimeEq` | one HMAC | `header tampered` (C9 step 4 — the factor was valid, so this is unambiguous tampering) |
| 10 | per-block HMAC (data-key-keyed) → per-chunk STREAM tag → only then release plaintext | linear | `authentication failed while decrypting…` (C1/C10) |

The C9 test "flip one bit in `m_cost` ⇒ failure faster than one Argon2id call" is satisfied by
step 5 preceding step 7; the A1 attack (absurd `m_cost` with a *recomputed* `header_hash` — which
is keyless and attacker-computable) is stopped by step 6 preceding step 7.

### 3.3 KDF parameter ceiling (C2, promoted from gap A1)

Proposed normative values — already staged as constants in
`crates/vault-core/src/crypto/mod.rs`:

| Parameter | Floor (C2) | Ceiling (C2) | Ceiling rationale |
|---|---|---|---|
| `m_cost` | 19,456 KiB | **4,194,304 KiB (4 GiB)** | 64× the default; 2× RFC 9106's most generous recommendation (2 GiB, non-interactive); half the C22 reference machine's 8 GiB RAM — anything above is a memory-DoS, not a security posture |
| `t_cost` | 2 | **24** | 8× the default t=3; OWASP's equivalence ladder tops out at t=5 — at the floor memory, t=24 already implies a multi-second unlock; beyond is denial, not defense |
| `p_cost` | 1 | **16** | parallelism beyond physical cores buys no attacker-resistance (RFC 9106); 16 covers workstation core counts |

Additional validity checks at step 6: `m_cost ≥ 8 × p_cost` KiB (RFC 9106 requirement — prevents
library-level errors from degenerate combinations), and the KiB→bytes conversion computed as
`u64::from(m_cost).checked_mul(1024)` — the libgcrypt overflow class is rejected before any
allocator sees the number. Error text (constant in `error.rs`, exact C2 string):
`"KDF parameters exceed safe limits — possible hostile or corrupt file"`.

Below-floor (stale, not hostile) keeps C2's distinct path: stderr WARNING containing
`below minimum recommended`, an interactive confirmation before deriving, and an upgrade offer
(`vault upgrade-kdf`, UC-11) after successful unlock. Never silent (C2).

### 3.4 Ambiguous-error policy

C9 (as amended by G0.2) mandates one indistinguishable message at the stanza step:
**`invalid credentials or tampered header`** (`Error::HeaderAuth`). Policy:

- The vault never distinguishes "wrong password", "modified KDF params with recomputed
  `header_hash`", "corrupted stanza ciphertext", or "swapped-in foreign header" — all fail the
  stanza unwrap at step 8 and emit the same string with the same exit code (5). Distinguishing
  them would hand an oracle to an attacker probing a stolen-then-restored file, and the *user*
  remediation is identical: retype the password; if it persists, restore from backup.
- A step-9 `header_hmac` failure (`header tampered`) is deliberately distinguishable: it fires
  only after a stanza unwrapped successfully, so the factor was valid and the condition is
  unambiguous tampering of header fields outside the stanza tag's coverage — no oracle is
  created (the attacker learns only that tampering was detected).
- Steps 1–6 failures **are** distinguishable on purpose: bad magic, newer version, keyless-hash
  corruption, and out-of-range KDF params are all conditions the attacker can already compute
  offline — naming them leaks nothing and gives the honest user an actionable message.
- Error messages never echo header bytes, file offsets of secret-adjacent fields, or derived
  material; file *paths* they echo pass through §3.5 sanitization.
- HMAC and tag comparisons use `subtle::ConstantTimeEq` (C25), so timing doesn't reintroduce the
  oracle the message text removes.

### 3.5 ANSI/control-sequence sanitization (C28, was gap A2)

Any byte sequence an attacker may have authored — entry fields seeded via import or a shared
machine, file paths, and the vault file bytes quoted in error messages — is sanitized before being
written to a terminal. CVE-2025-55754 (clipboard-seeding via escape sequences in console output)
is the precedent; CWE-150 the class.

```rust
/// Escape, never silently strip: C0 controls (except \n, \t), DEL (0x7F), and C1 (U+0080–U+009F).
/// Escaping ESC (0x1B) neutralizes all CSI/OSC/DCS sequences by construction.
/// Returns e.g. "title<U+001B>[2Jx" for input "title\x1b[2Jx".
pub fn sanitize_for_terminal(s: &str) -> Cow<'_, str>;
```

- **Visible escaping over stripping**: the user *sees* that a field contains `<U+001B>` — silent
  stripping would hide evidence of tampering.
- Applied at the CLI presentation layer to: `vault ls` output, `vault get` field display, `edit`
  previews, error messages echoing names/paths — and to `get --stdout` **only when stdout is a
  TTY**. When stdout is a pipe (the script case, UC-5), bytes pass through exactly, because scripts
  need the literal secret and no terminal is present to attack.
- `vault-core` never formats untrusted bytes into its error strings (error variants carry no
  attacker bytes except the io path, sanitized by the CLI).

### 3.6 Fuzzing strategy

The three scaffolded `cargo-fuzz` targets are the contract surface:

| Target | Feeds | Invariant |
|---|---|---|
| `header_parse` | arbitrary bytes → `Header::parse` | returns `Ok`/`Error` only; no panic, no hang, RSS bounded |
| `stanza_parse` | arbitrary bytes → stanza reader | bounds of §3.1 hold; count/len caps enforced |
| `block_stream` | arbitrary bytes → block reader (fixed test key) | size caps, end-marker, truncation handling |

Plus one added by UC-03: `payload_parse` (TLV, post-AEAD). Mechanics:

- **Corpus**: seed with the 241-byte minimal valid vault (UC-01), a max-header vault (8 stanzas ×
  4096), a multi-block body, and regression cases for every parser bug ever found (committed under
  `fuzz/corpus/`).
- **CI**: per-PR `cargo +nightly fuzz run <target> -- -max_total_time=300 -rss_limit_mb=512
  -timeout=10`; nightly scheduled job runs longer. The RSS limit turns "allocation before
  validation" bugs into hard failures; ASan (cargo-fuzz default) catches over-reads at the FFI
  boundary if libsodium is ever enabled.
- **Round-trip differential**: serialize(parse(bytes)) == canonical(bytes) for accepted inputs —
  catches accept/emit asymmetries.
- **Roadmap**: OSS-Fuzz enrollment and `arbitrary`-based structure-aware fuzzing (valid-header,
  hostile-stanza mutations) before M9; PRD success metric "no panics/OOM across fuzz corpus" gates
  v1.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| RAM-relative ceiling (`m ≤ available_RAM/2`) | adapts to small machines | nondeterministic accept/reject across hosts ⇒ a vault valid on one machine fails on another; untestable constraint | Rejected as the *constraint*; CLI may add an advisory warning |
| hard-reject below-floor params | simpler, no prompt | C2 explicitly mandates warn + prompt + upgrade offer (stale ≠ hostile) | Rejected — intent wins |
| silently strip ANSI escapes | cleaner output | hides tampering evidence; partial strips have bypass history | Rejected — visible escaping |
| distinguish "wrong password" from "tampered header" | friendlier UX | oracle for downgrade/tamper probing; C9 forbids it | Rejected — intent wins |
| serde-based header parsing | less code | attacker-facing parser must own its bounds and allocation order; C8's byte-exact layout is trivial by hand | Rejected (consistent with UC-03 §4) |
| `t` ceiling 16 / `p` ceiling 64 (task-prompt strawman) | — | p=64 wraps no real hardware and widens the `m ≥ 8p` interaction; constants m=4 GiB/t=24/p=16 are already staged in `crypto/mod.rs` | Rejected — keep scaffold values |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C2 | floor checked at step 6 before derivation; warn + prompt + `upgrade-kdf` offer for stale files; never silent |
| C7 | steps 1–2: exact magic bytes, LE u16 version, distinct "not a vault file" / "newer version" errors |
| C8 | parser returns the file's params verbatim (no compiled-in substitution); reader bounds make verbatim-read safe |
| C9 | step 5 keyless hash before Argon2id; step 8 stanza unwrap with the single ambiguous error; step 9 data-key-keyed HMAC (G0.2) verifiable on every unlock path; no payload byte decrypted on failure (steps strictly ordered) |
| C28 (candidate, gap A1) | §3.3 ceilings m≤4 GiB / t≤24 / p≤16, `m ≥ 8p`, checked KiB→bytes; rejection precedes allocation and derivation |
| C28 (was gap A2) | §3.5 `sanitize_for_terminal` on every attacker-influenced byte reaching a TTY |
| A4 (gap) | §3.1 rules + §3.6 fuzz targets and CI budgets |

## 6. Test plan

From the intent `test:` blocks: C7's magic/version/endianness units; C8's param-reader-verbatim and
round-trip units; C9's bit-flip-before-Argon2id timing test, HMAC-flip ambiguity test, and
downgrade test; C2's floor-warning integration tests (4 MiB / exact-floor / t=1 cases).

Spec-specific additions:

1. **Ceiling units**: `m=0xFFFFFFFF` KiB, `m=4 GiB+1 KiB`, `t=25`, `p=17`, `p=16,m<8p` — all
   rejected at step 6 with the C2 ceiling message, in < 10 ms, with zero large allocations (assert via
   allocator hook).
2. **Overflow unit**: param combinations whose KiB→bytes product exceeds u64 ranges are rejected,
   not wrapped (libgcrypt precedent).
3. **Hash-vs-ceiling ordering**: hostile file with huge `m_cost` *and* recomputed `header_hash`
   (attacker-computable) must die at step 6, never reaching Argon2id — wall-clock asserted.
4. **Oracle test**: wrong password vs tampered-KDF-params vs corrupted stanza → byte-identical
   stderr ("invalid credentials or tampered header") and identical exit codes (5). A flipped
   `header_hmac` with a VALID factor reports "header tampered" — distinguishable by design (G0.2).
5. **Sanitizer units**: fields containing `\x1b]52;…` (OSC-52 clipboard write), `\x1b[2J`, raw C1
   bytes, DEL — `ls` output contains the escaped form, never the raw byte; piped `get --stdout`
   passes bytes through verbatim.
6. **Fuzz gates in CI** per §3.6, plus committed regression corpus replays in plain `cargo test`
   (so a non-nightly contributor still runs every known crasher).
7. **Resource bound**: feed a 10 GiB file of valid magic + garbage; assert parser memory stays
   under the 33 KB header budget + one block buffer, and it fails fast.

## 7. Open questions

1. **Promote the ceiling and sanitization into the intent** — ✅ Resolved 2026-06-10 (intent v1.3.0): ceiling folded into C2, output sanitization is C28 —
   this spec is written as if approved; the intent is the gate (PRD §9 Q1).
2. **`header_hmac` on hardware-only unlock** — ✅ Resolved 2026-06-10 (Gate 0 G0.2, intent
   v1.4.0): C9/C10 HMAC keys now derive from the *data key* (`info="vault-header-hmac-v2"` /
   `"vault-block-hmac-v2"`), reachable on every stanza path. Verification order: header_hash →
   KDF bounds → stanza unwrap (wrong password / tampered KDF params fail here,
   indistinguishably) → header_hmac → block HMACs. As part of the same amendment,
   `master_seed` rotation is bound to body-writing saves so header-only rewrites cannot orphan
   the stored block HMACs.
3. **Exit codes** — ✅ Resolved 2026-06-10 (intent v1.4.0): C21 freezes the map — 2 rollback,
   3 not-a-vault/version, 4 corrupt, 5 auth, 6 KDF range, 7 no-clipboard, 8 usage, 9 not-found.
4. **OSC-52 nuance**: should `sanitize_for_terminal` special-case OSC-52 (clipboard write) with a
   louder warning, given C13/C27 make the clipboard our trusted delivery channel?
