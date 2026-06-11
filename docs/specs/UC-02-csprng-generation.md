# UC-02 — Generate Provably Strong Credentials (`vault gen`)

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-2 · **Constraints:** C26 (primary), C3, C11, C23, C27
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

`vault gen` produces credentials whose strength is **provable by construction** — uniform CSPRNG
output with a documented bit count — rather than estimated after the fact. This spec covers:

- the rejection-sampling algorithm (uniformity proof included),
- exact charset definitions for `alnum` / `ascii` / `words` modes,
- embedding the EFF Large Wordlist in the binary,
- entropy accounting shown to the user,
- the zxcvbn 60-bit entropy-floor warning on `vault add` / `vault edit`,
- secure handling of the generated secret in memory and on delivery.

**Why no human- or LLM-chosen passwords.** Human and LLM-generated passwords are samples from
*predictable distributions*. Kaspersky testing cracked **88% of DeepSeek- and 87% of
Llama-generated passwords** (33% for ChatGPT) on commodity GPU hardware
([threats §5.1](../../research/llm_offensive_threats.md)). An LLM-generated password *looks*
random but inherits the model's parametric biases — its effective entropy is unknowable and
empirically low. C26 therefore prohibits any non-CSPRNG source and any LLM/network call in the
generator. The only password strength that is provable rather than hopeful is uniform sampling
from a known set, with entropy = `len × log2(|charset|)` bits, exactly.

Out of scope: pronounceable-password modes (biased by design), custom user wordlists (v1),
passphrase separators other than `-` (v1).

## 2. Prior art

### 2.1 Open source

| Source | What we take | What we change |
|---|---|---|
| OpenBSD [`arc4random_uniform(3)`](https://man.openbsd.org/arc4random_uniform.3) | Rejection sampling as *the* canonical fix for modulo bias ("avoids modulo bias when the upper bound is not a power of two") | We reject from the top of the byte range (simpler to audit) rather than the bottom of the u32 range |
| [`getrandom` crate](https://docs.rs/getrandom/) | OS CSPRNG access (`getrandom(2)`, `SecRandomCopyBytes`, `BCryptGenRandom`) — cited in C26 | — |
| KeePassXC password generator | Charset-class UI, entropy display in bits | KeePassXC's generator is GUI-first; ours is CLI-first with machine-stable defaults |
| `pass` / [passwordstore.org](https://www.passwordstore.org/) | `pass generate` exists, delegates to `/dev/urandom` via `tr` | pass prints the generated secret to a TTY by default; we deliver model-blind (C27, §3.6) |
| [EFF Dice-Generated Passphrases](https://www.eff.org/dice) | The Large Wordlist: 7776 words, 12.9 bits/word — cited in C26 | We drive it from OsRng instead of physical dice |
| [zxcvbn-rs (`zxcvbn` crate)](https://crates.io/crates/zxcvbn) | Strength estimation for *user-supplied* passwords only | Never used to "improve" generated passwords — generation is uniform by construction |

### 2.2 Academic / standards

- D. L. Wheeler, *"zxcvbn: Low-Budget Password Strength Estimation"*, USENIX Security 2016 —
  the estimator behind the C26 entropy floor; models real attacker dictionaries/patterns
  rather than naive charset entropy.
- RFC 9106 (Argon2id) — the KDF floor (C2) and this generator are complementary defenses:
  the KDF prices each guess; uniform generation makes the guess count astronomically large.
- [research/llm_offensive_threats.md §5.1](../../research/llm_offensive_threats.md) —
  AI-assisted cracking figures grounding the "no human/LLM passwords" design input.

## 3. Proposed design

### 3.1 Charsets (exact definitions)

| Mode | Set | Size | Bits/char | Default length | Default entropy |
|---|---|---|---|---|---|
| `alnum` | `A–Z` ∪ `a–z` ∪ `0–9` | 62 | 5.954 | 20 | **119.1 bits** |
| `ascii` (default) | printable ASCII `0x21..=0x7E` (`!` through `~`, **no space**) | 94 | 6.555 | 20 | **131.1 bits** |
| `words` | EFF Large Wordlist | 7776 | 12.925 bits/word | 6 words | **77.5 bits** |

Space (`0x20`) is excluded from `ascii`: it is invisible, trimmed by many web forms, and breaks
copy-paste. `--length N` accepts `8..=256` for character modes (C26); `--words N` accepts
`6..=20` — the intent fixes the minimum at 6 words (≈ 77 bits), so 5-and-below is a hard
validation error, not a warning.

```rust
const ALNUM: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
// ASCII charset constructed as 0x21..=0x7E at compile time; asserted len == 94 in a unit test.
```

### 3.2 Rejection sampling — algorithm and uniformity proof

Modulo reduction (`byte % charset_len`) is **forbidden by C26**: for `len = 94`,
`256 = 2·94 + 68`, so characters at indices `0..68` would each receive 3 of the 256 byte
values while indices `68..94` receive 2 — a 1.5× frequency skew an offline cracker exploits
for free. Rejection sampling removes the bias entirely:

```rust
use zeroize::Zeroizing;

/// Uniformly sample one index in [0, len) from the OS CSPRNG. len <= 256.
fn sample_index(len: usize) -> Result<usize, GenError> {
    debug_assert!((2..=256).contains(&len));
    // Largest multiple of `len` that fits in a byte's range:
    let limit: u16 = (256 / len as u16) * len as u16; // == floor(256/len) * len
    loop {
        let mut b = Zeroizing::new([0u8; 1]);
        getrandom::fill(&mut *b)?;                    // OsRng — constraint C26
        if (b[0] as u16) < limit {
            return Ok(b[0] as usize % len);           // unbiased: see proof below
        }
        // else: reject and resample
    }
}
```

**Uniformity proof.** Let `L = floor(256/len) · len` (the `limit`). Accepted bytes are exactly
`{0, 1, …, L−1}`, and `L` is a multiple of `len`, so each residue class `r mod len` contains
exactly `L / len` accepted values. Each byte value is equiprobable (`1/256`) from the CSPRNG,
so conditioned on acceptance, `P(index = r) = (L/len)/L = 1/len` for every `r`. ∎

**Termination.** Acceptance probability is `L/256 ≥ 1/2` for every `len ≤ 256`
(worst case `len = 129..255`; for our sets: `ascii` 188/256 ≈ 73.4%, `alnum` 248/256 ≈ 96.9%).
Expected samples per character `≤ 2`; the loop terminates with probability 1 and the expected
total draw for a 20-char password is < 28 bytes. No timing side-channel concern: the rejection
pattern reveals nothing about *accepted* values.

**Words mode** samples a `u16` (2 bytes) per word with `limit = floor(65536/7776) · 7776 = 62208`
(acceptance ≈ 94.9%), same proof shape with 65536 in place of 256.

### 3.3 EFF wordlist embedding

- `eff_large_wordlist.txt` (the 7776-word column, dice indices stripped) is embedded at compile
  time via `include_str!` and parsed into a `static` `[&str; 7776]` by a `build.rs`-free
  `once_cell`/`LazyLock` initializer. Binary size cost ≈ 60 KiB — acceptable against C20's
  single-static-binary goal (no runtime file lookup, no network fetch, consistent with C23).
- A unit test asserts: exactly 7776 entries, all lowercase ASCII, no duplicates, and a pinned
  SHA-256 of the embedded text (supply-chain tamper check on the list itself).
- Words are joined with `-`. Entropy is `N × log2(7776) = N × 12.925` bits; the separator and
  word boundaries are assumed **known to the attacker** (Kerckhoffs) and contribute 0 bits.

### 3.4 Entropy accounting displayed to the user

Every `vault gen` prints an accounting line to **stderr** (stdout stays clean — §3.6):

```
Generated: 20 chars from 94-char printable ASCII = 131.1 bits (uniform CSPRNG).
```

The number is computed as `length × log2(charset_size)`, rounded to one decimal. This is the
*exact* entropy of the sampling process, not an estimate — the line says "uniform CSPRNG" to
distinguish it from zxcvbn *estimates* shown for user-supplied passwords (§3.5).

### 3.5 zxcvbn entropy floor on `vault add` / `vault edit` (warn, never block)

When the user supplies their own password (interactive prompt — never argv, see UC-05 §3.5):

```rust
let estimate = zxcvbn::zxcvbn(&password, &[&entry_name, &username]);
let bits = estimate.guesses_log10() * std::f64::consts::LOG2_10; // log2(10) ≈ 3.3219
if bits < 60.0 {
    eprintln!("WARNING: estimated strength ~{bits:.0} bits (< 60). \
               Consider `vault gen` for a provably strong password.");
}
// Entry is stored regardless — C26: warn, don't block.
```

- Threshold: **60 bits**, per C26. Entry name and username are passed as user inputs so
  `github-prod`-derived passwords score honestly.
- The warning goes to stderr; exit code is unaffected. Blocking is prohibited (warn-don't-refuse
  is explicit in the intent) — a user importing legacy credentials must not be stopped.
- zxcvbn is an *estimator* (Wheeler 2016): good at catching human patterns, not a certificate of
  strength. The UI language is "estimated"; only generated passwords get the word "provably".

### 3.6 Secure handling of the generated secret

- The candidate password is accumulated in `Zeroizing<Vec<u8>>` / `Zeroizing<String>` (C11);
  every rejected sample buffer is `Zeroizing` too. No `Vec<u8>` for secret bytes, no `Debug`.
- **Delivery defaults to the clipboard**, identical to `vault get` (C27/C13 machinery from
  [UC-04](UC-04-model-blind-retrieval.md)): a freshly generated password becomes a live secret
  the moment the user submits it to a signup form, so it must not land in an agent transcript.
  `vault gen --stdout` prints it with the C27 warning on stderr (UC-05 semantics).
- When `vault gen` is invoked *inside* `vault add` (offer: "generate instead? [Y/n]"), the
  secret flows directly from generator to entry struct to encrypted payload — it is never
  displayed at all.
- Accounting line (§3.4) contains length and charset only — never the secret.

### 3.7 Error paths

| Condition | Behavior |
|---|---|
| `getrandom` fails (kernel entropy unavailable) | Hard error, exit 1: `cannot read OS CSPRNG; refusing to generate`. Never fall back to a userspace PRNG (C26). |
| `--length` outside `8..=256` | clap validation error, exit 2 (usage). |
| `--words` outside `6..=20` | clap validation error, exit 2 (C26: min 6 words). |
| `--charset words --length N` | Error: `--length` applies to character modes; use `--words`. |
| Clipboard unavailable (headless) | Same fallback policy as UC-04 §3.7: refuse with guidance toward `--stdout`. |

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Modulo reduction of a random byte | One line, no loop | Provable bias (1.5× skew at len=94); forbidden by C26 | **Rejected** |
| `rand::Rng::gen_range` (Lemire/widening multiply) | Unbiased, fast | Pulls in `rand`'s sampling internals; harder for an auditor to verify than 6 lines of explicit rejection; C26's STATIC test greps for the explicit pattern | **Rejected** — auditability beats elegance |
| Float scaling (`byte as f64 / 256.0 * len`) | Branchless | Biased (uneven bucket widths); classic bug | **Rejected** |
| Ask an LLM for a "random" password | — | 87–88% cracked (threats §5.1); prohibited by C26 and the intent's prohibitions list | **Rejected** |
| Fetch wordlist at runtime / first run | Smaller binary | Network call violates C23; mutable wordlist breaks reproducibility | **Rejected** |
| Embed EFF Short Wordlist (1296 words) instead | Shorter words | 10.3 bits/word → needs 8 words for ~80 bits; Large list is the EFF default recommendation | **Rejected** (could ship later as `--wordlist short`) |
| Print generated password to stdout by default | Script-friendly | Lands in agent transcripts/scrollback — the exact C27 failure mode | **Rejected**; clipboard default + `--stdout` opt-in |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C26** | OsRng via `getrandom` only; explicit rejection sampling (proof §3.2); exact 62/94/7776 sets at the intent's defaults and lengths; EFF list embedded; zxcvbn 60-bit warn-don't-block on `add`/`edit` (§3.5); no LLM/network path exists in the module |
| **C3** | No custom crypto: `getrandom` and `zxcvbn` are audited/widely-reviewed crates; sampling is arithmetic, not a primitive |
| **C11** | All candidate/secret buffers are `Zeroizing`; rejected samples zeroized too (§3.6) |
| **C23** | Generator makes zero network calls; wordlist is compile-time embedded |
| **C27** | Generated secret defaults to clipboard delivery; stdout requires the warned `--stdout` opt-in (§3.6) |

## 6. Test plan

1. **UNIT (bias, C26):** generate 100,000 `ascii` characters; chi-square goodness-of-fit over
   94 categories; assert `p > 0.01`. Repeat for `alnum` (62) and `words` (7776 over 50,000 draws).
2. **UNIT (charset/length):** `vault gen --length 32 --charset alnum` → exactly 32 chars, all in
   `[A-Za-z0-9]`. `--charset ascii` → all bytes in `0x21..=0x7E`.
3. **UNIT (words):** `--charset words --words 6` → exactly 6 `-`-separated tokens, each present
   in the embedded list; pinned SHA-256 of the embedded list matches.
4. **UNIT (floor warning):** `vault add` with password `password1` → stderr contains
   `vault gen`, exit code 0, entry stored. With a 25-char generated password → no warning.
5. **UNIT (entropy line):** `--charset ascii --length 20` accounting line contains `131.1`.
6. **STATIC (C26):** grep generator module: `getrandom`/`OsRng` present; no `thread_rng`;
   no `% charset` outside the post-acceptance reduction inside `sample_index` (lint comment
   pins the audited line); no `reqwest`/`hyper`/LLM SDK in the dependency tree of `vault-gen`.
7. **PROPERTY:** for every `len` in `2..=256`, `limit % len == 0` and `limit > 0`.
8. **INTEGRATION (C27):** `vault gen` with no flags → stdout empty, clipboard holds a 20-char
   string; `vault gen --stdout` → password on stdout, warning on stderr.

## 7. Open questions

1. **EFF wordlist license attribution.** The EFF wordlists are published under a Creative
   Commons Attribution license (unverified exact version — confirm before publishing); embedding
   requires an attribution notice in `COPYRIGHT` and `--charset words --help`.
2. **`vault gen` default channel** — this spec proposes clipboard-by-default for symmetry with
   C27, but C27's text binds only `vault get`. Promote to a constraint amendment, or leave as
   implementation policy? (Recommend: fold into C27 at the next intent revision.)
3. **Symbol-restricted charsets** (`--charset alnum --symbols '!@#'`) for sites with composition
   rules — deferred; entropy accounting must then reflect the reduced set honestly.
4. **`zxcvbn` crate maintenance status** — re-check before M6 freeze; the estimator choice is
   load-bearing for C26's floor test.
