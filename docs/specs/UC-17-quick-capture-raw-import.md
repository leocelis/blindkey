# UC-17 — Quick-Capture from a Messy Secrets File

> **Tech spec** · Accepted v0.2 · implemented pre-1.0 · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-17 · **Constraints:** C21 (import), C26, C18, C19, C27; touches C11, C16, C17, C23
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Get a developer's real-world `keys.txt` — a pile of API keys and tokens with **no reliable
structure**: some `key=value`, some bare secret lines, blocks split by blank lines *or* `---`
rulers — into the vault in one low-friction pass, then make every secret findable
([UC-06](UC-06-entry-management.md)) and retrievable to the clipboard
([UC-04](UC-04-model-blind-retrieval.md)). This is the "easier than 1Password, faster, better"
on-ramp: point it at the file, skim the guesses, confirm, done.

It is the **lenient sibling** of [UC-12](UC-12-migration-import.md). UC-12 `--format txt` parses a
*documented* schema (first line = name, second = password). This spec adds `--format raw`: a
best-effort heuristic parser **with an interactive review step**, for files that have no schema at
all. Everything downstream (entropy scan, dedupe, single atomic save, post-import shred guidance)
is reused from UC-12 §3.3–§3.6 — this spec only adds the lenient parser, the classifier, the
interactive disambiguation, and a small optional entry-model nicety (`kind`).

Goals:

1. `vault import --format raw <file>` (also accepts stdin) → reviewed entries → one atomic save.
2. Never write a secret to stdout/stderr; the review UI shows **masked** previews only (C27).
3. Every captured secret is Protected at rest (C19) and entropy-scanned (C26).
4. No intermediate plaintext written by Vault; honest guidance to destroy the source (UC-12 §3.6).
5. Wrong guesses are *cheap to fix* in review — the parser is allowed to be imperfect because the
   human confirms before the save.

Out of scope: structured-format imports (UC-12), live file watching, re-export to the source format.

## 2. Prior art

### 2.1 Open source

| Source | Relevance |
|---|---|
| **pass** ([passwordstore.org](https://www.passwordstore.org/)) | The "first line is the secret, the rest is free-form notes" convention — the single most useful heuristic for an unlabeled block. Already the C21 baseline. |
| **trufflehog / gitleaks / detect-secrets** | Secret *detection* in arbitrary text via two signals: (a) high-entropy strings (Shannon entropy over base64/hex alphabets) and (b) known provider regexes/prefixes. We borrow the same two-signal classifier to tell a *secret* line from a *label* line. Mechanism is well established; specific thresholds/rulesets **(unverified — confirm the exact prefix set and entropy cutoffs against a current ruleset before freezing §3.3)**. |
| **1Password / Bitwarden item types** | Both ship non-login secret categories (e.g. "Secure Note"; 1Password "API Credential") — precedent that a vault entry need not be a username/password pair. Exact category names **(unverified — confirm before citing in user docs)**. |
| **KDBX custom fields / KeePassXC** | Arbitrary protected string fields per entry — the model our existing `custom_fields` (UC-03 §3.1) already mirrors, giving us a home for "extra lines" with no field name. |

### 2.2 Academic / standards

- **Shannon, "A Mathematical Theory of Communication" (1948)** — entropy of a string over an
  alphabet; the basis for the high-entropy-equals-secret signal. We compute bits/char over the
  detected alphabet (base64url, hex, or printable-ASCII) and threshold it.
- **Wheeler, "zxcvbn", USENIX Security 2016** — reused unchanged for the post-classification C26
  weak-secret scan (a captured value that is *low* entropy gets flagged, same as UC-12).
- CVE-2025-55754 / CVE-2019-20184 (ANSI/CSV-injection precedents already cited in
  [security_coverage_gaps.md](../../research/security_coverage_gaps.md) A2/A3) — the source file is
  untrusted bytes; anything echoed in the review UI is control-sanitized (§3.5).

## 3. Proposed design

### 3.1 CLI surface

```
vault import --format raw <file|->            # lenient parse + interactive review
            [--yes]                            # accept all guesses, no prompts (CI/non-TTY)
            [--default-kind login|apikey|note] # how to classify ambiguous blocks (default: apikey)
            [--tag <t>]                        # apply a tag to every imported entry
            [--on-duplicate skip|rename|overwrite]   # UC-12 §3.4, default skip
```

`--format raw` lives under the existing `vault import` command (C21) — **no new top-level command,
no new constraint**. Requires an unlocked session like every mutating command.

### 3.2 Block splitting (lenient)

Split the file into candidate blocks on **either** delimiter:

1. A line matching `^\s*-{3,}\s*$` (a `---`/`-----` ruler), **or**
2. A run of one or more blank lines.

Bounds (hostile-input posture, gap A4): max line length 64 KiB, max blocks 10 000, max bytes 64 MiB
— exceed any and the import aborts with a clear message before allocating per-block. Trailing/leading
whitespace trimmed per line; a block that is entirely blank after splitting is dropped.

### 3.3 Per-block classification

For each non-blank line in a block, assign a role:

```
classify_line(line) -> Role
  KeyValue(k, v)  if line matches `^\s*([A-Za-z0-9_.-]{1,64})\s*[:=]\s*(.+)$`
  Secret(v)       if looks_like_secret(v_or_line)        // entropy OR known prefix
  Label(v)        otherwise                               // short, low-entropy, human text
```

```
looks_like_secret(s) =
     has_known_prefix(s)                       // e.g. sk-, ghp_, gho_, AKIA, AIza, xox[bap]-,
                                               //      glpat-, AGE-SECRET-KEY-1, -----BEGIN … KEY-----
  || (len(s) >= 20 && shannon_bits_per_char(s) >= T_alphabet)   // T ~ 3.0 hex / 4.0 base64 (tune)
```

Block → entry mapping:

| Block shape | Title | Secret slot | Extra |
|---|---|---|---|
| `KeyValue` lines (`AWS_SECRET=…`) | the key name (`AWS_SECRET`) | the value | other KV pairs → custom_fields |
| one `Label` + one `Secret` | the label | the secret | — |
| bare `Secret` only | provider-from-prefix (`sk-`→`openai?`) else `imported-<n>` | the secret | raw line kept in notes |
| multiple secrets in one block | label or `imported-<n>` | first secret → primary | remaining secrets → **Protected** custom_fields |

The primary secret is stored in the entry's `password` field (UC-03 tag `0x8004`, already
P-bit/Protected — **so C19 is satisfied with zero model change**). Extra secrets use Protected
custom_fields (`0x800D`). Classification is deliberately conservative: **when unsure, treat a line
as Secret** (false-Secret is harmless — it's Protected and reviewable; a false-Label would print a
secret in the review UI, which §3.5 forbids).

### 3.4 Optional entry-model nicety: `kind`

To make `vault get`/`ls` label an API key as a *key* rather than a *password*, add an optional
discriminator to the UC-03 `Entry`:

```rust
pub enum EntryKind { Login, ApiKey, Note }   // default: Login (back-compat)
pub kind: EntryKind,                          // new TLV record 0x000E inside an entry
```

- It is **non-secret metadata** (which slot to surface), so it rides as a plain (non-P) TLV tag and
  is forward-compatible via UC-03's unknown-tag-skip — old readers ignore `0x000E` and see a normal
  entry. **No file-format break, no crypto change.**
- `get` on an `ApiKey` returns `password` by default (already the default field) and labels it
  "key"; `ls` may show a `🔑`/`[key]` marker.
- **This is the only place the intent is even arguably touched**: C18's field list and C19's
  Protected list are non-exhaustive ("not exhaustive; all fields are encrypted"), and the secret
  still lands in the already-Protected `password` slot, so **no constraint amendment is required** —
  at most a one-line documentation note adding `kind` to C18's enumerated example fields. Flagged in
  §7 for the maintainers; the importer works without it (everything maps to `Login` + `password`).

### 3.5 Interactive review (the UX that makes imperfect parsing acceptable)

After classification, present a compact, **masked** summary and let the user fix it before any save:

```
Parsed 7 blocks → 7 entries (review before save):

 #  title            kind    secret (masked)     extra
 1  AWS_SECRET       apikey  AKIA…J7QX (40)      region: us-east-1
 2  github           apikey  ghp_…a1b2 (40)      note: "personal PAT"
 3  imported-3       note    sk-pr…9f3 (51)      —     ← guessed; rename?
 …
[e]dit a row  ·  [m]erge two rows  ·  [s]kip a row  ·  [r]ename  ·  [Enter] save all
```

- Masking shows ≤4 leading + ≤4 trailing chars and the **length only** — never the middle, never the
  full value (C27; consistent with UC-08's masked-diff rule). A short secret (<12 chars) is shown as
  all-dots + length, so masking never reveals a meaningful fraction.
- Every displayed cell (titles, labels, custom names) is **ANSI/control-sanitized** before printing
  (gap A2) — a malicious `keys.txt` cannot own the terminal.
- `--yes` / non-TTY skips the review and accepts all guesses (UC-05 non-TTY matrix); the masked
  summary is still written to stderr as a record of what was captured.

### 3.6 Pipeline (reuses UC-12)

```
read(file|stdin)  → blocks (§3.2)  → classify (§3.3)  → Vec<Entry> (§3.3–3.4)
  → INTERACTIVE REVIEW (§3.5)        → confirmed Vec<Entry>
  → entropy_scan (C26, zxcvbn)       → flag weak captured values
  → dedupe (UC-12 §3.4)              → --on-duplicate policy
  → single atomic save               → one vault_version increment (C16), Protected fields
                                        inner-encrypted (C19), UC-03 §3.6 temp+rename+fsync
  → post-import guidance (UC-12 §3.6): destroy the source, with SSD/COW caveats
```

All buffers holding source bytes or secrets are `Zeroizing`/`SecretBox` end-to-end (C11). The raw
source file is read into a single mlock'd `Zeroizing<Vec<u8>>`; it is never copied to a temp file.
No network at any step (C23).

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **`--format raw` + interactive review** | handles real messy files; imperfect parser is safe because human confirms; reuses UC-12 pipeline | needs a small TUI review loop | ✅ **chosen** |
| Force users into UC-12 `--format txt` | no new code | rejects/mangles unstructured files — the actual user need; bad first impression | ❌ rejected |
| Fully automatic import (no review) | one keystroke | silent mis-classification stores a label as a secret or vice-versa; unfixable post-hoc | ❌ rejected (offered only as explicit `--yes`) |
| Dedicated `vault capture` command | discoverable verb | new command + arguably new constraint surface for no capability gain over `import --format raw` | ❌ rejected (note as alias in §7) |
| New top-level `secret`/freeform field on `Entry` | semantically clean | model bloat; `password`(Protected) + `custom_fields` already cover it; more C18/C19 surface | ❌ rejected — reuse `password`, add only the `kind` tag |
| LLM-assisted parsing of the blob | "smart" splitting | sends secrets to a model — categorically prohibited (C27); the whole point is model-blind | ❌ **prohibited** |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C21 (import)** | adds `--format raw` under the existing `import` command; no new command/verb |
| **C26** | every captured value runs through the zxcvbn scan; weak ones flagged with a `vault gen` nudge (warn-don't-block) |
| **C18** | captured fields are serialized only inside the AEAD payload via UC-03 §3.2; the source is never re-emitted as plaintext by Vault |
| **C19** | the primary secret lands in the already-Protected `password` slot; extra secrets use Protected (`0x800D`) custom_fields — inner-stream double-encrypted |
| **C27** | review UI shows masked previews only; `--yes`/non-TTY still never prints a full secret; no model/network path |
| **C16 / C17** | exactly one `vault_version` increment per import; single blob, no per-entry files |
| **C11 / C23** | source bytes + secrets in `Zeroizing`/`SecretBox`, mlock'd; zero network |
| Gap A2/A4 | block/line/byte caps before allocation; all echoed cells control-sanitized |

## 6. Test plan

1. **UNIT (splitter):** fixtures mixing `---` rulers and blank-line gaps; assert correct block count
   incl. empty-block drop and the `^-{3,}$` (not `--foo`) boundary.
2. **UNIT (classifier):** table of lines → expected Role; include known-prefix secrets, high-entropy
   base64/hex, `KEY=val`, `key: val`, and human labels; assert the conservative "unsure ⇒ Secret".
3. **UNIT (entropy):** Shannon bits/char over base64 vs hex vs prose; assert prose < threshold,
   random tokens ≥ threshold; boundary cases at the configured cutoff.
4. **INTEGRATION (round-trip):** import a 7-block messy fixture with `--yes`; assert 1 file write,
   `vault_version` +1, all secrets retrievable via `vault get`, and `strings vault.vlt` reveals no
   captured value (C18 probe).
5. **INTEGRATION (masking, C27):** capture under `script`/pty; assert no full secret and no middle
   bytes appear on stdout/stderr; only ≤4+≤4+length masks.
6. **UNIT (A2):** a block titled `evil\x1b]52;c;…\x07` lists as escaped text; raw ESC absent.
7. **INTEGRATION (kind):** import with `--default-kind apikey`; assert `get` returns the key without
   `--field` and an old reader (kind tag absent) still parses the entry (forward-compat).
8. **FUZZ:** `cargo-fuzz` target over arbitrary file bytes → no panic/OOM; bounds from §3.2 hold.

## 7. Open questions

1. **`kind` documentation note:** add `kind` to C18's example field list / mention in C19 (one-line
   doc clarification, two-maintainer per cowork.yaml `locked_files`), or keep it spec-only and ship
   the importer with `kind = Login` defaults? Importer works either way.
2. **Provider-prefix table & entropy thresholds (§3.3):** freeze an initial known-prefix set and
   per-alphabet cutoffs — source from a current public secret-scanning ruleset and pin it; revisit
   as a small data-only PR (a Lane B sidequest). False-positive/negative budget?
3. **Command alias:** expose `vault capture <file>` as sugar for `import --format raw`, or keep the
   single `import` surface? (Current: single surface.)
4. **stdin secret hygiene:** when reading the blob from a pipe (`pbpaste | vault import --format raw -`),
   confirm the source never lands in shell history or a tmpfile; document the safe invocation.
5. **Roadmap placement:** this is a **Lane B sidequest (S-15)** that unblocks once CP-1 freezes the
   Entry model; the `kind` tag (if adopted) wants to land *in* CP-1 so the format includes it from
   the first release rather than as a later format addition.
