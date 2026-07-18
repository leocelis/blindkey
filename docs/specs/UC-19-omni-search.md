# UC-19 — Fuzzy Keyboard-First Omni-Search

> **Tech spec** · Implemented · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-19 · **New constraints:** C35–C39; touches C12, C13, C19, C25, C27, C33
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Make every secret reachable in **one keystroke-fast pass**: open search, start typing, the right
entry rises to the top, press Enter, the password is on the clipboard. Fuzzy (typo- and
abbreviation-tolerant), keyboard-only, and instant — over the entry set already decrypted into
RAM on unlock ([UC-03](UC-03-store-secret.md) / [vault.rs](../../crates/blindkey-core/src/vault.rs)).
This is the "omni search experience that finds in the keys" — the friendly half of the `keys.txt`
use case, built so the security half costs nothing.

The matcher sees **metadata only** — `title`, `username`, `url`, `tags`. Secret values are never
added to the searchable corpus and never passed to the matcher (C35). This upgrades the current
substring `Blindkey::search` ([vault.rs#L381](../../crates/blindkey-core/src/vault.rs#L381), title+tags,
`contains`) to ranked fuzzy matching shared by the CLI and GUI.

Goals:

1. `blindkey find` (CLI/TUI) and a GUI omni-bar: type → ranked fuzzy results → Enter copies the
   password via the existing model-blind clipboard path (C13/C27/C33).
2. Fuzzy scoring with the proven signal hierarchy (consecutive > word-boundary > camelCase/
   delimiter > affine gaps > exact/prefix), smart-case, match-index highlighting.
3. Usage-aware ranking (frecency) as a tie-breaker/nudge, never overpowering match quality.
4. Keystroke→result < 100 ms for N ≤ 2000, synchronous, no debounce (C38).
5. No persisted search index (C36); zeroizing query buffer, no query/result logging (C37).

Out of scope: matching secret values or notes; server/remote search; an on-disk index; regex
search syntax (may come later as an opt-in `/regex` mode); cross-vault search.

## 2. Prior art

### 2.1 Open source

| Source | What we take | License |
|---|---|---|
| **fzf** (`src/algo/algo.go`) | The optimal V2 (Smith-Waterman-style) scoring model and its exact bonuses: match 16, gap-open −3 / extend −1 (affine), boundary 8–10, camelCase 7, consecutive 4, **first-char boundary bonus ×2**. Match-index highlighting (`hl`/`hl+`). | MIT |
| **fzy** (`ALGORITHM.md`) | The clearest rationale for the affine-gap dual-matrix and the consecutive-match correction; signal ordering consecutive>slash>word>capital>dot. | MIT |
| **nucleo-matcher** (Helix) | **Chosen matcher.** fzf-quality optimal scoring, explicit Unicode normalization + smart-case (`Normalization::Smart`, `CaseMatching`), `fuzzy_indices` for highlighting, minimal pure-offline deps (`memchr`). | MPL-2.0 |
| **fuzzy-matcher** (skim `SkimMatcherV2`) | MIT fallback if a weak-copyleft dep is unacceptable — near-identical capability, lighter Unicode story. | MIT |
| **zoxide / rupa z** | Frecency: frequency × recency tiers (<1h ×4, <1d ×2, <1wk ×0.5, else ×0.25); aging at a cap, drop score <1. | MIT |
| **1Password Quick Access** | Copy-on-Enter UX: Enter copies password, a modifier copies username. | — |

> nucleo-matcher is MPL-2.0 (file-level copyleft); as an **unmodified dependency** it imposes no
> obligation on our application code. If the project later wants a fully permissive tree, swap to
> `fuzzy-matcher` (MIT) — the matcher is isolated behind our own trait (§3.3) so this is a one-file
> change.

### 2.2 Academic / standards

- **Smith & Waterman (1981)** local alignment + **Gotoh (1982)** affine gap — the DP behind
  optimal fuzzy scoring.
- **Navarro (2001)**, *A guided tour to approximate string matching* — online-scan vs. indexed
  trade-off; justifies a linear scan (no index) for a small corpus.
- **Miller (1968)** / **Nielsen** response-time limits — 0.1 s = instantaneous; our < 100 ms budget.
- **Burkhard & Keller (1973)** BK-trees, n-gram indexing — surveyed and **rejected** at this scale
  (§4): constant factors invert below ~10⁴ entries, and a persisted index is a disk side-channel.

Full citations are in the references listed in §2 above (Navarro, Miller, BK-trees survey).

## 3. Proposed design

### 3.1 Matcher abstraction (`blindkey-core::search`)

A thin trait isolates the dependency so the algorithm choice is swappable and unit-testable:

```rust
/// Scored, highlightable fuzzy match over non-secret metadata (C35).
pub struct Hit<'a> { pub entry: &'a Entry, pub score: i64, pub indices: Vec<MatchSpan> }
pub struct MatchSpan { pub field: Field, pub ranges: Vec<(u32, u32)> } // for highlighting
pub enum Field { Title, Username, Url, Tag }

pub trait FuzzyMatcher {
    /// Score `query` against one metadata string; None = no match. Returns char-index ranges.
    fn score(&mut self, query: &str, candidate: &str) -> Option<(i64, Vec<(u32, u32)>)>;
}
```

Default impl wraps `nucleo_matcher::Matcher` with one reused instance + pre-converted `Utf32Str`
haystacks (the documented hot-loop rule). The corpus builder (§3.2) and ranker (§3.4) are
matcher-agnostic.

### 3.2 Corpus — metadata only (C35)

On unlock, build a per-entry haystack from `{title, username, url, tags}` **only**. Secret,
password, and notes fields are never read into the corpus. The corpus holds `&Entry` plus the
small set of searchable strings; it is rebuilt in memory on add/edit/remove. No bytes are written
to disk (C36).

> Security invariant, asserted in code at the corpus-build site: the field list is a closed enum
> (`Field`) with no secret variant; a test (§6 T1) proves a query that occurs **only** inside a
> secret value yields zero hits.

### 3.3 Scoring (per candidate string)

Delegated to the matcher, preserving the fzf/fzy signal hierarchy (highest→lowest): consecutive
run → word-boundary (doubled on the first matched char) → camelCase / delimiter (`/ _ - . :`) →
affine gap (open ≫ extend; leading/trailing cheaper than inner) → exact/prefix boost. **Smart-case**
(insensitive until the query has an uppercase char) comes from `CaseMatching::Smart`. An entry's
field scores are combined by **max** (best-matching field wins) with a small per-field weight so a
title hit edges an equal url hit: `title ×1.0, username ×0.9, url ×0.85, tag ×0.9` (tunable;
verified empirically in phase 5 per IVD Rule 5).

### 3.4 Ranking — fuzzy first, frecency as nudge (C-none; UX)

Two stages:

1. **Filter:** keep entries with a fuzzy hit. Empty query → all entries (C-UX, P5).
2. **Rank:** `final = fuzzy_score + w · normalized_frecency`, where `normalized_frecency` is
   min-max scaled to `[0,1]` over the current candidate set and `w` is small enough that fuzzy tier
   order is never inverted (start `w = 8`, i.e. half a single match unit; tune in phase 5). Usage
   never resurrects a non-match.

**Frecency store:** per-entry `{ uses: u32, last_used: u64 }`, bumped when an entry is selected
(Enter/copy). `recency_factor` = zoxide tiers (<1h ×4, <1d ×2, <1wk ×0.5, else ×0.25); aging when
the summed score passes a cap, drop < 1. Stored as a small encrypted side-record inside the vault
payload (NOT a plaintext file — C36 forbids a plaintext index; this is ciphertext within the
existing `.vlt`). **Open question Q1:** confirm placement (payload field vs. a dedicated stanza)
during spec review.

**Tie-break cascade (total order):** frecency → most-recent → frequency → shorter candidate →
lexicographic — stable, non-jittering selection (P8).

### 3.5 CLI surface

```
blindkey find QUERY            # copy the BEST fuzzy match's password to the clipboard (model-blind)
blindkey find QUERY --stdout   # non-interactive: print ranked titles (no secret), scriptable
blindkey find                  # (no query) browse all entries, most-used first
```

- **Default (copy):** rank by `Blindkey::find`, copy the top hit's password via the existing
  clipboard path (auto-clear, C13/C27/C33 — C39), print the matched title + the next few matches to
  stderr, and `record_use` the chosen entry so frecency learns (persisted on save). This is the
  fast keyboard flow on the CLI: `blindkey find githb` → password on the clipboard.
- **`--stdout`:** print ranked titles only (no secret, no clipboard, no state change) — scriptable.
- The query is never echoed back or logged, including on a miss (C37).
- The existing `blindkey ls --search` stays the literal substring lister (scripts depend on it); `find`
  is the ranked fuzzy surface. **(Q2 resolved: `ls --search` stays literal.)**

> **Refinement (IVD Rule 5, implemented):** the original draft bundled a full interactive ratatui
> picker into `blindkey find`. Shipped instead: the non-interactive resolver above (fully CI-testable,
> no TTY dependency, no TUI stack pulled into the one-shot CLI). The **rich interactive type-to-
> filter experience lands in the GUI omni-bar (§3.6)**; an interactive terminal picker is a clean
> follow-up in the existing `blindkey-tui` crate (which already owns the ratatui + alt-screen secret-
> hygiene stack), not the CLI binary.

### 3.6 GUI surface

An always-available omni-bar (focus on `/` or Ctrl-K) above the entry list. Synchronous filter on
every keystroke (no debounce, C38); highlight match spans; arrow/Ctrl-N nav; Enter copies password.
Reuses the GUI's existing clipboard + auto-lock wiring.

### 3.7 Security properties

- **C35** corpus excludes secrets — closed `Field` enum, asserted + tested.
- **C36** no on-disk index; frecency lives as ciphertext inside the `.vlt`, not a plaintext sidecar.
- **C37** the live query is a `Zeroizing<String>` (or the project secret-string type), zeroized on
  clear/dismiss/lock; no `eprintln!`/log carries query, matched title, count, or selection.
- **C39** selection delivers via the model-blind clipboard helper (C13/C27/C33); never a default
  stdout write. `--stdout` stays an explicit, warned, titles-only opt-in.
- **Constant-time is intentionally NOT used** (P16): matching is over non-secret metadata, so there
  is no secret-dependent branch to protect; a code comment at the match site states this so no
  reviewer "hardens" it into a bug.

## 4. Alternatives considered

- **On-disk inverted/trigram/BK-tree index** — rejected (§2.2): at ≤ ~10³–10⁴ short in-RAM strings a
  linear scan is sub-ms (Navarro online regime); an index adds rebuild cost, inverts constant
  factors, and creates a plaintext-shaped disk side-channel over sensitive metadata (C36).
- **Plain substring (status quo)** — kept for `ls --search`, insufficient for "omni" (no typo
  tolerance, no abbreviation matching, no ranking).
- **Debounced async search** — rejected (C38): unnecessary for in-RAM matching under one frame; only
  adds latency.
- **Hand-rolled scorer** — rejected: re-deriving fzf's tuned constants is error-prone; a vetted,
  offline, permissive crate behind our trait is safer and swappable.

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C35** (corpus excludes secrets) | Closed `Field` enum (Title/Username/Url/Tag); secret/notes never read into corpus; test T1. |
| **C36** (no on-disk index) | In-RAM match only; frecency is ciphertext inside `.vlt`; test T5 (data dir unchanged). |
| **C37** (zeroizing query, no logs) | `Zeroizing` query, cleared on dismiss/lock; no log path carries query/result; test T6. |
| **C38** (< 100 ms, no debounce) | Synchronous linear scan + reused matcher; bench T4 at N=2000. |
| **C39** (model-blind delivery) | Selection → existing clipboard helper; `--stdout` titles-only opt-in; test T3. |
| C12/C19/C25 | Query + corpus use the hardened in-memory types; nothing new persisted. |
| C13/C27/C33 | Reuses the clipboard auto-clear/transient path unchanged. |

## 6. Test plan

- **T1 (C35, security-critical):** entry whose query substring exists ONLY in its secret value →
  zero hits. Also: corpus builder never touches the secret field (type-level + unit).
- **T2 (ranking quality):** golden cases — `gh`→GitHub#1; exact title > prefix > interior;
  consecutive > gapped for same chars; smart-case (`git`↔GitHub, `GH` case-sensitive).
- **T3 (C39):** `find` selection routes through the clipboard helper, not stdout; `--stdout` prints
  titles only, no secret.
- **T4 (C38):** bench/`#[test]` timing — full-corpus match for 1–8 char queries at N=2000 under a
  generous ceiling (assert < 100 ms; expect ≪).
- **T5 (C36):** snapshot the data dir before/after a search session → byte-identical; no index file.
- **T6 (C37):** query type is zeroizing; lock clears it; grep the crate for log macros near the
  search path → none carry query/result.
- **T7 (frecency):** zoxide tiers + aging + tie-break determinism (stable order across runs).

## 7. Open questions

- **Q1:** frecency store placement — a `payload` field vs. a dedicated encrypted stanza; migration
  for existing vaults (default to zero usage).
- **Q2:** should `ls --search` re-route through the fuzzy ranker, or stay literal substring for
  script stability? (Leaning: stay literal; `find` is the fuzzy surface.)
- **Q3:** matcher license posture — ship with nucleo-matcher (MPL-2.0) or default to fuzzy-matcher
  (MIT)? Trait isolation makes it a one-file decision; recommend nucleo for Unicode quality.
- **Q4:** GUI omni-bar — modal palette (Ctrl-K overlay) vs. always-visible filter box above the list.
