//! UC-19 — fuzzy keyboard-first omni-search over **non-secret entry metadata**.
//!
//! Security invariant (constraint **C35**): the searchable corpus is built from
//! `{title, username, url, tags}` **only**. Secret and secret-adjacent values — `password`,
//! `otp_secret`, protected custom fields, and the free-form `notes` field (which users paste
//! anything into) — are **never** added to the corpus and never passed to the matcher. A matcher
//! cannot leak a secret it never sees. Matching is **in-memory only**; nothing is persisted to disk
//! (**C36**) and no query/result is logged (**C37**, enforced at the call sites).
//!
//! Constant-time matching is intentionally **not** used here: every byte the matcher touches is
//! non-secret metadata the user is actively searching, so there is no secret-dependent branch to
//! protect (it would be cargo-cult — see UC-19 §3.7).
//!
//! Scoring is delegated to [`nucleo_matcher`] (the Helix matcher): fzf-quality optimal alignment
//! with consecutive-run, word-boundary, camelCase and delimiter bonuses, affine gap penalties, and
//! smart-case — kept behind the small surface in this module so the dependency is swappable.

use crate::format::entry::Entry;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};

/// Which **non-secret** metadata field a match came from. This is a deliberately **closed** set:
/// there is no variant for `password`, `otp_secret`, protected custom fields, or `notes`, because
/// secret and secret-adjacent data is never searchable (C35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Entry title.
    Title,
    /// Username.
    Username,
    /// URL.
    Url,
    /// Tag at the given index in `entry.tags`.
    Tag(usize),
}

/// Matched character positions within one field's string — drives highlighting (P10).
#[derive(Debug, Clone)]
pub struct FieldMatch {
    /// The field these positions index into.
    pub field: Field,
    /// Char indices into that field's `&str` that matched, ascending and deduplicated.
    pub positions: Vec<u32>,
}

/// One scored search result. Borrows the matched entry and carries the per-field match spans.
#[derive(Debug)]
pub struct Hit<'a> {
    /// The matched entry.
    pub entry: &'a Entry,
    /// Fuzzy score — higher is better. The weighted best over the entry's searchable fields. A
    /// matched entry always scores at least 1; an empty (browse-mode) query scores every entry 0.
    pub score: u32,
    /// Highlight spans, one per field that matched (a title hit and a tag hit can both appear).
    pub matches: Vec<FieldMatch>,
}

// Per-field weight (×100) so an equal-quality title hit edges a url hit. Tunable (IVD Rule 5);
// title is the primary handle, url the weakest (often shares tokens across many entries).
const W_TITLE: u32 = 100;
const W_USERNAME: u32 = 90;
const W_TAG: u32 = 90;
const W_URL: u32 = 85;

/// A reusable fuzzy-search engine. Holds the `nucleo` [`Matcher`] and a scratch char buffer so the
/// per-keystroke path keeps allocation low (constraint C38, < 100 ms). Construct one per search
/// session (CLI `find`, GUI omni-bar) and reuse it across keystrokes.
pub struct Engine {
    matcher: Matcher,
    hay_buf: Vec<char>,
    idx_buf: Vec<u32>,
}

// `nucleo_matcher::Matcher` is not `Debug`; provide an opaque impl (the crate denies
// `missing_debug_implementations`). The scratch buffers carry only non-secret query metadata.
impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// Build a fresh engine with the default (non-path) matcher configuration.
    pub fn new() -> Self {
        Engine {
            matcher: Matcher::new(Config::DEFAULT),
            hay_buf: Vec::new(),
            idx_buf: Vec::new(),
        }
    }

    /// Fuzzy-search `entries` by `query` over their non-secret metadata (C35), returning hits sorted
    /// best-first with a deterministic tie-break so the selection never jitters (P8). An empty or
    /// whitespace-only query returns **every** entry with score 0 (browse mode, P5) — the caller
    /// layers usage ranking on top ([`crate::vault::Vault::find`]).
    pub fn search<'a>(&mut self, entries: &'a [Entry], query: &str) -> Vec<Hit<'a>> {
        let q = query.trim();
        if q.is_empty() {
            let mut hits: Vec<Hit<'a>> = entries
                .iter()
                .map(|e| Hit {
                    entry: e,
                    score: 0,
                    matches: Vec::new(),
                })
                .collect();
            hits.sort_by(|a, b| tie_break(a.entry, b.entry));
            return hits;
        }
        let pattern = Pattern::parse(q, CaseMatching::Smart, Normalization::Smart);
        let mut hits: Vec<Hit<'a>> = Vec::new();
        for entry in entries {
            if let Some(hit) = self.score_entry(entry, &pattern) {
                hits.push(hit);
            }
        }
        hits.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| tie_break(a.entry, b.entry))
        });
        hits
    }

    /// Score one entry across its searchable fields; `None` if no field matches.
    fn score_entry<'a>(&mut self, entry: &'a Entry, pattern: &Pattern) -> Option<Hit<'a>> {
        let mut best = 0u32;
        let mut matches: Vec<FieldMatch> = Vec::new();

        self.consider(
            pattern,
            &entry.title,
            W_TITLE,
            Field::Title,
            &mut best,
            &mut matches,
        );
        self.consider(
            pattern,
            &entry.username,
            W_USERNAME,
            Field::Username,
            &mut best,
            &mut matches,
        );
        self.consider(
            pattern,
            &entry.url,
            W_URL,
            Field::Url,
            &mut best,
            &mut matches,
        );
        for (i, tag) in entry.tags.iter().enumerate() {
            self.consider(pattern, tag, W_TAG, Field::Tag(i), &mut best, &mut matches);
        }

        if matches.is_empty() {
            return None;
        }
        // A matched entry must outrank browse-mode (score 0) even if weighting rounds low.
        Some(Hit {
            entry,
            score: best.max(1),
            matches,
        })
    }

    /// Score `text` for one field; on a match, fold its weighted score into `best` and push the
    /// (sorted, deduped) highlight positions into `matches`.
    fn consider(
        &mut self,
        pattern: &Pattern,
        text: &str,
        weight: u32,
        field: Field,
        best: &mut u32,
        matches: &mut Vec<FieldMatch>,
    ) {
        if text.is_empty() {
            return;
        }
        self.idx_buf.clear();
        let hay = Utf32Str::new(text, &mut self.hay_buf);
        if let Some(raw) = pattern.indices(hay, &mut self.matcher, &mut self.idx_buf) {
            let weighted = raw.saturating_mul(weight) / 100;
            if weighted > *best {
                *best = weighted;
            }
            // nucleo appends indices unsorted/undeduped (per-atom); fix for highlighting.
            self.idx_buf.sort_unstable();
            self.idx_buf.dedup();
            if !self.idx_buf.is_empty() {
                matches.push(FieldMatch {
                    field,
                    positions: self.idx_buf.clone(),
                });
            }
        }
    }
}

/// Deterministic, total tie-break (P8 tail): title, then stable entry id. Keeps result order
/// repeatable across runs so a highlighted selection never jumps between equal-scored rows.
fn tie_break(a: &Entry, b: &Entry) -> std::cmp::Ordering {
    a.title.cmp(&b.title).then_with(|| a.id.cmp(&b.id))
}

/// How much a maxed-out usage signal can add to a fuzzy score. Small by design (P6): frecency is a
/// tie-breaker/nudge, never strong enough to lift a weak match over a clearly better one. Tunable.
const FRECENCY_WEIGHT: f64 = 8.0;

/// Re-rank `hits` by `fuzzy_score + FRECENCY_WEIGHT × normalized_frecency`, where the usage signal
/// from `frecency` is min-max normalized to `[0, 1]` over the current candidate set (P6/P7). Fuzzy
/// quality dominates; usage only breaks near-ties and orders browse mode (empty query, all fuzzy 0).
/// Filtering already happened in [`Engine::search`] — usage never resurrects a non-match.
pub fn blend_frecency<F>(hits: Vec<Hit<'_>>, frecency: F) -> Vec<Hit<'_>>
where
    F: Fn(&[u8; 16]) -> f64,
{
    if hits.len() < 2 {
        return hits;
    }
    let fr: Vec<f64> = hits.iter().map(|h| frecency(&h.entry.id)).collect();
    let max = fr.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let min = fr.iter().copied().fold(f64::INFINITY, f64::min);
    let range = max - min;
    let mut keyed: Vec<(f64, Hit<'_>)> = hits
        .into_iter()
        .enumerate()
        .map(|(i, h)| {
            let norm = if range > 0.0 {
                (fr[i] - min) / range
            } else {
                0.0
            };
            (f64::from(h.score) + FRECENCY_WEIGHT * norm, h)
        })
        .collect();
    keyed.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| tie_break(a.1.entry, b.1.entry))
    });
    keyed.into_iter().map(|(_, h)| h).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::entry::Protected;

    fn entry(title: &str, username: &str, url: &str, tags: &[&str], secret: &[u8]) -> Entry {
        Entry {
            id: {
                // Stable-but-distinct ids from the title so tie-breaks are deterministic in tests.
                let mut id = [0u8; 16];
                for (i, b) in title.bytes().take(16).enumerate() {
                    id[i] = b;
                }
                id
            },
            title: title.into(),
            username: username.into(),
            password: Protected::new(secret.to_vec()),
            url: url.into(),
            notes: String::new(),
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
            otp_secret: None,
            created_at: 0,
            modified_at: 0,
            expires_at: None,
            custom_fields: vec![],
        }
    }

    /// T1 (C35, security-critical): a query that occurs ONLY inside a secret value must NOT match.
    #[test]
    fn corpus_excludes_secret_values() {
        let mut eng = Engine::new();
        // The token "ghp" appears only in the password bytes — never in any metadata field.
        let entries = vec![entry(
            "GitHub",
            "octocat",
            "github.com",
            &["work"],
            b"ghp_supersecret",
        )];
        let hits = eng.search(&entries, "ghp_supersecret");
        assert!(
            hits.is_empty(),
            "secret value must never be searchable (C35)"
        );
        // And the same query restricted to its metadata-present prefix DOES match (sanity).
        assert_eq!(eng.search(&entries, "github").len(), 1);
    }

    /// T2: ranking quality — word-start beats mid-word; exact/prefix beats interior.
    #[test]
    fn ranking_prefers_word_start_and_prefix() {
        let mut eng = Engine::new();
        let entries = vec![
            entry("GitHub", "", "", &[], b"x"),
            entry("rough-draft", "", "", &[], b"x"), // contains g,h via "rouGH"? no — ensure non-prefix
            entry("Sourcegraph", "", "", &[], b"x"),
        ];
        let hits = eng.search(&entries, "gh");
        assert!(!hits.is_empty());
        assert_eq!(
            hits[0].entry.title, "GitHub",
            "prefix/word-start should rank first"
        );
    }

    /// T2 cont.: smart-case — lowercase query is case-insensitive; results carry highlight spans.
    #[test]
    fn smart_case_and_highlight_spans() {
        let mut eng = Engine::new();
        let entries = vec![entry(
            "GitHub",
            "octocat",
            "https://github.com",
            &["dev"],
            b"x",
        )];
        let hits = eng.search(&entries, "git");
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0]
                .matches
                .iter()
                .any(|m| matches!(m.field, Field::Title) && !m.positions.is_empty()),
            "a title match should carry highlight positions"
        );
    }

    /// Username and tags are searchable metadata (C35 allow-list), notes is not.
    #[test]
    fn username_and_tag_match_but_notes_do_not() {
        let mut eng = Engine::new();
        let mut e = entry("Acme", "alice", "", &["banking", "prod"], b"x");
        e.notes = "recovery phrase: zphr".into();
        let entries = vec![e];
        assert_eq!(
            eng.search(&entries, "alice").len(),
            1,
            "username searchable"
        );
        assert_eq!(eng.search(&entries, "banking").len(), 1, "tag searchable");
        assert!(
            eng.search(&entries, "zphr").is_empty(),
            "notes must not be searchable"
        );
    }

    /// T4 (C38): a full-corpus fuzzy match for short queries stays under the 100 ms budget at
    /// N = 2000 — even in an unoptimized debug build, where this runs far slower than release.
    #[test]
    fn latency_under_budget_at_scale() {
        let mut entries = Vec::with_capacity(2000);
        for i in 0..2000u32 {
            entries.push(entry(
                &format!("service-{i}-github-api"),
                &format!("user{i}@example.com"),
                &format!("https://host-{i}.example.com/login"),
                &["work", "cloud", "prod"],
                b"secret-value",
            ));
        }
        let mut eng = Engine::new();
        for q in [
            "g", "gh", "git", "githu", "service", "user12", "examp", "cloud",
        ] {
            let t = std::time::Instant::now();
            let hits = eng.search(&entries, q);
            let elapsed = t.elapsed();
            assert!(
                elapsed.as_millis() < 100,
                "query {q:?} took {elapsed:?} (> 100 ms budget, C38) at N={}",
                entries.len()
            );
            assert!(
                !hits.is_empty(),
                "query {q:?} should match the synthetic corpus"
            );
        }
    }

    /// Empty query is browse mode: every entry, deterministic order.
    #[test]
    fn empty_query_lists_all_deterministically() {
        let mut eng = Engine::new();
        let entries = vec![
            entry("beta", "", "", &[], b"x"),
            entry("alpha", "", "", &[], b"x"),
        ];
        let a = eng.search(&entries, "");
        let b = eng.search(&entries, "   ");
        assert_eq!(a.len(), 2);
        assert_eq!(
            a[0].entry.title, "alpha",
            "browse order is deterministic (sorted)"
        );
        assert_eq!(
            a.iter().map(|h| h.entry.title.as_str()).collect::<Vec<_>>(),
            b.iter().map(|h| h.entry.title.as_str()).collect::<Vec<_>>(),
        );
    }
}
