//! Fuzzy search result cache (UC-20 / C42) — skip redundant `Vault::find` calls on incidental repaints.

/// Tracks whether `display_items` is still valid for the current query and vault generation.
#[derive(Default)]
pub struct SearchCache {
    query: String,
    entries_generation: u64,
    total_entries: usize,
}

impl SearchCache {
    /// Drop cache metadata (e.g. on lock — C37 query wipe).
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Whether `display_items` from the last compute is still valid.
    pub fn is_warm_for(&self, query: &str, entries_generation: u64, total_entries: usize) -> bool {
        self.query == query
            && self.entries_generation == entries_generation
            && self.total_entries == total_entries
    }

    /// Mark the cache warm after fresh `find` results are stored in `display_items`.
    pub fn mark(&mut self, query: &str, entries_generation: u64, total_entries: usize) {
        self.query = query.to_string();
        self.entries_generation = entries_generation;
        self.total_entries = total_entries;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warm_after_mark() {
        let mut cache = SearchCache::default();
        cache.mark("gh", 1, 10);
        assert!(cache.is_warm_for("gh", 1, 10));
        assert!(!cache.is_warm_for("gh", 2, 10));
        assert!(!cache.is_warm_for("git", 1, 10));
    }

    #[test]
    fn clear_resets_warmth() {
        let mut cache = SearchCache::default();
        cache.mark("q", 1, 1);
        cache.clear();
        assert!(!cache.is_warm_for("q", 1, 1));
    }
}
