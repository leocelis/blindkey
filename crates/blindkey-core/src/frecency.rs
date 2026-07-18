//! UC-19 — per-entry **frecency** (frequency × recency), the usage signal that nudges the entries
//! you reach for to the top of search (P6/P7).
//!
//! Persistence (constraint **C36**): the store is serialized **into the encrypted payload**
//! (see [`crate::format::payload`]), so at rest it is ciphertext under the outer AEAD — never a
//! plaintext index file on disk. It is keyed by entry id, so the map is bounded by the entry count
//! (one record per entry); zoxide-style aging of an unbounded append-only log is therefore
//! unnecessary here — stale records are pruned when their entry is removed.
//!
//! Recency tiers follow zoxide (verified): last use < 1 h ×4, < 1 day ×2, < 1 week ×0.5, else ×0.25.

use std::collections::BTreeMap;

const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;
const WEEK: u64 = 604_800;

/// One entry's usage record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// Number of times the entry was selected/used.
    pub uses: u32,
    /// Unix seconds of the most recent use.
    pub last_used: u64,
}

/// The recency multiplier for an age in seconds (zoxide tiers).
fn recency_factor(age_secs: u64) -> f64 {
    if age_secs < HOUR {
        4.0
    } else if age_secs < DAY {
        2.0
    } else if age_secs < WEEK {
        0.5
    } else {
        0.25
    }
}

/// Bytes per serialized record: id[16] ‖ uses(u32 LE) ‖ last_used(u64 LE).
const RECORD_LEN: usize = 16 + 4 + 8;

/// A bounded map of entry-id → [`Usage`]. Deterministic iteration order (BTreeMap) so serialized
/// bytes are reproducible across saves.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FrecencyStore {
    map: BTreeMap<[u8; 16], Usage>,
}

impl FrecencyStore {
    /// An empty store (new vault, or a vault written before this feature existed).
    pub fn new() -> Self {
        FrecencyStore {
            map: BTreeMap::new(),
        }
    }

    /// Whether the store holds no usage records.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Record one use of `id` at `now` (unix seconds): bump the count, set last-used.
    pub fn record(&mut self, id: [u8; 16], now: u64) {
        let u = self.map.entry(id).or_insert(Usage {
            uses: 0,
            last_used: now,
        });
        u.uses = u.uses.saturating_add(1);
        u.last_used = now;
    }

    /// Drop the usage record for `id` (called when its entry is removed, keeping the store bounded).
    pub fn forget(&mut self, id: &[u8; 16]) {
        self.map.remove(id);
    }

    /// Frecency score for `id` at `now`: `uses × recency_factor(age)`. Zero if unseen. Clock skew
    /// (a future `last_used`) is treated as age 0 via saturating subtraction.
    pub fn score(&self, id: &[u8; 16], now: u64) -> f64 {
        match self.map.get(id) {
            Some(u) => f64::from(u.uses) * recency_factor(now.saturating_sub(u.last_used)),
            None => 0.0,
        }
    }

    /// Serialize to the payload `USAGE` record value (sorted, fixed-width records). Empty → empty.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.map.len() * RECORD_LEN);
        for (id, u) in &self.map {
            out.extend_from_slice(id);
            out.extend_from_slice(&u.uses.to_le_bytes());
            out.extend_from_slice(&u.last_used.to_le_bytes());
        }
        out
    }

    /// Parse a `USAGE` record value. A length that is not a whole number of records is rejected
    /// (a hostile/corrupt payload must never produce a panic or partial record).
    // `is_multiple_of` (the lint's suggestion) is 1.87+; the source stays 1.82-clean.
    #[allow(clippy::manual_is_multiple_of)]
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() % RECORD_LEN != 0 {
            return Err(crate::Error::BodyMalformed);
        }
        let mut map = BTreeMap::new();
        for chunk in bytes.chunks_exact(RECORD_LEN) {
            let mut id = [0u8; 16];
            id.copy_from_slice(&chunk[0..16]);
            let uses = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
            let last_used = u64::from_le_bytes(chunk[20..28].try_into().unwrap());
            map.insert(id, Usage { uses, last_used });
        }
        Ok(FrecencyStore { map })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_bumps_and_sets_recency() {
        let mut s = FrecencyStore::new();
        let id = [1u8; 16];
        s.record(id, 1_000);
        s.record(id, 2_000);
        // 2 uses, last_used recent → factor 4.0.
        assert_eq!(s.score(&id, 2_000 + 10), 8.0);
        // Same 2 uses but a week+ stale → factor 0.25.
        assert_eq!(s.score(&id, 2_000 + WEEK + 1), 0.5);
        // Unseen id → 0.
        assert_eq!(s.score(&[9u8; 16], 2_000), 0.0);
    }

    #[test]
    fn recency_tiers() {
        let mut s = FrecencyStore::new();
        let id = [2u8; 16];
        s.record(id, 0); // uses = 1
        assert_eq!(s.score(&id, HOUR - 1), 4.0);
        assert_eq!(s.score(&id, DAY - 1), 2.0);
        assert_eq!(s.score(&id, WEEK - 1), 0.5);
        assert_eq!(s.score(&id, WEEK + 1), 0.25);
    }

    #[test]
    fn serialize_round_trip_and_determinism() {
        let mut s = FrecencyStore::new();
        s.record([3u8; 16], 111);
        s.record([1u8; 16], 222);
        s.record([1u8; 16], 333);
        let bytes = s.serialize();
        assert_eq!(bytes.len(), 2 * RECORD_LEN);
        let again = FrecencyStore::parse(&bytes).unwrap();
        assert_eq!(s, again);
        // Deterministic: re-serialize is byte-identical (sorted by id).
        assert_eq!(again.serialize(), bytes);
    }

    #[test]
    fn parse_rejects_ragged_length() {
        assert!(matches!(
            FrecencyStore::parse(&[0u8; RECORD_LEN + 3]),
            Err(crate::Error::BodyMalformed)
        ));
    }

    #[test]
    fn forget_removes() {
        let mut s = FrecencyStore::new();
        s.record([4u8; 16], 1);
        s.forget(&[4u8; 16]);
        assert!(s.is_empty());
    }
}
