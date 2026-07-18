//! Built-in diceware wordlist for passphrase generation (constraint C26, diceware mode).
//!
//! This is a **256-word** list (exactly `2^8`, so each word contributes a clean **8 bits** of
//! entropy). It is deliberately small and hand-curated so it can ship in the binary and be verified
//! in a test (no duplicates, all lowercase `[a-z]{3,8}`). For the strongest passphrases use the
//! **EFF large wordlist** (7776 words, ~12.9 bits/word) via `gen --words N --wordlist <file>`:
//! download it from <https://www.eff.org/dice> (EFF, CC-BY 3.0).
//!
//! Words were chosen to be short, common, and unambiguous; the integrity test below is the source of
//! truth for the list's size and uniqueness.

/// The built-in 256-word diceware list (8 bits/word). See module docs.
pub const BUILTIN: &[&str] = &[
    "able", "acid", "acorn", "actor", "adapt", "afar", "agent", "agree", "ahead", "aim", "air",
    "alarm", "album", "alert", "alien", "alley", "almond", "aloft", "amber", "amend", "amino",
    "ample", "angel", "anger", "angle", "ankle", "apex", "apple", "april", "apron", "arc", "arena",
    "argue", "arise", "armor", "army", "aroma", "array", "arrow", "ash", "aside", "asset", "atlas",
    "atom", "attic", "audio", "audit", "aunt", "auto", "avoid", "awake", "award", "axis", "bacon",
    "badge", "bagel", "baker", "balm", "banjo", "barn", "basil", "basin", "batch", "beach", "beam",
    "bean", "bear", "beef", "begin", "bell", "belt", "bench", "berry", "bike", "birch", "bird",
    "blade", "blank", "blaze", "blend", "blink", "block", "bloom", "blue", "blush", "board",
    "boat", "bonus", "book", "boost", "booth", "boots", "born", "boss", "botany", "bowl", "brave",
    "bread", "brick", "brief", "bring", "broad", "broom", "brown", "brush", "bubble", "buddy",
    "buffet", "bugle", "build", "bulb", "bundle", "bunny", "bush", "cabin", "cable", "cacao",
    "cactus", "cadet", "cage", "cake", "camel", "candy", "canoe", "canyon", "cape", "card",
    "cargo", "carol", "carry", "cart", "carve", "cash", "cause", "cedar", "cello", "chalk",
    "charm", "chart", "chase", "cheek", "chef", "cherry", "chess", "chest", "chime", "city",
    "civic", "clamp", "clash", "clay", "clean", "clear", "cliff", "climb", "cloak", "clock",
    "cloud", "clove", "clown", "coach", "coast", "cobra", "cocoa", "coin", "comet", "coral",
    "couch", "cough", "court", "cover", "craft", "crane", "crate", "cream", "crew", "crisp",
    "crop", "cross", "crowd", "crown", "cube", "curl", "curve", "cycle", "daisy", "dance", "dawn",
    "deck", "deer", "delta", "denim", "depth", "diary", "dice", "diet", "disk", "ditch", "dock",
    "dome", "donor", "dough", "dove", "draft", "drama", "dream", "dress", "drift", "drill",
    "drink", "drive", "drum", "dusk", "eagle", "early", "earth", "easel", "east", "echo", "edge",
    "eel", "elbow", "elder", "elf", "elite", "elm", "ember", "empty", "enter", "envoy", "epoch",
    "equal", "error", "essay", "ether", "ethic", "even", "event", "every", "exact", "exam",
    "exile", "exit", "extra", "fable", "fact", "fade", "fairy", "faith", "fame", "fancy", "fang",
    "farm", "fault", "fawn", "feast",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn builtin_is_exactly_256_clean_unique_words() {
        assert_eq!(
            BUILTIN.len(),
            256,
            "the built-in list must be exactly 2^8 words"
        );
        let set: HashSet<&&str> = BUILTIN.iter().collect();
        assert_eq!(
            set.len(),
            BUILTIN.len(),
            "the built-in list must have no duplicates"
        );
        for w in BUILTIN {
            let n = w.len();
            assert!((3..=8).contains(&n), "word {w:?} must be 3–8 chars");
            assert!(
                w.bytes().all(|b| b.is_ascii_lowercase()),
                "word {w:?} must be lowercase a–z"
            );
        }
    }
}
