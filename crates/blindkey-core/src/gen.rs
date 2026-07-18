//! CSPRNG password generation (constraint C26).
//!
//! Passwords are drawn from the OS CSPRNG (`getrandom`) using **rejection sampling**, never modulo
//! reduction — modulo would bias toward the lower-indexed characters and silently lower the entropy.
//! The only provable password strength is uniform CSPRNG output with a documented bit count, which
//! is why human- and LLM-chosen passwords are not an input here (research: AI-assisted cracking).
//!
//! v1 ships the character-set modes; the EFF-wordlist diceware mode is added when the wordlist data
//! is bundled.

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Alphanumeric set, 62 characters (`A–Z a–z 0–9`).
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Printable-ASCII set, 94 characters (`!`..=`~`).
const ASCII: &[u8] = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/// Which character set to draw from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// `A–Z a–z 0–9` (62 chars, ~5.95 bits/char).
    Alnum,
    /// Printable ASCII (94 chars, ~6.55 bits/char).
    Ascii,
}

impl Charset {
    fn alphabet(self) -> &'static [u8] {
        match self {
            Charset::Alnum => ALNUM,
            Charset::Ascii => ASCII,
        }
    }
}

/// Shannon entropy of a generated password of `length` chars from `charset`, in bits.
pub fn entropy_bits(charset: Charset, length: usize) -> f64 {
    (charset.alphabet().len() as f64).log2() * length as f64
}

/// Generate a password of `length` characters drawn uniformly from `charset` (constraint C26).
///
/// Uses rejection sampling: a random byte is rejected unless it falls in the largest multiple of the
/// alphabet length ≤ 256, so `byte % len` is unbiased. Returns a zeroizing string.
pub fn password(charset: Charset, length: usize) -> Result<Zeroizing<String>> {
    let alphabet = charset.alphabet();
    let n = alphabet.len();
    // Largest multiple of n that fits in a byte; bytes >= this are rejected (no modulo bias).
    let limit = (256 / n) * n;

    let mut out = Zeroizing::new(String::with_capacity(length));
    let mut byte = [0u8; 1];
    while out.len() < length {
        getrandom::getrandom(&mut byte).map_err(|_| Error::Crypto)?;
        let b = byte[0] as usize;
        if b < limit {
            out.push(alphabet[b % n] as char);
        }
        // else: reject and resample
    }
    Ok(out)
}

/// Generate a diceware passphrase of `words` words drawn uniformly from `wordlist`, joined by `-`.
///
/// Uses the same unbiased rejection sampling as [`password`], but over a `u32` index into the list,
/// so each word is a uniform CSPRNG choice (constraint C26 — no human/LLM word selection).
pub fn passphrase(words: usize, wordlist: &[&str]) -> Result<Zeroizing<String>> {
    let n = wordlist.len();
    if n < 2 {
        return Err(Error::Crypto);
    }
    let n32 = n as u32;
    // Largest multiple of n that fits in a u32; values >= this are rejected (no modulo bias).
    let limit = (u32::MAX / n32) * n32;

    let mut out = Zeroizing::new(String::new());
    let mut produced = 0usize;
    let mut buf = [0u8; 4];
    while produced < words {
        getrandom::getrandom(&mut buf).map_err(|_| Error::Crypto)?;
        let r = u32::from_le_bytes(buf);
        if r < limit {
            if produced > 0 {
                out.push('-');
            }
            out.push_str(wordlist[(r % n32) as usize]);
            produced += 1;
        }
    }
    Ok(out)
}

/// Entropy in bits of a `words`-word passphrase drawn from a list of `list_len` words.
pub fn passphrase_entropy_bits(words: usize, list_len: usize) -> f64 {
    if list_len < 2 {
        return 0.0;
    }
    (list_len as f64).log2() * words as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_alphabet() {
        for cs in [Charset::Alnum, Charset::Ascii] {
            let p = password(cs, 32).unwrap();
            assert_eq!(p.chars().count(), 32);
            let alpha = cs.alphabet();
            assert!(p.bytes().all(|b| alpha.contains(&b)));
        }
    }

    #[test]
    fn entropy_is_documented() {
        // 20 alnum chars ≈ 119 bits; 20 ascii ≈ 131 bits.
        assert!((entropy_bits(Charset::Alnum, 20) - 119.08).abs() < 0.5);
        assert!((entropy_bits(Charset::Ascii, 20) - 131.0).abs() < 0.5);
    }

    #[test]
    fn distribution_covers_the_alphabet_without_obvious_bias() {
        // Generate a large sample and assert every character appears, and no character is wildly
        // over-represented (a crude modulo-bias smoke test — full chi-square is a heavier test).
        let alpha = Charset::Ascii.alphabet();
        let n = alpha.len();
        let total = 200 * n;
        let p = password(Charset::Ascii, total).unwrap();
        let mut counts = vec![0usize; n];
        for b in p.bytes() {
            counts[alpha.iter().position(|&c| c == b).unwrap()] += 1;
        }
        assert!(counts.iter().all(|&c| c > 0), "every char must appear");
        let expected = total as f64 / n as f64;
        assert!(
            counts.iter().all(|&c| (c as f64) < expected * 1.8),
            "no char should be ~2x over-represented (would signal modulo bias)"
        );
    }

    #[test]
    fn two_generations_differ() {
        assert_ne!(
            *password(Charset::Ascii, 24).unwrap(),
            *password(Charset::Ascii, 24).unwrap()
        );
    }

    #[test]
    fn passphrase_shape_and_entropy() {
        let list = crate::wordlist::BUILTIN;
        let pp = passphrase(6, list).unwrap();
        // 6 words → 5 separators; every chunk is a word from the list.
        let parts: Vec<&str> = pp.split('-').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts.iter().all(|w| list.contains(w)));
        // 256-word list = 8 bits/word → 48 bits for 6 words.
        assert!((passphrase_entropy_bits(6, list.len()) - 48.0).abs() < 0.01);
    }

    #[test]
    fn passphrases_differ_and_reject_tiny_lists() {
        let list = crate::wordlist::BUILTIN;
        assert_ne!(*passphrase(8, list).unwrap(), *passphrase(8, list).unwrap());
        assert!(passphrase(4, &["only"]).is_err()); // list too small
    }
}
