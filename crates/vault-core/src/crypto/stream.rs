//! XChaCha20-Poly1305 STREAM payload encryption (constraint C1).
//!
//! The payload is split into 64 KiB chunks, each independently AEAD-sealed with ChaCha20-Poly1305.
//! The per-chunk nonce is `11-byte big-endian counter || 1-byte final-chunk marker` (0x01 on the
//! last chunk, 0x00 otherwise) — the age STREAM construction. The extended-nonce ("X") security
//! comes from the per-save random `nonce_prefix`, which is the HKDF **salt** that derives the
//! payload key — not from a 24-byte AEAD nonce:
//!
//! ```text
//! payload_key = HKDF-SHA-256(ikm = data_key, salt = nonce_prefix, info = "vault-payload-v1")
//! ```
//!
//! A fresh `nonce_prefix` per body-writing save (C1/C8) gives every save an independent keystream,
//! so a history-keeping backend cannot XOR two versions to recover plaintext diffs. **No plaintext
//! byte is released before its chunk's Poly1305 tag verifies**: each chunk is decrypted (and
//! authenticated) in full before its bytes are appended, and the function returns `Err` — dropping
//! the partial output — on any tag failure (constraint C1).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use zeroize::Zeroizing;

use super::{hkdf32, STREAM_CHUNK_SIZE};
use crate::{Error, Result};

const PAYLOAD_INFO: &[u8] = b"vault-payload-v1";
const TAG_LEN: usize = 16;

/// Derive the payload key (constraint C1). Exposed for the C1 derivation test.
pub fn payload_key(data_key: &[u8; 32], nonce_prefix: &[u8; 16]) -> [u8; 32] {
    hkdf32(data_key, nonce_prefix, PAYLOAD_INFO)
}

/// Per-chunk nonce: 3 zero bytes ‖ 8-byte big-endian counter (= 11-byte counter) ‖ 1-byte marker.
fn chunk_nonce(counter: u64, is_last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = if is_last { 0x01 } else { 0x00 };
    n
}

/// Encrypt `plaintext` as a STREAM of sealed 64 KiB chunks (constraint C1).
pub fn encrypt(data_key: &[u8; 32], nonce_prefix: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = Zeroizing::new(payload_key(data_key, nonce_prefix));
    let cipher = ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Crypto)?;

    // Chunk the plaintext; append a final empty chunk when the length is empty or an exact multiple
    // of the chunk size, so the last-chunk marker is always present (age behavior — kills truncation
    // ambiguity).
    let mut chunks: Vec<&[u8]> = plaintext.chunks(STREAM_CHUNK_SIZE).collect();
    // `% == 0` (not `u64::is_multiple_of`, which is newer than our 1.82 source floor — the core
    // stays buildable on 1.82 even though the workspace toolchain is now 1.96).
    #[allow(clippy::manual_is_multiple_of)]
    if plaintext.is_empty() || plaintext.len() % STREAM_CHUNK_SIZE == 0 {
        chunks.push(&[]);
    }

    let last = chunks.len() - 1;
    let mut out = Vec::with_capacity(plaintext.len() + chunks.len() * TAG_LEN);
    for (i, chunk) in chunks.iter().enumerate() {
        let nonce = chunk_nonce(i as u64, i == last);
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), *chunk)
            .map_err(|_| Error::Crypto)?;
        out.extend_from_slice(&sealed);
    }
    Ok(out)
}

/// Decrypt a STREAM produced by [`encrypt`] (constraint C1).
///
/// Each chunk's tag is verified before its bytes are accepted; any failure aborts with
/// [`Error::BodyAuth`] and no partial plaintext is returned. Output is zeroized on drop.
///
/// Prefer [`decrypt_streaming`] when opening a vault — it avoids retaining the full plaintext
/// buffer (security-gap review P3 / C19 in-memory posture).
pub fn decrypt(
    data_key: &[u8; 32],
    nonce_prefix: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut dec = StreamDecryptor::new(data_key, nonce_prefix, ciphertext)?;
    let mut out = Zeroizing::new(Vec::new());
    while let Some(chunk) = dec.next_plaintext_chunk()? {
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Incremental STREAM decryptor — yields verified plaintext chunks without building one buffer.
pub struct StreamDecryptor<'a> {
    cipher: chacha20poly1305::ChaCha20Poly1305,
    rest: &'a [u8],
    counter: u64,
}

impl std::fmt::Debug for StreamDecryptor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamDecryptor")
            .field("rest_len", &self.rest.len())
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl<'a> StreamDecryptor<'a> {
    /// Begin decrypting `ciphertext` with the payload key derived from `data_key` + `nonce_prefix`.
    pub fn new(data_key: &[u8; 32], nonce_prefix: &[u8; 16], ciphertext: &'a [u8]) -> Result<Self> {
        let key = Zeroizing::new(payload_key(data_key, nonce_prefix));
        let cipher = ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Crypto)?;
        Ok(StreamDecryptor {
            cipher,
            rest: ciphertext,
            counter: 0,
        })
    }

    /// Next verified plaintext chunk, or `None` when finished.
    pub fn next_plaintext_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        if self.rest.len() < TAG_LEN {
            return Err(Error::BodyMalformed);
        }
        let take = self.rest.len().min(sealed_full());
        let is_last = take == self.rest.len();
        let nonce = chunk_nonce(self.counter, is_last);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), &self.rest[..take])
            .map_err(|_| Error::BodyAuth)?;
        self.rest = &self.rest[take..];
        if !is_last {
            self.counter = self.counter.checked_add(1).ok_or(Error::BodyMalformed)?;
        }
        Ok(Some(Zeroizing::new(pt)))
    }
}

fn sealed_full() -> usize {
    STREAM_CHUNK_SIZE + TAG_LEN
}

/// Decrypt the outer STREAM and parse the payload incrementally (security-gap review P3).
pub fn decrypt_streaming<F>(
    data_key: &[u8; 32],
    nonce_prefix: &[u8; 16],
    ciphertext: &[u8],
    mut on_chunk: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut dec = StreamDecryptor::new(data_key, nonce_prefix, ciphertext)?;
    while let Some(chunk) = dec.next_plaintext_chunk()? {
        on_chunk(&chunk)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DK: [u8; 32] = [0x11; 32];
    const NP: [u8; 16] = [0x22; 16];

    fn round_trip(len: usize) {
        let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let ct = encrypt(&DK, &NP, &pt).unwrap();
        assert_eq!(&decrypt(&DK, &NP, &ct).unwrap()[..], &pt[..], "len={len}");
    }

    #[test]
    fn round_trips_across_chunk_boundaries() {
        for len in [
            0,
            1,
            100,
            STREAM_CHUNK_SIZE - 1,
            STREAM_CHUNK_SIZE,
            STREAM_CHUNK_SIZE + 1,
        ] {
            round_trip(len);
        }
        round_trip(3 * STREAM_CHUNK_SIZE + 5);
    }

    #[test]
    fn three_chunks_exact() {
        // C1 test (a): plaintext spanning [64KiB, 64KiB, 1].
        let pt: Vec<u8> = (0..2 * STREAM_CHUNK_SIZE + 1)
            .map(|i| (i % 256) as u8)
            .collect();
        let ct = encrypt(&DK, &NP, &pt).unwrap();
        assert_eq!(&decrypt(&DK, &NP, &ct).unwrap()[..], &pt[..]);
    }

    #[test]
    fn swapped_chunks_fail_tag() {
        // C1 test (b): swap chunk 0 and chunk 1 → counter/nonce mismatch → BodyAuth.
        let pt = vec![7u8; 2 * STREAM_CHUNK_SIZE + 1];
        let mut ct = encrypt(&DK, &NP, &pt).unwrap();
        let block = STREAM_CHUNK_SIZE + TAG_LEN;
        let (a, b): (Vec<u8>, Vec<u8>) = (ct[..block].into(), ct[block..2 * block].into());
        ct[..block].copy_from_slice(&b);
        ct[block..2 * block].copy_from_slice(&a);
        assert!(matches!(decrypt(&DK, &NP, &ct), Err(Error::BodyAuth)));
    }

    #[test]
    fn truncation_before_final_marker_fails() {
        // C1 test (c): drop the final chunk → the new last chunk was sealed non-last → BodyAuth.
        let pt = vec![3u8; 2 * STREAM_CHUNK_SIZE + 1];
        let ct = encrypt(&DK, &NP, &pt).unwrap();
        let block = STREAM_CHUNK_SIZE + TAG_LEN;
        let truncated = &ct[..2 * block]; // drop the 3rd (final) chunk
        assert!(matches!(decrypt(&DK, &NP, truncated), Err(Error::BodyAuth)));
    }

    #[test]
    fn flipped_byte_fails_tag() {
        let pt = vec![1u8; 100];
        let mut ct = encrypt(&DK, &NP, &pt).unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(decrypt(&DK, &NP, &ct), Err(Error::BodyAuth)));
    }

    #[test]
    fn nonce_prefix_changes_keystream_and_key() {
        // C1 cross-save independence + payload-key derivation.
        assert_eq!(payload_key(&DK, &NP), payload_key(&DK, &NP));
        assert_ne!(payload_key(&DK, &NP), payload_key(&DK, &[0x33; 16]));

        let pt = vec![0u8; 3 * STREAM_CHUNK_SIZE]; // all-zero plaintext exposes keystream reuse
        let a = encrypt(&DK, &NP, &pt).unwrap();
        let b = encrypt(&DK, &[0x33; 16], &pt).unwrap();
        assert_eq!(a.len(), b.len());
        // Every chunk's ciphertext differs between the two nonce_prefixes (no keystream reuse).
        let block = STREAM_CHUNK_SIZE + TAG_LEN;
        for c in a.chunks(block).zip(b.chunks(block)) {
            assert_ne!(c.0, c.1);
        }
    }
}
