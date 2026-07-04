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
    let mut enc = StreamEncryptor::new(data_key, nonce_prefix)?;
    enc.push(plaintext)?;
    enc.finish()
}

/// Incremental STREAM encryptor — accepts arbitrary-size plaintext chunks (UC-23 / C63).
pub struct StreamEncryptor {
    cipher: chacha20poly1305::ChaCha20Poly1305,
    pending: Vec<u8>,
    out: Vec<u8>,
    counter: u64,
    finished: bool,
    plaintext_len: usize,
}

impl std::fmt::Debug for StreamEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEncryptor")
            .field("pending_len", &self.pending.len())
            .field("out_len", &self.out.len())
            .field("counter", &self.counter)
            .field("plaintext_len", &self.plaintext_len)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl StreamEncryptor {
    /// Begin encrypting with the payload key derived from `data_key` + `nonce_prefix`.
    pub fn new(data_key: &[u8; 32], nonce_prefix: &[u8; 16]) -> Result<Self> {
        let key = Zeroizing::new(payload_key(data_key, nonce_prefix));
        let cipher = ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Crypto)?;
        Ok(Self {
            cipher,
            pending: Vec::new(),
            out: Vec::new(),
            counter: 0,
            finished: false,
            plaintext_len: 0,
        })
    }

    /// Total plaintext bytes accepted so far (before padding).
    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    /// Append plaintext; seals full 64 KiB chunks eagerly.
    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        if self.finished {
            return Err(Error::Crypto);
        }
        self.plaintext_len += data.len();
        self.pending.extend_from_slice(data);
        while self.pending.len() >= STREAM_CHUNK_SIZE {
            let chunk: Vec<u8> = self.pending.drain(..STREAM_CHUNK_SIZE).collect();
            self.seal_one(&chunk, false)?;
        }
        Ok(())
    }

    fn seal_one(&mut self, chunk: &[u8], is_last: bool) -> Result<()> {
        let nonce = chunk_nonce(self.counter, is_last);
        let sealed = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), chunk)
            .map_err(|_| Error::Crypto)?;
        self.out.extend_from_slice(&sealed);
        if !is_last {
            self.counter = self.counter.checked_add(1).ok_or(Error::BodyMalformed)?;
        }
        Ok(())
    }

    /// Seal any remainder and the age final-chunk marker; returns STREAM ciphertext.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::Crypto);
        }
        self.finished = true;
        if self.pending.is_empty() {
            if self.plaintext_len == 0 || self.plaintext_len.is_multiple_of(STREAM_CHUNK_SIZE) {
                self.seal_one(&[], true)?;
            }
        } else {
            let tail = std::mem::take(&mut self.pending);
            self.seal_one(&tail, true)?;
        }
        Ok(self.out)
    }
}

/// Decrypt a STREAM produced by [`encrypt`] (constraint C1).
///
/// Each chunk's tag is verified before its bytes are accepted; any failure aborts with
/// [`Error::BodyAuth`] and no partial plaintext is returned. Output is zeroized on drop.
///
/// Prefer [`decrypt_streaming`] when opening a vault — it avoids retaining the full plaintext
/// buffer (C19 in-memory posture).
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

/// Decrypt the outer STREAM and parse the payload incrementally .
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
    fn stream_encryptor_matches_encrypt() {
        let pt: Vec<u8> = (0..STREAM_CHUNK_SIZE + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        let a = encrypt(&DK, &NP, &pt).unwrap();
        let mut enc = StreamEncryptor::new(&DK, &NP).unwrap();
        enc.push(&pt[..STREAM_CHUNK_SIZE / 2]).unwrap();
        enc.push(&pt[STREAM_CHUNK_SIZE / 2..]).unwrap();
        let b = enc.finish().unwrap();
        assert_eq!(a, b);
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
