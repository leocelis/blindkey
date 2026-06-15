//! The inner ChaCha20 random stream over Protected fields (constraint C19).
//!
//! After the outer XChaCha20-Poly1305 AEAD (C1), every field marked Protected (password,
//! `otp_secret`, protected custom values) receives an **additional** ChaCha20 stream-cipher pass
//! keyed by the payload's 64-byte `inner_stream_key`. Protected fields are processed in **document
//! order through a single stream** whose state advances sequentially (not independently keyed per
//! field), exactly matching between save (encrypt) and open (decrypt) — KDBX 4 precedent.
//!
//! Two views of the same keystream:
//! - [`InnerStream`] — a forward-only cursor used when **serializing** (encrypt each Protected
//!   field in document order, advancing the stream).
//! - [`SealKey`] — a shared, seekable handle used for **in-memory protection** (C19 "IN-MEMORY
//!   USE"): an opened vault keeps each Protected field *encrypted in RAM*, storing only its byte
//!   offset, and decrypts on demand by seeking the keystream to that offset. The key bytes are
//!   mlocked off swap for the life of the open vault.
//!
//! On disk this layer is defense-in-depth (the outer AEAD is the primary boundary); in memory it is
//! the primary defense — a swap leak or partial heap disclosure of the decrypted payload buffer does
//! not directly expose password bytes, because Protected fields stay ChaCha20-encrypted until the
//! field accessor runs. The session still holds the key, so it does not defend against a full,
//! key-inclusive memory dump (KDBX 4 has the same property; see C19 rationale).
//!
//! ## Key derivation (implementation-defined, within C19's latitude)
//! The 64-byte key is mapped to an IETF ChaCha20 instance:
//! - bytes `0..32`  → 256-bit ChaCha20 key
//! - bytes `32..44` → 96-bit nonce
//! - bytes `44..64` → reserved (unused by the 12-byte-nonce instantiation in v1)
//!
//! The counter starts at zero; byte offset `N` of the keystream is identical whether reached by
//! advancing [`InnerStream`] or by [`SealKey`] seeking — so encrypt (save) and decrypt (access)
//! agree.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use zeroize::{Zeroize, Zeroizing};

use crate::format::payload::INNER_STREAM_KEY_LEN;

fn cipher_from_key(key: &[u8]) -> ChaCha20 {
    let cipher_key = chacha20::Key::from_slice(&key[0..32]);
    let nonce = chacha20::Nonce::from_slice(&key[32..44]);
    ChaCha20::new(cipher_key, nonce)
}

/// A forward-only ChaCha20 keystream over a vault's Protected fields, for serialization (C19).
pub(crate) struct InnerStream {
    cipher: ChaCha20,
}

impl InnerStream {
    /// Build the stream from the 64-byte inner-stream key.
    ///
    /// Callers guarantee `key.len() == INNER_STREAM_KEY_LEN` (the payload parser validates the
    /// length before constructing, and a save always uses a freshly generated 64-byte key).
    pub(crate) fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), INNER_STREAM_KEY_LEN);
        InnerStream {
            cipher: cipher_from_key(key),
        }
    }

    /// Apply the next keystream segment to `data` in place, advancing the stream by `data.len()`
    /// bytes. Used to encrypt Protected fields in document order during serialization.
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

/// A shared, seekable handle to the inner-stream key, for in-memory decrypt-on-access (C19).
///
/// Held behind an `Arc` and referenced by every `Sealed` Protected field of an open vault. The key
/// bytes are mlocked off swap for the handle's lifetime and zeroized on drop.
pub(crate) struct SealKey {
    key: Box<[u8; INNER_STREAM_KEY_LEN]>,
    locked: bool,
}

impl SealKey {
    /// Copy the 64-byte inner-stream key into a locked-off-swap buffer. `key_bytes.len()` MUST be
    /// `INNER_STREAM_KEY_LEN` (the payload parser validates this before constructing).
    pub(crate) fn new(key_bytes: &[u8]) -> Self {
        debug_assert_eq!(key_bytes.len(), INNER_STREAM_KEY_LEN);
        let mut key = Box::new([0u8; INNER_STREAM_KEY_LEN]);
        key.copy_from_slice(&key_bytes[..INNER_STREAM_KEY_LEN]);
        let locked = vault_sys::lock_region(key.as_ptr(), INNER_STREAM_KEY_LEN);
        SealKey { key, locked }
    }

    /// Decrypt the Protected field whose ciphertext is `ct`, sealed at keystream byte `offset`.
    /// Returns transient plaintext that zeroes on drop (C11).
    pub(crate) fn open_at(&self, offset: u64, ct: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut cipher = cipher_from_key(&self.key[..]);
        cipher.seek(offset);
        let mut buf = Zeroizing::new(ct.to_vec());
        cipher.apply_keystream(&mut buf);
        buf
    }
}

impl Drop for SealKey {
    fn drop(&mut self) {
        if self.locked {
            vault_sys::unlock_region(self.key.as_ptr(), INNER_STREAM_KEY_LEN);
        }
        self.key.zeroize();
    }
}

impl core::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; INNER_STREAM_KEY_LEN] = [0x5A; INNER_STREAM_KEY_LEN];

    #[test]
    fn apply_is_its_own_inverse() {
        let plain = b"ghp_FAKE0mZ9xQ2vL7nR4tW8pY1aB3cD5eF6gH7iJ";
        let mut buf = plain.to_vec();
        InnerStream::new(&KEY).apply(&mut buf);
        assert_ne!(buf, plain); // encrypted: not the plaintext
        InnerStream::new(&KEY).apply(&mut buf);
        assert_eq!(buf, plain); // decrypted back with a fresh stream at the same key
    }

    #[test]
    fn stream_advances_sequentially_across_fields() {
        // Two fields encrypted through one advancing stream must differ from the same two fields
        // each encrypted from a fresh stream position 0 (the second field's keystream is offset).
        let (a, b) = (
            b"first-secret-value".to_vec(),
            b"first-secret-value".to_vec(),
        );
        let mut s = InnerStream::new(&KEY);
        let mut a_seq = a.clone();
        s.apply(&mut a_seq);
        let mut b_seq = b.clone();
        s.apply(&mut b_seq); // continues the stream — different keystream than a
        assert_ne!(
            a_seq, b_seq,
            "identical plaintexts must encrypt differently down one stream"
        );

        // Decrypting in the same order recovers both.
        let mut d = InnerStream::new(&KEY);
        let mut a_back = a_seq.clone();
        d.apply(&mut a_back);
        let mut b_back = b_seq.clone();
        d.apply(&mut b_back);
        assert_eq!(a_back, a);
        assert_eq!(b_back, b);
    }

    #[test]
    fn wrong_key_does_not_recover() {
        let plain = b"supersecret123".to_vec();
        let mut ct = plain.clone();
        InnerStream::new(&KEY).apply(&mut ct);
        let mut wrong = ct.clone();
        InnerStream::new(&[0x11; INNER_STREAM_KEY_LEN]).apply(&mut wrong);
        assert_ne!(wrong, plain);
    }

    #[test]
    fn seal_key_seek_matches_sequential_stream() {
        // The seekable SealKey must reproduce exactly the keystream positions an advancing
        // InnerStream produced — so a field encrypted at offset N decrypts by seeking to N.
        let f0 = b"first-field-secret".to_vec();
        let f1 = b"second-field-secret-longer".to_vec();
        let mut enc = InnerStream::new(&KEY);
        let mut c0 = f0.clone();
        enc.apply(&mut c0);
        let off1 = c0.len() as u64;
        let mut c1 = f1.clone();
        enc.apply(&mut c1);

        let sk = SealKey::new(&KEY);
        assert_eq!(&sk.open_at(0, &c0)[..], &f0[..]);
        assert_eq!(&sk.open_at(off1, &c1)[..], &f1[..]);
    }
}
