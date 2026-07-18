//! HmacBlockStream — Encrypt-then-MAC per-block body authentication (constraint C10).
//!
//! The encrypted body is split into blocks, each framed on disk as:
//!
//! ```text
//! [hmac: 32][size: u32 LE][ciphertext: size]
//! ```
//!
//! with `HMAC = HMAC-SHA-256(key = HKDF-SHA-256(ikm = data_key,
//! salt = block_index_u64_LE || master_seed[32], info = "vault-block-hmac-v1"),
//! data = block_index_u64_LE || size_u32_LE || ciphertext)`. A `size == 0` block terminates the
//! stream and is itself authenticated, so truncation (dropping the terminator) and block
//! swap/duplication are all detected. The HMAC key is derived from the **data key** (not the
//! password-derived master key) so any unlock path can verify the body (constraint C10, G0.2).
//!
//! This is the *integrity* layer; the ciphertext it frames is the XChaCha20-Poly1305 STREAM output
//! (constraint C1), which is the *encryption* layer. Per-block HMACs are verified before any block
//! is handed onward for decryption.

use super::cursor::Cursor;
use super::BLOCK_SIZE;
use crate::{Error, Result};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const BLOCK_HMAC_INFO: &[u8] = b"vault-block-hmac-v1";
const HMAC_LEN: usize = 32;

/// Per-block HMAC key: `HKDF-SHA-256(ikm = data_key, salt = index_LE || master_seed, info)`.
fn block_key(data_key: &[u8; 32], index: u64, master_seed: &[u8; 32]) -> [u8; 32] {
    let mut salt = [0u8; 8 + 32];
    salt[..8].copy_from_slice(&index.to_le_bytes());
    salt[8..].copy_from_slice(master_seed);
    let hk = Hkdf::<Sha256>::new(Some(&salt), data_key);
    let mut okm = [0u8; 32];
    hk.expand(BLOCK_HMAC_INFO, &mut okm)
        .expect("32 is a valid HKDF-SHA-256 output length");
    okm
}

fn write_block(
    out: &mut Vec<u8>,
    data_key: &[u8; 32],
    master_seed: &[u8; 32],
    index: u64,
    payload: &[u8],
) {
    let key = block_key(data_key, index, master_seed);
    let size = payload.len() as u32;
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&index.to_le_bytes());
    mac.update(&size.to_le_bytes());
    mac.update(payload);
    let tag = mac.finalize().into_bytes();
    out.extend_from_slice(&tag);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(payload);
}

fn frame_inner(
    data_key: &[u8; 32],
    master_seed: &[u8; 32],
    ciphertext: &[u8],
    block_size: usize,
) -> Vec<u8> {
    debug_assert!(block_size > 0 && block_size <= BLOCK_SIZE);
    let mut out = Vec::new();
    let mut index: u64 = 0;
    for chunk in ciphertext.chunks(block_size) {
        write_block(&mut out, data_key, master_seed, index, chunk);
        index += 1;
    }
    // Authenticated end-of-stream marker (size = 0).
    write_block(&mut out, data_key, master_seed, index, &[]);
    out
}

/// Frame ciphertext into an authenticated block stream using the default 1 MiB block size.
pub fn frame(data_key: &[u8; 32], master_seed: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    frame_inner(data_key, master_seed, ciphertext, BLOCK_SIZE)
}

/// Read and verify a block stream, returning the concatenated ciphertext.
///
/// Verifies each block's HMAC (constant-time) *before* accepting its bytes, rejects any block whose
/// declared size exceeds [`BLOCK_SIZE`] before allocating, and requires the authenticated
/// `size == 0` terminator — so swap, duplication, and truncation all fail (constraint C10).
pub fn read(data_key: &[u8; 32], master_seed: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>> {
    let mut cur = Cursor::new(bytes);
    let mut out = Vec::new();
    let mut index: u64 = 0;

    loop {
        let tag = cur
            .take_array::<HMAC_LEN>()
            .map_err(|_| Error::BodyMalformed)?;
        let size = cur.read_u32_le().map_err(|_| Error::BodyMalformed)?;
        if size as usize > BLOCK_SIZE {
            return Err(Error::BodyMalformed);
        }
        let payload = cur.take(size as usize).map_err(|_| Error::BodyMalformed)?;

        // Verify the per-block HMAC (constant-time via the `hmac` crate) before trusting bytes.
        let key = block_key(data_key, index, master_seed);
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(&index.to_le_bytes());
        mac.update(&size.to_le_bytes());
        mac.update(payload);
        mac.verify_slice(&tag).map_err(|_| Error::BodyAuth)?;

        if size == 0 {
            // Authenticated terminator. Reject trailing bytes appended after it.
            if cur.remaining() != 0 {
                return Err(Error::BodyMalformed);
            }
            return Ok(out);
        }
        out.extend_from_slice(payload);
        index = index.checked_add(1).ok_or(Error::BodyMalformed)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DK: [u8; 32] = [0xA1; 32];
    const SEED: [u8; 32] = [0xB2; 32];
    const BS: usize = 4; // tiny blocks so multi-block tests stay cheap

    #[test]
    fn round_trip_multi_block() {
        let ct = b"the quick brown fox jumps".to_vec(); // 25 bytes → 7 blocks of 4 (+term)
        let framed = frame_inner(&DK, &SEED, &ct, BS);
        assert_eq!(read(&DK, &SEED, &framed).unwrap(), ct);
    }

    #[test]
    fn round_trip_empty_and_default_block_size() {
        let framed = frame(&DK, &SEED, b"");
        assert_eq!(read(&DK, &SEED, &framed).unwrap(), b"");
        let ct = vec![9u8; 100];
        assert_eq!(read(&DK, &SEED, &frame(&DK, &SEED, &ct)).unwrap(), ct);
    }

    // On-disk block length for a `BS`-sized data block: 32 (hmac) + 4 (size) + BS payload.
    const BLOCK_LEN: usize = HMAC_LEN + 4 + BS;

    #[test]
    fn swapped_blocks_fail_hmac() {
        // C10: swap blocks 0 and 1 → block at index 0 carries index-1's tag → BodyAuth.
        let ct = vec![1u8; 4 * 3]; // exactly 3 full blocks
        let mut framed = frame_inner(&DK, &SEED, &ct, BS);
        let (b0, b1) = (0..BLOCK_LEN, BLOCK_LEN..2 * BLOCK_LEN);
        let block0: Vec<u8> = framed[b0].to_vec();
        let block1: Vec<u8> = framed[b1.clone()].to_vec();
        framed[0..BLOCK_LEN].copy_from_slice(&block1);
        framed[BLOCK_LEN..2 * BLOCK_LEN].copy_from_slice(&block0);
        assert!(matches!(read(&DK, &SEED, &framed), Err(Error::BodyAuth)));
    }

    #[test]
    fn duplicated_block_fails_hmac() {
        // C10: copy block 1 over block 2 → at index 2 the tag is index-1's → BodyAuth.
        let ct = vec![2u8; 4 * 3];
        let mut framed = frame_inner(&DK, &SEED, &ct, BS);
        let block1: Vec<u8> = framed[BLOCK_LEN..2 * BLOCK_LEN].to_vec();
        framed[2 * BLOCK_LEN..3 * BLOCK_LEN].copy_from_slice(&block1);
        assert!(matches!(read(&DK, &SEED, &framed), Err(Error::BodyAuth)));
    }

    #[test]
    fn missing_terminator_is_truncation_error() {
        // C10: drop the size=0 terminator block → unexpected EOF.
        let ct = vec![3u8; 4 * 2];
        let framed = frame_inner(&DK, &SEED, &ct, BS);
        let terminator_len = HMAC_LEN + 4; // size=0 → empty payload
        let truncated = &framed[..framed.len() - terminator_len];
        assert!(matches!(
            read(&DK, &SEED, truncated),
            Err(Error::BodyMalformed)
        ));
    }

    #[test]
    fn flipped_ciphertext_byte_fails_hmac() {
        let ct = vec![4u8; 10];
        let mut framed = frame_inner(&DK, &SEED, &ct, BS);
        // First block's payload begins after [hmac:32][size:4].
        framed[HMAC_LEN + 4] ^= 0x01;
        assert!(matches!(read(&DK, &SEED, &framed), Err(Error::BodyAuth)));
    }

    #[test]
    fn oversized_block_size_rejected() {
        // A hostile block claiming size > BLOCK_SIZE is rejected before allocation.
        let mut framed = vec![0u8; HMAC_LEN];
        framed.extend_from_slice(&((BLOCK_SIZE as u32) + 1).to_le_bytes());
        assert!(matches!(
            read(&DK, &SEED, &framed),
            Err(Error::BodyMalformed)
        ));
    }

    #[test]
    fn wrong_data_key_fails() {
        let framed = frame(&DK, &SEED, b"secret-ish ciphertext");
        let wrong = [0xFFu8; 32];
        assert!(matches!(read(&wrong, &SEED, &framed), Err(Error::BodyAuth)));
    }
}
