//! Merkle tree over AEAD block tags (UC-25 / C70 / ADR-0008).
//!
//! HMAC-SHA-256 keyed by `mac_key` (HKDF-derived from the volume master). Leaf preimage is
//! `block_id_le || version_le || tag[16]`; the tree is padded to a power of two with empty leaves
//! `HMAC(mac_key, idx_le || 0u8)`. The root binds every allocated block at a given version, so a
//! cut-paste / rewind of ciphertext fails the root check.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac(mac_key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn leaf(mac_key: &[u8; 32], block_id: u64, version: u64, tag: &[u8; 16]) -> [u8; 32] {
    hmac(
        mac_key,
        &[&block_id.to_le_bytes(), &version.to_le_bytes(), tag],
    )
}

fn empty_leaf(mac_key: &[u8; 32], idx: u64) -> [u8; 32] {
    hmac(mac_key, &[&idx.to_le_bytes(), &[0u8]])
}

fn node(mac_key: &[u8; 32], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hmac(mac_key, &[left, right])
}

/// Merkle root over `tags` (block ids `0..tags.len()`) at `version`. Empty volumes (no tags) hash a
/// single empty leaf so the root is still well-defined.
pub(crate) fn root(mac_key: &[u8; 32], version: u64, tags: &[[u8; 16]]) -> [u8; 32] {
    let n = tags.len();
    let mut width = 1usize;
    while width < n.max(1) {
        width <<= 1;
    }
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(width);
    for (i, t) in tags.iter().enumerate() {
        level.push(leaf(mac_key, i as u64, version, t));
    }
    for idx in n..width {
        level.push(empty_leaf(mac_key, idx as u64));
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(node(mac_key, &pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}
