//! Fixed-size AEAD data blocks (UC-25 / C68).
//!
//! Each block seals exactly `capacity` plaintext bytes with XChaCha20-Poly1305. The nonce is
//! **derived** deterministically from `(block_id, version)` so a fresh `version` per sync gives a
//! unique nonce for every block position (no keystream reuse). The block kind is bound as AAD, so
//! a block cannot be replayed as a different kind. On-disk layout: `nonce[24] || ct || tag[16]`.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Result};

/// XChaCha20-Poly1305 nonce length.
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;

/// Block kinds bound as AAD (persisted layout — UC-25 §on-disk).
pub(crate) const KIND_FREE: u8 = 0;
pub(crate) const KIND_FILE: u8 = 1;
pub(crate) const KIND_DIR: u8 = 2;

type HmacSha256 = Hmac<Sha256>;

/// Derived per-block nonce: first 24 bytes of `HMAC-SHA256(nonce_key, block_id_le || version_le)`.
pub(crate) fn block_nonce(nonce_key: &[u8; 32], block_id: u64, version: u64) -> [u8; NONCE_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(nonce_key).expect("HMAC accepts any key length");
    mac.update(&block_id.to_le_bytes());
    mac.update(&version.to_le_bytes());
    let full = mac.finalize().into_bytes();
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&full[..NONCE_LEN]);
    n
}

/// AAD: `volume_id || block_id_le || version_le || kind`.
fn block_aad(volume_id: &[u8; 16], block_id: u64, version: u64, kind: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 8 + 8 + 1);
    aad.extend_from_slice(volume_id);
    aad.extend_from_slice(&block_id.to_le_bytes());
    aad.extend_from_slice(&version.to_le_bytes());
    aad.push(kind);
    aad
}

/// Seal one block → on-disk bytes `nonce[24] || ct || tag[16]`.
pub(crate) fn seal_block(
    volume_key: &[u8; 32],
    nonce_key: &[u8; 32],
    volume_id: &[u8; 16],
    block_id: u64,
    version: u64,
    kind: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(volume_key).map_err(|_| Error::Crypto)?;
    let nonce = block_nonce(nonce_key, block_id, version);
    let aad = block_aad(volume_id, block_id, version, kind);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The Poly1305 tag (last 16 bytes) of a sealed on-disk block — the Merkle leaf input (ADR-0008).
pub(crate) fn block_tag(on_disk: &[u8]) -> Result<[u8; TAG_LEN]> {
    if on_disk.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::VolumeOpenFailed);
    }
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&on_disk[on_disk.len() - TAG_LEN..]);
    Ok(t)
}

/// Open one block → its `capacity` plaintext bytes. The nonce is re-derived (the stored nonce is
/// self-describing layout only). Any tamper of ct/tag/AAD fails closed with [`Error::VolumeOpenFailed`].
pub(crate) fn open_block(
    volume_key: &[u8; 32],
    nonce_key: &[u8; 32],
    volume_id: &[u8; 16],
    block_id: u64,
    version: u64,
    kind: u8,
    on_disk: &[u8],
) -> Result<Vec<u8>> {
    if on_disk.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::VolumeOpenFailed);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(volume_key).map_err(|_| Error::VolumeOpenFailed)?;
    let nonce = block_nonce(nonce_key, block_id, version);
    let aad = block_aad(volume_id, block_id, version, kind);
    cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &on_disk[NONCE_LEN..], aad: &aad })
        .map_err(|_| Error::VolumeOpenFailed)
}
