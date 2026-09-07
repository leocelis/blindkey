//! Inner volume header — fixed-size, dual AEAD-wrapped superblock metadata (UC-25).
//!
//! Sits right after the plaintext outer [`Header`](crate::format::Header). Two identical plaintext
//! copies (primary + backup) are each XChaCha20-Poly1305-sealed with `volume_key` under a fresh
//! random nonce and a copy-indexed AAD, so a torn write to one copy still leaves a recoverable
//! header. It records the freshness/commitment fields (`kcom`, `merkle_root`, `version`) and the
//! block-layout counts needed to read the data region.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::pad::PadMode;
use crate::{Error, Result};

use super::block::{NONCE_LEN, TAG_LEN};

const INNER_VERSION: u16 = 1;
const AAD_LABEL: &[u8] = b"volume-inner";

/// Fixed inner-header plaintext length (all fields are fixed-width).
pub(crate) const INNER_PT_LEN: usize = 2  // inner_version
    + 2  // block_size_kib
    + 1  // pad_mode
    + 8  // size_bytes
    + 8  // max_bytes
    + 8  // version
    + 4  // block_count
    + 4  // meta_block_count
    + 8  // meta_len
    + 32 // kcom
    + 32; // merkle_root

/// On-disk length of one wrapped inner-header copy.
pub(crate) const INNER_WRAPPED_LEN: usize = NONCE_LEN + INNER_PT_LEN + TAG_LEN;

/// Parsed inner-header fields.
#[derive(Debug, Clone)]
pub(crate) struct InnerHeader {
    pub block_size_kib: u16,
    pub pad_mode: PadMode,
    pub size_bytes: u64,
    pub max_bytes: u64,
    pub version: u64,
    pub block_count: u32,
    pub meta_block_count: u32,
    pub meta_len: u64,
    pub kcom: [u8; 32],
    pub merkle_root: [u8; 32],
}

impl InnerHeader {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INNER_PT_LEN);
        out.extend_from_slice(&INNER_VERSION.to_le_bytes());
        out.extend_from_slice(&self.block_size_kib.to_le_bytes());
        out.push(self.pad_mode.to_byte());
        out.extend_from_slice(&self.size_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_bytes.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.block_count.to_le_bytes());
        out.extend_from_slice(&self.meta_block_count.to_le_bytes());
        out.extend_from_slice(&self.meta_len.to_le_bytes());
        out.extend_from_slice(&self.kcom);
        out.extend_from_slice(&self.merkle_root);
        debug_assert_eq!(out.len(), INNER_PT_LEN);
        out
    }

    fn decode(pt: &[u8]) -> Result<Self> {
        if pt.len() != INNER_PT_LEN {
            return Err(Error::VolumeOpenFailed);
        }
        let mut c = Reader { buf: pt, pos: 0 };
        let _inner_version = c.u16()?;
        let block_size_kib = c.u16()?;
        let pad_mode = PadMode::from_byte(c.u8()?);
        let size_bytes = c.u64()?;
        let max_bytes = c.u64()?;
        let version = c.u64()?;
        let block_count = c.u32()?;
        let meta_block_count = c.u32()?;
        let meta_len = c.u64()?;
        let kcom = c.arr32()?;
        let merkle_root = c.arr32()?;
        Ok(Self {
            block_size_kib,
            pad_mode,
            size_bytes,
            max_bytes,
            version,
            block_count,
            meta_block_count,
            meta_len,
            kcom,
            merkle_root,
        })
    }
}

fn aad(volume_id: &[u8; 16], copy: u8) -> Vec<u8> {
    let mut a = Vec::with_capacity(16 + AAD_LABEL.len() + 1);
    a.extend_from_slice(volume_id);
    a.extend_from_slice(AAD_LABEL);
    a.push(copy);
    a
}

/// Wrap one inner-header copy → `nonce[24] || ct || tag[16]`.
fn wrap_copy(volume_key: &[u8; 32], volume_id: &[u8; 16], copy: u8, pt: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(volume_key).map_err(|_| Error::Crypto)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Crypto)?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: pt,
                aad: &aad(volume_id, copy),
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(INNER_WRAPPED_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Serialize the dual (primary + backup) wrapped inner header — total `2 * INNER_WRAPPED_LEN` bytes.
pub(crate) fn serialize_dual(
    volume_key: &[u8; 32],
    volume_id: &[u8; 16],
    inner: &InnerHeader,
) -> Result<Vec<u8>> {
    let pt = inner.encode();
    let mut out = wrap_copy(volume_key, volume_id, 0, &pt)?;
    out.extend_from_slice(&wrap_copy(volume_key, volume_id, 1, &pt)?);
    Ok(out)
}

fn unwrap_copy(
    volume_key: &[u8; 32],
    volume_id: &[u8; 16],
    copy: u8,
    on_disk: &[u8],
) -> Result<InnerHeader> {
    if on_disk.len() < INNER_WRAPPED_LEN {
        return Err(Error::VolumeOpenFailed);
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(volume_key).map_err(|_| Error::VolumeOpenFailed)?;
    let nonce = &on_disk[..NONCE_LEN];
    let ct = &on_disk[NONCE_LEN..INNER_WRAPPED_LEN];
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad(volume_id, copy),
            },
        )
        .map_err(|_| Error::VolumeOpenFailed)?;
    InnerHeader::decode(&pt)
}

/// Parse the dual inner header, falling back to the backup copy if the primary is damaged.
pub(crate) fn parse_dual(
    volume_key: &[u8; 32],
    volume_id: &[u8; 16],
    region: &[u8],
) -> Result<InnerHeader> {
    if region.len() < 2 * INNER_WRAPPED_LEN {
        return Err(Error::VolumeOpenFailed);
    }
    match unwrap_copy(volume_key, volume_id, 0, &region[..INNER_WRAPPED_LEN]) {
        Ok(h) => Ok(h),
        Err(_) => unwrap_copy(
            volume_key,
            volume_id,
            1,
            &region[INNER_WRAPPED_LEN..2 * INNER_WRAPPED_LEN],
        ),
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::VolumeOpenFailed)?;
        if end > self.buf.len() {
            return Err(Error::VolumeOpenFailed);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn arr32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}
