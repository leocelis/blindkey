//! In-memory VFS + path hygiene and inode-table (dir-meta) serialization (UC-25).
//!
//! Paths are forward-slash relative strings; `..`, absolute paths, and NUL bytes are rejected
//! (C: no traversal). The tree is a `BTreeMap` so entries serialize in a deterministic sorted order.
//! The inode table is packed into the leading dir-meta blocks; each file's bytes occupy a
//! contiguous run of file-data blocks recorded as `(first_block, block_count)`.

use std::collections::BTreeMap;

use crate::{Error, Result};

/// A VFS node — a directory or a file with in-memory contents.
#[derive(Debug, Clone)]
pub(crate) enum Node {
    Dir,
    File(Vec<u8>),
}

/// The in-memory volume tree. Keys are normalized relative paths (root is the empty string).
pub(crate) type Vfs = BTreeMap<String, Node>;

/// Normalize + validate a caller path. Rejects absolute paths, `..`, and NUL (fail closed).
pub(crate) fn normalize(path: &str) -> Result<String> {
    if path.contains('\0') {
        return Err(Error::VolumeOpenFailed);
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(Error::VolumeOpenFailed);
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => return Err(Error::VolumeOpenFailed),
            s => parts.push(s),
        }
    }
    Ok(parts.join("/"))
}

/// Parent directory of a normalized path (`""` for a top-level entry).
pub(crate) fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => "",
    }
}

/// Last path component (base name).
pub(crate) fn base_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// A single inode-table entry (dir or file). File entries carry their block run.
#[derive(Debug, Clone)]
pub(crate) struct Inode {
    pub path: String,
    pub is_dir: bool,
    pub length: u64,
    pub first_block: u64,
    pub block_count: u64,
}

/// Encode the inode table (fixed-width fields + length-prefixed UTF-8 paths).
pub(crate) fn encode_inodes(inodes: &[Inode]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(inodes.len() as u32).to_le_bytes());
    for e in inodes {
        let p = e.path.as_bytes();
        out.extend_from_slice(&(p.len() as u16).to_le_bytes());
        out.extend_from_slice(p);
        out.push(if e.is_dir { 1 } else { 0 });
        out.extend_from_slice(&e.length.to_le_bytes());
        out.extend_from_slice(&e.first_block.to_le_bytes());
        out.extend_from_slice(&e.block_count.to_le_bytes());
    }
    out
}

/// Decode the inode table (fails closed on any short/oversized field).
pub(crate) fn decode_inodes(buf: &[u8]) -> Result<Vec<Inode>> {
    let mut c = Reader { buf, pos: 0 };
    let count = c.u32()?;
    let mut out = Vec::with_capacity(count.min(1 << 16) as usize);
    for _ in 0..count {
        let plen = c.u16()? as usize;
        let path =
            String::from_utf8(c.take(plen)?.to_vec()).map_err(|_| Error::VolumeOpenFailed)?;
        let is_dir = c.u8()? != 0;
        let length = c.u64()?;
        let first_block = c.u64()?;
        let block_count = c.u64()?;
        out.push(Inode {
            path,
            is_dir,
            length,
            first_block,
            block_count,
        });
    }
    Ok(out)
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
}
