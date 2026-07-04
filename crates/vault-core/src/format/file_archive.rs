//! Inner file-archive TLV payload for sealed containers (UC-23, constraints C30/C62/C65).
//!
//! Plaintext layout (inside the STREAM AEAD):
//!
//! ```text
//! (FILE_HDR FILE_PART*)* END
//! ```
//!
//! `FILE_HDR` value: `path_len u32 | path_utf8 | mode u32 | mtime u64 | size u64`.
//! `FILE_PART` carries the next chunk of file bytes. Paths are validated before extract (C65).

use super::cursor::Cursor;
use super::tlv::{read_record, write_record};
use crate::{Error, Result};

/// Maximum UTF-8 path length stored in an archive entry (4 KiB).
pub const MAX_PATH_LEN: usize = 4096;
/// Maximum single `FILE_PART` payload.
pub const MAX_PART_LEN: usize = 64 * 1024;
/// Maximum declared file body size (256 GiB — hostile-input cap).
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024 * 1024;

/// TLV tags for the inner file archive.
pub mod tag {
    /// Start of a file entry (path + metadata).
    pub const FILE_HDR: u16 = 0x0100;
    /// Chunk of file body bytes.
    pub const FILE_PART: u16 = 0x0101;
    /// End of archive marker.
    pub const END: u16 = 0xFFFF;
}

/// Metadata for one archived file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// Relative path inside the container (forward slashes).
    pub path: String,
    /// Unix permission bits (lower 12 bits).
    pub mode: u32,
    /// Modification time (Unix seconds).
    pub mtime: u64,
    /// Declared body size in bytes.
    pub size: u64,
}

fn encode_hdr(meta: &FileMeta) -> Result<Vec<u8>> {
    if meta.path.len() > MAX_PATH_LEN {
        return Err(Error::BodyMalformed);
    }
    let mut out = Vec::with_capacity(4 + meta.path.len() + 20);
    out.extend_from_slice(&(meta.path.len() as u32).to_le_bytes());
    out.extend_from_slice(meta.path.as_bytes());
    out.extend_from_slice(&meta.mode.to_le_bytes());
    out.extend_from_slice(&meta.mtime.to_le_bytes());
    out.extend_from_slice(&meta.size.to_le_bytes());
    Ok(out)
}

fn decode_hdr(value: &[u8]) -> Result<FileMeta> {
    let mut cur = Cursor::new(value);
    let path_len = cur.read_u32_le()? as usize;
    if path_len > MAX_PATH_LEN {
        return Err(Error::BodyMalformed);
    }
    let path_bytes = cur.take(path_len).map_err(|_| Error::BodyMalformed)?;
    let path = String::from_utf8(path_bytes.to_vec()).map_err(|_| Error::BodyMalformed)?;
    validate_inner_path(&path)?;
    let mode = cur.read_u32_le()?;
    let mtime = cur.read_u64_le()?;
    let size = cur.read_u64_le()?;
    if size > MAX_FILE_SIZE || cur.remaining() != 0 {
        return Err(Error::BodyMalformed);
    }
    Ok(FileMeta {
        path,
        mode,
        mtime,
        size,
    })
}

/// Reject absolute paths, `..`, and empty components (C65).
pub fn validate_inner_path(path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
        return Err(Error::SealedOpenFailed);
    }
    if path.contains('\\') {
        return Err(Error::SealedOpenFailed);
    }
    for comp in path.split('/') {
        if comp.is_empty() || comp == ".." || comp == "." {
            return Err(Error::SealedOpenFailed);
        }
    }
    Ok(())
}

/// Resolve `path` strictly under `root` (C65).
pub fn resolve_under_root(root: &std::path::Path, path: &str) -> Result<std::path::PathBuf> {
    validate_inner_path(path)?;
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let out = root.join(path);
    if !out.starts_with(&root) {
        return Err(Error::SealedOpenFailed);
    }
    Ok(out)
}

/// Append a `FILE_HDR` record for `meta`.
pub fn write_file_hdr(out: &mut Vec<u8>, meta: &FileMeta) -> Result<()> {
    validate_inner_path(&meta.path)?;
    write_record(out, tag::FILE_HDR, &encode_hdr(meta)?);
    Ok(())
}

/// Append a `FILE_PART` chunk.
pub fn write_file_part(out: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    if chunk.len() > MAX_PART_LEN {
        return Err(Error::BodyMalformed);
    }
    write_record(out, tag::FILE_PART, chunk);
    Ok(())
}

/// Append the archive `END` marker.
pub fn write_end(out: &mut Vec<u8>) {
    write_record(out, tag::END, &[]);
}

/// Parse a complete archive (post-AEAD plaintext, padding stripped).
pub fn parse_all(bytes: &[u8]) -> Result<Vec<(FileMeta, Vec<u8>)>> {
    let mut cur = Cursor::new(bytes);
    let mut out = Vec::new();
    let mut current: Option<(FileMeta, Vec<u8>)> = None;

    while let Some((t, v)) = read_record(&mut cur, MAX_PART_LEN + 128)? {
        match t {
            tag::END => {
                if let Some((meta, body)) = current.take() {
                    if body.len() as u64 != meta.size {
                        return Err(Error::BodyMalformed);
                    }
                    out.push((meta, body));
                }
                break;
            }
            tag::FILE_HDR => {
                if let Some((meta, body)) = current.take() {
                    if body.len() as u64 != meta.size {
                        return Err(Error::BodyMalformed);
                    }
                    out.push((meta, body));
                }
                current = Some((decode_hdr(v)?, Vec::new()));
            }
            tag::FILE_PART => {
                let slot = current.as_mut().ok_or(Error::BodyMalformed)?;
                if slot.1.len() as u64 + v.len() as u64 > slot.0.size {
                    return Err(Error::BodyMalformed);
                }
                slot.1.extend_from_slice(v);
            }
            _ => return Err(Error::BodyMalformed),
        }
    }

    if current.is_some() {
        return Err(Error::BodyMalformed);
    }
    Ok(out)
}

/// Incremental archive parser for streaming decrypt (UC-23 / C63).
#[derive(Debug, Default)]
pub struct ArchiveIncrementalParser {
    buf: Vec<u8>,
    current: Option<(FileMeta, Vec<u8>)>,
    done: bool,
}

impl ArchiveIncrementalParser {
    /// New parser expecting plaintext archive bytes (padding already stripped or trailing zeros).
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed decrypted plaintext; returns any newly completed `(meta, body)` pairs.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<(FileMeta, Vec<u8>)>> {
        if self.done {
            if data.is_empty() || data.iter().all(|&b| b == 0) {
                return Ok(Vec::new());
            }
            return Err(Error::BodyMalformed);
        }
        self.buf.extend_from_slice(data);
        let mut completed = Vec::new();
        loop {
            let mut cur = Cursor::new(&self.buf);
            let Some((t, v)) = read_record(&mut cur, MAX_PART_LEN + 128)? else {
                break;
            };
            let consumed = cur.position();
            match t {
                tag::END => {
                    if let Some((meta, body)) = self.current.take() {
                        if body.len() as u64 != meta.size {
                            return Err(Error::BodyMalformed);
                        }
                        completed.push((meta, body));
                    }
                    self.buf.drain(..consumed);
                    self.done = true;
                    break;
                }
                tag::FILE_HDR => {
                    if let Some((meta, body)) = self.current.take() {
                        if body.len() as u64 != meta.size {
                            return Err(Error::BodyMalformed);
                        }
                        completed.push((meta, body));
                    }
                    self.current = Some((decode_hdr(v)?, Vec::new()));
                    self.buf.drain(..consumed);
                }
                tag::FILE_PART => {
                    let slot = self.current.as_mut().ok_or(Error::BodyMalformed)?;
                    if slot.1.len() as u64 + v.len() as u64 > slot.0.size {
                        return Err(Error::BodyMalformed);
                    }
                    slot.1.extend_from_slice(v);
                    self.buf.drain(..consumed);
                }
                _ => return Err(Error::BodyMalformed),
            }
        }
        Ok(completed)
    }

    /// True after an authenticated `END` record was parsed.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Require a clean end-of-archive (no trailing file, `END` seen).
    pub fn finish(self) -> Result<()> {
        if !self.done || self.current.is_some() {
            return Err(Error::BodyMalformed);
        }
        if !self.buf.is_empty() && self.buf.iter().all(|&b| b == 0) {
            return Ok(());
        }
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::BodyMalformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_one_file() {
        let mut buf = Vec::new();
        let meta = FileMeta {
            path: "dir/hello.txt".into(),
            mode: 0o644,
            mtime: 1_700_000_000,
            size: 5,
        };
        write_file_hdr(&mut buf, &meta).unwrap();
        write_file_part(&mut buf, b"hello").unwrap();
        write_end(&mut buf);
        let files = parse_all(&buf).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, meta);
        assert_eq!(files[0].1, b"hello");
    }

    #[test]
    fn rejects_traversal_paths() {
        assert!(validate_inner_path("../etc/passwd").is_err());
        assert!(validate_inner_path("/abs").is_err());
    }

    #[test]
    fn parse_all_rejects_hostile_inner_paths() {
        use super::tag;
        for hostile in ["../etc/passwd", "foo/../../bar"] {
            let mut buf = Vec::new();
            let mut val = Vec::new();
            val.extend_from_slice(&(hostile.len() as u32).to_le_bytes());
            val.extend_from_slice(hostile.as_bytes());
            val.extend_from_slice(&0o644u32.to_le_bytes());
            val.extend_from_slice(&0u64.to_le_bytes());
            val.extend_from_slice(&1u64.to_le_bytes());
            write_record(&mut buf, tag::FILE_HDR, &val);
            write_record(&mut buf, tag::FILE_PART, b"x");
            write_record(&mut buf, tag::END, &[]);
            assert!(
                parse_all(&buf).is_err(),
                "parse_all must reject hostile inner path: {hostile}"
            );
        }
    }

    #[test]
    fn incremental_parse_large_file_split_feeds() {
        let payload = vec![0xCDu8; 128 * 1024];
        let mut buf = Vec::new();
        let meta = FileMeta {
            path: "large.bin".into(),
            mode: 0o644,
            mtime: 0,
            size: payload.len() as u64,
        };
        write_file_hdr(&mut buf, &meta).unwrap();
        for chunk in payload.chunks(MAX_PART_LEN) {
            write_file_part(&mut buf, chunk).unwrap();
        }
        write_end(&mut buf);
        buf.extend_from_slice(&[0u8; 64]);

        let mut parser = ArchiveIncrementalParser::new();
        let mut written = 0usize;
        for chunk in buf.chunks(1000) {
            for (m, body) in parser.feed(chunk).unwrap() {
                assert_eq!(body.len() as u64, m.size);
                written += body.len();
            }
        }
        assert_eq!(written, payload.len());
        parser.finish().unwrap();
    }

    #[test]
    fn incremental_parser_accepts_trailing_zero_padding_after_end() {
        let mut buf = Vec::new();
        let meta = FileMeta {
            path: "big.bin".into(),
            mode: 0o644,
            mtime: 0,
            size: 4,
        };
        write_file_hdr(&mut buf, &meta).unwrap();
        write_file_part(&mut buf, b"data").unwrap();
        write_end(&mut buf);

        let mut parser = ArchiveIncrementalParser::new();
        let _ = parser.feed(&buf).unwrap();
        assert!(parser.is_done());
        let _ = parser.feed(&[0u8; 16]).unwrap();
        parser.finish().unwrap();
    }
}
