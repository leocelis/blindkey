//! Incremental TLV parser for STREAM-decrypted plaintext chunks (security-gap review P3).
//!
//! Feeds authenticated plaintext in arbitrary chunk sizes without requiring the full payload in
//! one contiguous buffer first.

use zeroize::Zeroizing;

use crate::{Error, Result};

const HEADER_LEN: usize = 6; // tag u16 + len u32

/// Parses TLV records from streamed plaintext; retains only an incomplete tail between feeds.
#[derive(Debug, Default)]
pub struct IncrementalTlv {
    pending: Zeroizing<Vec<u8>>,
    max_len: usize,
}

impl IncrementalTlv {
    /// Create a parser capped at `max_len` per record value (same as [`tlv::read_record`]).
    pub fn new(max_len: usize) -> Self {
        Self {
            pending: Zeroizing::new(Vec::new()),
            max_len,
        }
    }

    /// Append a verified plaintext chunk from the outer STREAM layer.
    pub fn feed(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.pending.extend_from_slice(chunk);
    }

    /// Try to read the next complete record. Returns `Ok(None)` when more bytes are needed.
    pub fn try_next_record(&mut self) -> Result<Option<(u16, Zeroizing<Vec<u8>>)>> {
        if self.pending.len() < HEADER_LEN {
            return Ok(None);
        }
        let tag = u16::from_le_bytes([self.pending[0], self.pending[1]]);
        let len = u32::from_le_bytes([
            self.pending[2],
            self.pending[3],
            self.pending[4],
            self.pending[5],
        ]) as usize;
        if len > self.max_len {
            return Err(Error::BodyMalformed);
        }
        let total = HEADER_LEN.checked_add(len).ok_or(Error::BodyMalformed)?;
        if self.pending.len() < total {
            return Ok(None);
        }
        let value = Zeroizing::new(self.pending[HEADER_LEN..total].to_vec());
        self.pending.drain(0..total);
        Ok(Some((tag, value)))
    }

    /// Bytes still buffered (incomplete record tail or post-`END` padding).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::tlv;

    #[test]
    fn records_split_across_feeds() {
        let mut buf = Vec::new();
        tlv::write_record(&mut buf, 0x0002, b"hello");
        tlv::write_record(&mut buf, 0x0000, &[]);

        let mut p = IncrementalTlv::new(64);
        // Split mid-header
        p.feed(&buf[..3]);
        assert!(p.try_next_record().unwrap().is_none());
        p.feed(&buf[3..]);
        let (t, v) = p.try_next_record().unwrap().unwrap();
        assert_eq!(t, 0x0002);
        assert_eq!(&v[..], b"hello");
        let (t2, v2) = p.try_next_record().unwrap().unwrap();
        assert_eq!(t2, 0x0000);
        assert!(v2.is_empty());
    }
}
