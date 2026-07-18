//! A minimal **bounded** byte reader for parsing untrusted vault files.
//!
//! Every read is checked against the remaining input before it happens, so a truncated or hostile
//! file yields a clean [`Error::HeaderCorrupt`] instead of a panic or an over-read. This is the
//! foundation of the hardened-parser posture (constraints C7–C10, C30): the format
//! parsers never index past the slice and never allocate based on an unchecked length.

use crate::{Error, Result};

/// A forward-only cursor over a byte slice with bounds-checked reads.
#[derive(Debug)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Wrap a byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// All bytes from the start through the current position (the span an integrity tag covers).
    pub fn consumed(&self) -> &'a [u8] {
        &self.buf[..self.pos]
    }

    /// Read exactly `n` bytes, advancing the cursor. Errors if fewer than `n` remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::HeaderCorrupt)?;
        if end > self.buf.len() {
            return Err(Error::HeaderCorrupt);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Read a fixed-size array.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    pub fn read_u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take_array::<2>()?))
    }

    /// Read a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take_array::<4>()?))
    }

    /// Read a little-endian `u64`.
    pub fn read_u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take_array::<8>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_bounds() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0xAA];
        let mut c = Cursor::new(&bytes);
        assert_eq!(c.read_u32_le().unwrap(), 0x04030201);
        assert_eq!(c.read_u8().unwrap(), 0xAA);
        assert_eq!(c.remaining(), 0);
        // One byte too many → clean error, no panic.
        assert!(matches!(c.read_u8(), Err(Error::HeaderCorrupt)));
    }

    #[test]
    fn take_past_end_is_error_not_panic() {
        let bytes = [0u8; 3];
        let mut c = Cursor::new(&bytes);
        assert!(matches!(c.take(4), Err(Error::HeaderCorrupt)));
        // overflow-safe length
        assert!(matches!(c.take(usize::MAX), Err(Error::HeaderCorrupt)));
    }

    #[test]
    fn consumed_tracks_position() {
        let bytes = [1, 2, 3, 4];
        let mut c = Cursor::new(&bytes);
        let _ = c.take(2).unwrap();
        assert_eq!(c.consumed(), &[1, 2]);
        assert_eq!(c.position(), 2);
    }
}
