//! Bounded TLV (tag–length–value) codec for the encrypted payload (constraints C18, C19, C30).
//!
//! Record shape, all integers little-endian: `tag: u16 | len: u32 | value: [len]`. A tag with bit
//! 15 (`0x8000`) set marks a **Protected** field, whose `value` is inner-stream encrypted (C19)
//! before it reaches this codec — the codec itself never encrypts, it only frames bytes.
//!
//! This parser runs on *authenticated* plaintext (the STREAM tags and block HMACs are verified
//! first — C1/C10), so its threat level is below the header parser's. It is still bounds-checked
//! and fuzzed (C30): every `len` is validated against a cap *and* the remaining buffer before any
//! allocation, and unknown tags are skipped for forward compatibility.

use super::cursor::Cursor;
use crate::{Error, Result};

/// Tag bit 15: the record's value is a Protected (inner-stream-encrypted) field (C19).
pub const PROTECTED_BIT: u16 = 0x8000;

/// Maximum length of a single entry **field** value (1 MiB, per UC-03 §3.2).
pub const MAX_FIELD_LEN: usize = 1024 * 1024;
/// Maximum length of an **entry** record value (a whole entry's worth of fields).
pub const MAX_ENTRY_LEN: usize = 16 * 1024 * 1024;

/// Append one record to `out`.
pub fn write_record(out: &mut Vec<u8>, tag: u16, value: &[u8]) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

/// Read one record, bounded by `max_len`. Returns `Ok(None)` at a clean end of buffer.
///
/// Rejects a declared length above `max_len` *before* touching the buffer; the cursor then
/// re-checks against the real remaining bytes, so neither an oversized cap nor a truncated buffer
/// can cause an over-read or unbounded allocation.
pub fn read_record<'a>(cur: &mut Cursor<'a>, max_len: usize) -> Result<Option<(u16, &'a [u8])>> {
    if cur.remaining() == 0 {
        return Ok(None);
    }
    let tag = cur.read_u16_le().map_err(|_| Error::BodyMalformed)?;
    let len = cur.read_u32_le().map_err(|_| Error::BodyMalformed)? as usize;
    if len > max_len {
        return Err(Error::BodyMalformed);
    }
    if cur.remaining() < len {
        // Incremental parsers (UC-23 file archive) may receive partial records.
        return Ok(None);
    }
    let value = cur.take(len).map_err(|_| Error::BodyMalformed)?;
    Ok(Some((tag, value)))
}

/// Decode a UTF-8 string field, rejecting invalid UTF-8 (post-AEAD, so this is a structural check).
pub fn decode_str(value: &[u8]) -> Result<String> {
    String::from_utf8(value.to_vec()).map_err(|_| Error::BodyMalformed)
}

/// Decode a fixed 8-byte little-endian `i64`.
pub fn decode_i64(value: &[u8]) -> Result<i64> {
    let arr: [u8; 8] = value.try_into().map_err(|_| Error::BodyMalformed)?;
    Ok(i64::from_le_bytes(arr))
}

/// Decode a fixed 8-byte little-endian `u64`.
pub fn decode_u64(value: &[u8]) -> Result<u64> {
    let arr: [u8; 8] = value.try_into().map_err(|_| Error::BodyMalformed)?;
    Ok(u64::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_records_and_eof() {
        let mut buf = Vec::new();
        write_record(&mut buf, 0x0002, b"hello");
        write_record(&mut buf, 0x8004, &[1, 2, 3]);
        let mut cur = Cursor::new(&buf);
        assert_eq!(
            read_record(&mut cur, 64).unwrap(),
            Some((0x0002, &b"hello"[..]))
        );
        let (tag, val) = read_record(&mut cur, 64).unwrap().unwrap();
        assert_eq!(tag & PROTECTED_BIT, PROTECTED_BIT);
        assert_eq!(val, &[1, 2, 3]);
        assert_eq!(read_record(&mut cur, 64).unwrap(), None); // clean EOF
    }

    #[test]
    fn oversized_len_rejected_before_alloc() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0002u16.to_le_bytes());
        buf.extend_from_slice(&u32::MAX.to_le_bytes()); // claims 4 GiB
        let mut cur = Cursor::new(&buf);
        assert!(matches!(
            read_record(&mut cur, MAX_FIELD_LEN),
            Err(Error::BodyMalformed)
        ));
    }

    #[test]
    fn len_within_cap_but_past_eof_is_incomplete_not_fatal() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0002u16.to_le_bytes());
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        let mut cur = Cursor::new(&buf);
        assert_eq!(read_record(&mut cur, MAX_FIELD_LEN).unwrap(), None);
    }

    #[test]
    fn decoders_validate_length() {
        assert_eq!(decode_str(b"hi").unwrap(), "hi");
        assert!(decode_str(&[0xff, 0xfe]).is_err()); // invalid UTF-8
        assert_eq!(decode_i64(&7i64.to_le_bytes()).unwrap(), 7);
        assert!(decode_i64(&[0u8; 4]).is_err()); // wrong width
        assert_eq!(decode_u64(&9u64.to_le_bytes()).unwrap(), 9);
    }
}
