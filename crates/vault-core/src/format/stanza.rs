//! Key-wrapping stanza records (constraint C5).
//!
//! A stanza wraps the data key under one unlock factor. The header carries `stanza_count` of them
//! (any one unlocks — the OR envelope). At the **format** layer a stanza is an opaque, bounded
//! blob: `[type: u8][len: u32 LE][data: len]`. The envelope layer (C5/C6, constraint group G2)
//! interprets `data` (`wrap_nonce[24] || wrapped_key[48] || extra`); the parser here only enforces
//! the structural bounds so a hostile file can never trigger an unbounded allocation.

use super::cursor::Cursor;
use super::{MAX_STANZAS, MAX_STANZA_DATA_LEN};
use crate::{Error, Result};

/// Stanza type tags (constraint C5). `password` (1) is always present in a valid vault.
pub mod kind {
    /// Password stanza — Argon2id-derived wrapping key. Always present.
    pub const PASSWORD: u8 = 1;
    /// FIDO2 `hmac-secret` stanza.
    pub const FIDO2: u8 = 2;
    /// YubiKey HMAC-SHA1 challenge-response stanza.
    pub const YUBIKEY: u8 = 3;
    /// TPM 2.0 PCR-sealed stanza.
    pub const TPM: u8 = 4;
    /// macOS Secure Enclave / Keychain stanza.
    pub const KEYCHAIN: u8 = 5;
    /// Windows DPAPI stanza.
    pub const DPAPI: u8 = 6;
    /// **Composite** password **AND** YubiKey HMAC-SHA1 stanza — both factors required to unwrap
    /// (true 2FA, unlike the single-factor OR stanzas above). `data` is
    /// `challenge[32] || wrap_nonce[24] || wrapped_key[48]`.
    pub const PW_YUBIKEY: u8 = 7;
}

/// One key-wrapping stanza record. `data` is opaque at this layer (interpreted by the envelope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stanza {
    /// Stanza type tag (see [`kind`]).
    pub stanza_type: u8,
    /// Opaque wrapping data: `wrap_nonce[24] || wrapped_key[48] || extra`. Bounded to
    /// [`MAX_STANZA_DATA_LEN`].
    pub data: Vec<u8>,
}

impl Stanza {
    /// On-disk byte length of this record: `1 (type) + 4 (len) + data`.
    pub fn on_disk_len(&self) -> usize {
        1 + 4 + self.data.len()
    }

    /// Parse one stanza record from the cursor, enforcing the length bound *before* allocating.
    pub fn parse(cur: &mut Cursor<'_>) -> Result<Stanza> {
        let stanza_type = cur.read_u8()?;
        let len = cur.read_u32_le()?;
        if len > MAX_STANZA_DATA_LEN {
            return Err(Error::HeaderCorrupt);
        }
        // `len` is bounded by MAX_STANZA_DATA_LEN (4096); `take` re-checks against the real buffer,
        // so even a len within bound but past EOF is rejected without panicking.
        let data = cur.take(len as usize)?.to_vec();
        Ok(Stanza { stanza_type, data })
    }

    /// Append this stanza's on-disk bytes to `out`.
    pub fn serialize_into(&self, out: &mut Vec<u8>) {
        debug_assert!(self.data.len() <= MAX_STANZA_DATA_LEN as usize);
        out.push(self.stanza_type);
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
    }
}

/// Parse a length-prefixed stanza sequence from raw bytes: `[count: u8][stanza × count]`.
///
/// Public, bytes-level entry point used by the `stanza_parse` fuzz target and tests (the
/// [`Cursor`] type is internal to the format module).
pub fn parse_sequence(bytes: &[u8]) -> Result<Vec<Stanza>> {
    let mut cur = Cursor::new(bytes);
    let count = cur.read_u8()?;
    parse_all(&mut cur, count)
}

/// Parse `count` stanzas in sequence. Rejects `count > MAX_STANZAS` (constraint C5).
pub fn parse_all(cur: &mut Cursor<'_>, count: u8) -> Result<Vec<Stanza>> {
    if count > MAX_STANZAS {
        return Err(Error::HeaderCorrupt);
    }
    let mut stanzas = Vec::with_capacity(count as usize);
    for _ in 0..count {
        stanzas.push(Stanza::parse(cur)?);
    }
    Ok(stanzas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = Stanza {
            stanza_type: kind::PASSWORD,
            data: vec![7u8; 72], // 24-byte nonce + 48-byte wrapped key
        };
        let mut buf = Vec::new();
        s.serialize_into(&mut buf);
        assert_eq!(buf.len(), s.on_disk_len());
        let mut cur = Cursor::new(&buf);
        assert_eq!(Stanza::parse(&mut cur).unwrap(), s);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn oversized_len_rejected_before_alloc() {
        // type=1, len=0xFFFFFFFF, no data — must reject on the bound, not try to allocate 4 GiB.
        let mut buf = vec![kind::PASSWORD];
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut cur = Cursor::new(&buf);
        assert!(matches!(Stanza::parse(&mut cur), Err(Error::HeaderCorrupt)));
    }

    #[test]
    fn too_many_stanzas_rejected() {
        let mut cur = Cursor::new(&[]);
        assert!(matches!(
            parse_all(&mut cur, MAX_STANZAS + 1),
            Err(Error::HeaderCorrupt)
        ));
    }

    #[test]
    fn len_within_bound_but_past_eof_rejected() {
        // len says 100 but only 10 bytes follow.
        let mut buf = vec![kind::PASSWORD];
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        let mut cur = Cursor::new(&buf);
        assert!(matches!(Stanza::parse(&mut cur), Err(Error::HeaderCorrupt)));
    }
}
