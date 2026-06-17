//! The decrypted payload: inner header + version counter + entries (constraints C18, C19, C16).
//!
//! Layout (TLV records, see [`super::tlv`]):
//!
//! ```text
//! 0x0001 inner_stream_algorithm  u8 = 1 (ChaCha20)   ┐ inner header (C19)
//! 0x0002 inner_stream_key        [64]                ┘
//! 0x0010 vault_version           u64                   (C16)
//! 0x0020 entry                   (one per entry, value = field TLV stream)
//! 0x0000 end-of-payload
//! ```
//!
//! This is the plaintext that the XChaCha20-Poly1305 STREAM layer (C1) encrypts and the
//! HmacBlockStream (C10) authenticates. The Protected field values inside each entry are
//! inner-stream encrypted (C19) by the open/save flow; this module frames the structure only.

use std::sync::Arc;

use super::cursor::Cursor;
use super::entry::{Entry, Protected};
use super::inner_stream::{InnerStream, SealKey};
use super::tlv::{self, MAX_ENTRY_LEN};
use crate::pad::PadMode;
use crate::{Error, Result};

/// The only inner-stream algorithm in v1: ChaCha20 (constraint C19).
pub const INNER_STREAM_CHACHA20: u8 = 1;
/// Inner-stream key length (constraint C19).
pub const INNER_STREAM_KEY_LEN: usize = 64;

mod tag {
    pub const INNER_ALGO: u16 = 0x0001;
    pub const INNER_KEY: u16 = 0x0002;
    pub const PAD_MODE: u16 = 0x0003; // UC-07 §3.2 padding policy (u8); absent = none
    pub const VAULT_VERSION: u16 = 0x0010;
    pub const ENTRY: u16 = 0x0020;
    pub const USAGE: u16 = 0x0030; // UC-19 frecency store (id‖uses‖last_used × n); absent = empty
    pub const END: u16 = 0x0000;
}

/// The decrypted vault payload.
#[derive(Debug, PartialEq, Eq)]
pub struct Payload {
    /// 64-byte inner-stream key, regenerated on every save (constraint C19). Secret.
    pub inner_stream_key: Protected,
    /// Payload size-padding policy (UC-07 §3.2). Persisted inside the AEAD; default `None`.
    pub pad_mode: PadMode,
    /// Monotonic version counter (constraint C16).
    pub vault_version: u64,
    /// The entries.
    pub entries: Vec<Entry>,
    /// Per-entry usage signal for search ranking (UC-19). Lives here so it is encrypted at rest
    /// (constraint C36 — no plaintext index). Absent in vaults written before this feature → empty.
    pub usage: crate::frecency::FrecencyStore,
}

impl Payload {
    /// Serialize the payload to its plaintext TLV form (pre-encryption).
    ///
    /// The inner header (algorithm + `inner_stream_key`) is written in the clear (it is protected by
    /// the outer AEAD); every entry's Protected field values are then inner-stream encrypted under
    /// that key through one advancing [`InnerStream`], in entry order (constraint C19).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        tlv::write_record(&mut out, tag::INNER_ALGO, &[INNER_STREAM_CHACHA20]);
        tlv::write_record(&mut out, tag::INNER_KEY, &self.inner_stream_key.expose());
        tlv::write_record(&mut out, tag::PAD_MODE, &[self.pad_mode.to_byte()]);
        tlv::write_record(
            &mut out,
            tag::VAULT_VERSION,
            &self.vault_version.to_le_bytes(),
        );
        let mut inner = InnerStream::new(&self.inner_stream_key.expose());
        for e in &self.entries {
            tlv::write_record(&mut out, tag::ENTRY, &e.serialize(&mut inner));
        }
        // UC-19 usage signal — written inside the payload so the outer AEAD encrypts it (C36).
        if !self.usage.is_empty() {
            tlv::write_record(&mut out, tag::USAGE, &self.usage.serialize());
        }
        tlv::write_record(&mut out, tag::END, &[]);
        out
    }

    /// Parse a decrypted payload. Stops at the `0x0000` end marker or a clean end of buffer.
    ///
    /// Entries are collected first, then decoded through one [`InnerStream`] built from the parsed
    /// `inner_stream_key` — so the key is always available before any Protected field is decrypted,
    /// regardless of record order (constraint C19).
    pub fn parse(bytes: &[u8]) -> Result<Payload> {
        let mut cur = Cursor::new(bytes);
        let mut inner_key: Option<Protected> = None;
        let mut pad_mode = PadMode::None;
        let mut version: Option<u64> = None;
        let mut entry_blobs: Vec<&[u8]> = Vec::new();
        let mut usage = crate::frecency::FrecencyStore::new();

        while let Some((t, v)) = tlv::read_record(&mut cur, MAX_ENTRY_LEN)? {
            match t {
                tag::END => break,
                tag::INNER_ALGO => {
                    if v != [INNER_STREAM_CHACHA20] {
                        return Err(Error::BodyMalformed); // unsupported inner-stream algorithm
                    }
                }
                tag::INNER_KEY => {
                    if v.len() != INNER_STREAM_KEY_LEN {
                        return Err(Error::BodyMalformed);
                    }
                    inner_key = Some(Protected::new(v.to_vec()));
                }
                tag::PAD_MODE => {
                    if let Some(&b) = v.first() {
                        pad_mode = PadMode::from_byte(b);
                    }
                }
                tag::VAULT_VERSION => version = Some(tlv::decode_u64(v)?),
                tag::ENTRY => entry_blobs.push(v),
                tag::USAGE => usage = crate::frecency::FrecencyStore::parse(v)?,
                _ => { /* unknown record — skip for forward compatibility */ }
            }
        }

        let inner_key = inner_key.ok_or(Error::BodyMalformed)?;
        // Protected fields are kept encrypted in memory and decrypted on access (C19): build one
        // shared, mlocked seal key, and seal each field at its running keystream offset.
        let seal = Arc::new(SealKey::new(&inner_key.expose()));
        let mut offset: u64 = 0;
        let mut entries = Vec::with_capacity(entry_blobs.len());
        for blob in entry_blobs {
            entries.push(Entry::parse(blob, &seal, &mut offset)?);
        }

        Ok(Payload {
            inner_stream_key: inner_key,
            pad_mode,
            vault_version: version.ok_or(Error::BodyMalformed)?,
            entries,
            usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::entry::{CustomField, CustomValue, Entry};

    fn entry(id: u8, title: &str, pw: &[u8]) -> Entry {
        Entry {
            id: [id; 16],
            title: title.into(),
            username: "u".into(),
            password: Protected::new(pw.to_vec()),
            url: String::new(),
            notes: String::new(),
            tags: vec![],
            otp_secret: None,
            created_at: 1,
            modified_at: 2,
            expires_at: None,
            custom_fields: vec![CustomField {
                name: "k".into(),
                value: CustomValue::Protected(Protected::new(b"v".to_vec())),
            }],
        }
    }

    fn sample() -> Payload {
        // Populate usage so round_trip exercises the UC-19 USAGE record path too.
        let mut usage = crate::frecency::FrecencyStore::new();
        usage.record([1u8; 16], 1_000);
        usage.record([2u8; 16], 2_000);
        Payload {
            inner_stream_key: Protected::new(vec![0x5A; INNER_STREAM_KEY_LEN]),
            pad_mode: PadMode::None,
            vault_version: 3,
            entries: vec![entry(1, "a", b"pw-a"), entry(2, "b", b"pw-b")],
            usage,
        }
    }

    #[test]
    fn round_trip() {
        let p = sample();
        assert_eq!(Payload::parse(&p.serialize()).unwrap(), p);
    }

    #[test]
    fn protected_fields_not_plaintext_in_serialized_payload() {
        // C19 (at-rest defense-in-depth): inside the outer-AEAD-decrypted payload, a Protected
        // field's bytes are ChaCha20-encrypted — the plaintext secret must not be findable — yet a
        // normal parse recovers it.
        let secret = b"UNIQUE-passw0rd-DEADBEEF-not-in-bytes";
        let p = Payload {
            inner_stream_key: Protected::new(vec![0x5A; INNER_STREAM_KEY_LEN]),
            pad_mode: PadMode::None,
            vault_version: 1,
            entries: vec![entry(1, "svc", secret)],
            usage: crate::frecency::FrecencyStore::new(),
        };
        let bytes = p.serialize();
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret),
            "Protected field must be inner-stream encrypted in the serialized payload"
        );
        let parsed = Payload::parse(&bytes).unwrap();
        assert_eq!(&parsed.entries[0].password.expose()[..], secret);
    }

    #[test]
    fn round_trip_empty_entries() {
        let p = Payload {
            inner_stream_key: Protected::new(vec![1; INNER_STREAM_KEY_LEN]),
            pad_mode: PadMode::None,
            vault_version: 0,
            entries: vec![],
            usage: crate::frecency::FrecencyStore::new(),
        };
        assert_eq!(Payload::parse(&p.serialize()).unwrap(), p);
    }

    #[test]
    fn missing_inner_key_or_version_rejected() {
        // Only a version, no inner key → malformed.
        let mut bytes = Vec::new();
        tlv::write_record(&mut bytes, tag::VAULT_VERSION, &7u64.to_le_bytes());
        tlv::write_record(&mut bytes, tag::END, &[]);
        assert!(matches!(Payload::parse(&bytes), Err(Error::BodyMalformed)));
    }

    #[test]
    fn wrong_inner_key_length_rejected() {
        let mut bytes = Vec::new();
        tlv::write_record(&mut bytes, tag::INNER_ALGO, &[INNER_STREAM_CHACHA20]);
        tlv::write_record(&mut bytes, tag::INNER_KEY, &[0u8; 32]); // should be 64
        tlv::write_record(&mut bytes, tag::VAULT_VERSION, &1u64.to_le_bytes());
        assert!(matches!(Payload::parse(&bytes), Err(Error::BodyMalformed)));
    }

    #[test]
    fn unsupported_inner_algo_rejected() {
        let mut bytes = Vec::new();
        tlv::write_record(&mut bytes, tag::INNER_ALGO, &[2]); // not ChaCha20
        tlv::write_record(&mut bytes, tag::INNER_KEY, &[0u8; INNER_STREAM_KEY_LEN]);
        tlv::write_record(&mut bytes, tag::VAULT_VERSION, &1u64.to_le_bytes());
        assert!(matches!(Payload::parse(&bytes), Err(Error::BodyMalformed)));
    }

    #[test]
    fn stops_at_end_marker_ignoring_trailing() {
        // Bytes after the END marker are not parsed (e.g. block padding).
        let p = sample();
        let mut bytes = p.serialize();
        bytes.extend_from_slice(&[0xFF; 16]); // trailing padding
        assert_eq!(Payload::parse(&bytes).unwrap(), p);
    }
}
