//! Entry data model and its TLV serialization (constraints C18, C11, C19).
//!
//! An `Entry` lives ONLY inside the decrypted payload (constraint C18 — no entry field ever appears
//! in the plaintext header). Secret-bearing fields use [`Protected`], a zeroizing, redacted wrapper
//! (constraint C11). The inner-stream ChaCha20 layer (constraint C19) protects Protected field
//! values both at rest and **in memory**: on serialize they are encrypted under the payload's
//! `inner_stream_key` in document order through a single advancing [`InnerStream`]; on parse they
//! are kept **`Sealed` (still encrypted in RAM)** with only their keystream offset, and decrypted
//! on access by [`Protected::expose`]. Newly created/edited values are `Plain` until the next save.

use core::fmt;
use std::sync::Arc;

use secrecy::{ExposeSecret, Secret, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::cursor::Cursor;
use super::inner_stream::{InnerStream, SealKey};
use super::tlv::{self, MAX_FIELD_LEN, PROTECTED_BIT};
use crate::Result;

/// TLV tags for an entry's fields (the inner stream of a `0x0020` entry record). Tags with the
/// [`PROTECTED_BIT`] set are inner-stream encrypted (C19).
mod tag {
    pub const ID: u16 = 0x0001;
    pub const TITLE: u16 = 0x0002;
    pub const USERNAME: u16 = 0x0003;
    pub const PASSWORD: u16 = 0x8004; // Protected
    pub const URL: u16 = 0x0005;
    pub const NOTES: u16 = 0x0006;
    pub const TAG: u16 = 0x0007; // repeated
    pub const OTP_SECRET: u16 = 0x8008; // Protected, optional
    pub const CREATED_AT: u16 = 0x0009;
    pub const MODIFIED_AT: u16 = 0x000A;
    pub const EXPIRES_AT: u16 = 0x000B; // optional
    pub const CUSTOM_NAME: u16 = 0x000C;
    pub const CUSTOM_VALUE: u16 = 0x000D;
    pub const CUSTOM_VALUE_PROTECTED: u16 = 0x800D; // Protected
}

/// A secret-bearing value: zeroized on drop, never logged, compared in constant time (C11, C25).
///
/// Two in-memory forms (C19):
/// - **Plain** — a freshly created or edited value, held as zeroizing plaintext.
/// - **Sealed** — a value loaded from an opened vault: kept **inner-stream-encrypted in RAM**,
///   storing only its ciphertext and keystream offset (plus a shared handle to the mlocked key).
///   The plaintext is materialized only when [`Protected::expose`] is called (decrypt-on-access),
///   so a swap leak or partial heap disclosure of the payload does not directly expose secret bytes.
pub struct Protected(ProtectedInner);

enum ProtectedInner {
    Plain(SecretBox<[u8]>),
    Sealed {
        ct: Box<[u8]>,
        key: Arc<SealKey>,
        offset: u64,
    },
}

impl Protected {
    /// Wrap secret plaintext bytes (a newly created or edited value).
    pub fn new(bytes: Vec<u8>) -> Self {
        Protected(ProtectedInner::Plain(Secret::new(bytes.into_boxed_slice())))
    }

    /// Wrap an inner-stream-**encrypted** field loaded from an opened vault (C19 in-memory form):
    /// the bytes stay ChaCha20-encrypted in RAM until [`Protected::expose`] decrypts them.
    pub(crate) fn sealed(ct: Vec<u8>, key: Arc<SealKey>, offset: u64) -> Self {
        Protected(ProtectedInner::Sealed {
            ct: ct.into_boxed_slice(),
            key,
            offset,
        })
    }

    /// Decrypt (if sealed) and return the plaintext secret bytes, zeroized on drop. For a `Sealed`
    /// value this runs the inner-stream ChaCha20 decryption at access time (C19); the plaintext
    /// exists only in the returned buffer. Callers must not log the result.
    pub fn expose(&self) -> Zeroizing<Vec<u8>> {
        match &self.0 {
            ProtectedInner::Plain(s) => Zeroizing::new(s.expose_secret().to_vec()),
            ProtectedInner::Sealed { ct, key, offset } => key.open_at(*offset, ct),
        }
    }
}

#[cfg(test)]
impl Protected {
    /// Test hook (C19 test 4): the in-memory ciphertext of a `Sealed` value, or `None` if `Plain`.
    /// Lets a test assert that a loaded field is *not* plaintext in memory before access.
    fn sealed_ct(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectedInner::Sealed { ct, .. } => Some(ct),
            ProtectedInner::Plain(_) => None,
        }
    }
}

impl fmt::Debug for Protected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Protected([REDACTED])")
    }
}

impl PartialEq for Protected {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time (C25): never branch on secret bytes.
        let (a, b) = (self.expose(), other.expose());
        a.as_slice().ct_eq(b.as_slice()).into()
    }
}
impl Eq for Protected {}

/// A user-defined custom field value — either plaintext metadata or a Protected secret (C19).
#[derive(Debug, PartialEq, Eq)]
pub enum CustomValue {
    /// Non-secret value (TLV tag `0x000D`).
    Plain(String),
    /// Secret value, inner-stream encrypted (TLV tag `0x800D`).
    Protected(Protected),
}

/// A custom field: a name plus a (plain or protected) value.
#[derive(Debug, PartialEq, Eq)]
pub struct CustomField {
    /// Field name (non-secret).
    pub name: String,
    /// Field value.
    pub value: CustomValue,
}

/// One credential entry. No field of this struct is ever serialized outside the AEAD body (C18).
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    /// 16-byte random identifier, assigned once at creation (stable entry identity).
    pub id: [u8; 16],
    /// Entry title (non-secret metadata, but encrypted in the payload like every field — C18).
    pub title: String,
    /// Username (non-secret metadata).
    pub username: String,
    /// Password — Protected (C19).
    pub password: Protected,
    /// URL (non-secret metadata).
    pub url: String,
    /// Free-form notes (non-secret metadata).
    pub notes: String,
    /// Tags (non-secret metadata).
    pub tags: Vec<String>,
    /// Optional TOTP secret — Protected (C19).
    pub otp_secret: Option<Protected>,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Last-modified time (unix seconds).
    pub modified_at: i64,
    /// Optional expiry time (unix seconds).
    pub expires_at: Option<i64>,
    /// Custom fields.
    pub custom_fields: Vec<CustomField>,
}

impl Entry {
    /// Serialize this entry's fields as a TLV stream (the value of a `0x0020` entry record).
    ///
    /// Protected field values are inner-stream encrypted through `inner` in document order (C19);
    /// `inner` MUST be the same stream instance shared across all entries in the payload, in the
    /// order they are serialized, so save/open stay in lockstep.
    pub(crate) fn serialize(&self, inner: &mut InnerStream) -> Vec<u8> {
        let mut out = Vec::new();
        tlv::write_record(&mut out, tag::ID, &self.id);
        tlv::write_record(&mut out, tag::TITLE, self.title.as_bytes());
        tlv::write_record(&mut out, tag::USERNAME, self.username.as_bytes());
        write_protected(&mut out, tag::PASSWORD, &self.password.expose(), inner);
        tlv::write_record(&mut out, tag::URL, self.url.as_bytes());
        tlv::write_record(&mut out, tag::NOTES, self.notes.as_bytes());
        for t in &self.tags {
            tlv::write_record(&mut out, tag::TAG, t.as_bytes());
        }
        if let Some(otp) = &self.otp_secret {
            write_protected(&mut out, tag::OTP_SECRET, &otp.expose(), inner);
        }
        tlv::write_record(&mut out, tag::CREATED_AT, &self.created_at.to_le_bytes());
        tlv::write_record(&mut out, tag::MODIFIED_AT, &self.modified_at.to_le_bytes());
        if let Some(exp) = self.expires_at {
            tlv::write_record(&mut out, tag::EXPIRES_AT, &exp.to_le_bytes());
        }
        for cf in &self.custom_fields {
            tlv::write_record(&mut out, tag::CUSTOM_NAME, cf.name.as_bytes());
            match &cf.value {
                CustomValue::Plain(s) => {
                    tlv::write_record(&mut out, tag::CUSTOM_VALUE, s.as_bytes())
                }
                CustomValue::Protected(p) => {
                    write_protected(&mut out, tag::CUSTOM_VALUE_PROTECTED, &p.expose(), inner)
                }
            }
        }
        out
    }

    /// Parse an entry from its field TLV stream. Unknown tags are skipped (forward compatibility).
    ///
    /// Protected field values are kept **encrypted in memory** (C19 in-memory form): each is stored
    /// `Sealed` with its keystream `offset` (the running byte position, shared across the whole
    /// payload in document order) and a handle to the inner-stream `key`; it is decrypted only when
    /// the field is exposed. `offset` MUST be the same running counter used across all entries.
    pub(crate) fn parse(bytes: &[u8], key: &Arc<SealKey>, offset: &mut u64) -> Result<Entry> {
        let mut cur = Cursor::new(bytes);
        let mut e = Entry {
            id: [0u8; 16],
            title: String::new(),
            username: String::new(),
            password: Protected::new(Vec::new()),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            otp_secret: None,
            created_at: 0,
            modified_at: 0,
            expires_at: None,
            custom_fields: Vec::new(),
        };
        // A custom field is a NAME record followed by a VALUE record; pair them as we go.
        let mut pending_name: Option<String> = None;

        while let Some((t, v)) = tlv::read_record(&mut cur, MAX_FIELD_LEN)? {
            // A new custom-name or any non-custom-value tag closes an unpaired pending name
            // (a name with no value becomes a field with an empty plaintext value).
            if t != tag::CUSTOM_VALUE && t != tag::CUSTOM_VALUE_PROTECTED {
                if let Some(name) = pending_name.take() {
                    e.custom_fields.push(CustomField {
                        name,
                        value: CustomValue::Plain(String::new()),
                    });
                }
            }
            match t {
                tag::ID => {
                    let arr: [u8; 16] = v.try_into().map_err(|_| crate::Error::BodyMalformed)?;
                    e.id = arr;
                }
                tag::TITLE => e.title = tlv::decode_str(v)?,
                tag::USERNAME => e.username = tlv::decode_str(v)?,
                tag::PASSWORD => e.password = seal_protected(v, key, offset),
                tag::URL => e.url = tlv::decode_str(v)?,
                tag::NOTES => e.notes = tlv::decode_str(v)?,
                tag::TAG => e.tags.push(tlv::decode_str(v)?),
                tag::OTP_SECRET => e.otp_secret = Some(seal_protected(v, key, offset)),
                tag::CREATED_AT => e.created_at = tlv::decode_i64(v)?,
                tag::MODIFIED_AT => e.modified_at = tlv::decode_i64(v)?,
                tag::EXPIRES_AT => e.expires_at = Some(tlv::decode_i64(v)?),
                tag::CUSTOM_NAME => pending_name = Some(tlv::decode_str(v)?),
                tag::CUSTOM_VALUE => {
                    let name = pending_name.take().unwrap_or_default();
                    e.custom_fields.push(CustomField {
                        name,
                        value: CustomValue::Plain(tlv::decode_str(v)?),
                    });
                }
                tag::CUSTOM_VALUE_PROTECTED => {
                    let name = pending_name.take().unwrap_or_default();
                    e.custom_fields.push(CustomField {
                        name,
                        value: CustomValue::Protected(seal_protected(v, key, offset)),
                    });
                }
                _ => { /* unknown tag (incl. unknown Protected) — skip for forward compat */ }
            }
        }
        if let Some(name) = pending_name.take() {
            e.custom_fields.push(CustomField {
                name,
                value: CustomValue::Plain(String::new()),
            });
        }
        Ok(e)
    }
}

// A tag is Protected iff its high bit is set — used by the inner-stream layer (C19), kept here so
// the predicate lives with the tag definitions.
#[allow(dead_code)]
pub(crate) fn is_protected(tag: u16) -> bool {
    tag & PROTECTED_BIT != 0
}

/// Inner-stream encrypt `plaintext` and write it as a `tag` record (C19). The stream advances by
/// `plaintext.len()` bytes; the transient buffer is overwritten in place to ciphertext.
fn write_protected(out: &mut Vec<u8>, tag: u16, plaintext: &[u8], inner: &mut InnerStream) {
    let mut buf = plaintext.to_vec();
    inner.apply(&mut buf);
    tlv::write_record(out, tag, &buf);
}

/// Wrap a Protected field value as `Sealed` (kept encrypted in memory, C19) at the current keystream
/// `offset`, then advance `offset` by the field length so the next Protected field is positioned
/// correctly in the shared inner stream. The ciphertext is **not** decrypted here.
fn seal_protected(ct: &[u8], key: &Arc<SealKey>, offset: &mut u64) -> Protected {
    let p = Protected::sealed(ct.to_vec(), key.clone(), *offset);
    *offset += ct.len() as u64;
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::payload::INNER_STREAM_KEY_LEN;

    const INNER_KEY: [u8; INNER_STREAM_KEY_LEN] = [0x5A; INNER_STREAM_KEY_LEN];

    fn seal_key(k: &[u8; INNER_STREAM_KEY_LEN]) -> Arc<SealKey> {
        Arc::new(SealKey::new(k))
    }

    /// Serialize then parse an entry through the inner stream at a fixed key (C19 round-trip). The
    /// parsed entry's Protected fields come back `Sealed` (encrypted in memory).
    fn round_trip_through_stream(e: &Entry) -> (Vec<u8>, Entry) {
        let bytes = e.serialize(&mut InnerStream::new(&INNER_KEY));
        let mut offset = 0u64;
        let parsed = Entry::parse(&bytes, &seal_key(&INNER_KEY), &mut offset).unwrap();
        (bytes, parsed)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn sample() -> Entry {
        Entry {
            id: [0xAB; 16],
            title: "github-prod".into(),
            username: "leo".into(),
            password: Protected::new(b"supersecret123".to_vec()),
            url: "https://github.com/org".into(),
            notes: "line1\nline2".into(),
            tags: vec!["work".into(), "vcs".into()],
            otp_secret: Some(Protected::new(b"otpseed".to_vec())),
            created_at: 1_700_000_000,
            modified_at: 1_700_000_500,
            expires_at: Some(1_800_000_000),
            custom_fields: vec![
                CustomField {
                    name: "recovery".into(),
                    value: CustomValue::Plain("ABCD".into()),
                },
                CustomField {
                    name: "api_key".into(),
                    value: CustomValue::Protected(Protected::new(b"sk-xyz".to_vec())),
                },
            ],
        }
    }

    #[test]
    fn round_trip() {
        let e = sample();
        let (_, parsed) = round_trip_through_stream(&e);
        assert_eq!(parsed, e);
    }

    #[test]
    fn round_trip_minimal() {
        let e = Entry {
            id: [1; 16],
            title: "t".into(),
            username: String::new(),
            password: Protected::new(b"p".to_vec()),
            url: String::new(),
            notes: String::new(),
            tags: vec![],
            otp_secret: None,
            created_at: 1,
            modified_at: 2,
            expires_at: None,
            custom_fields: vec![],
        };
        let (_, parsed) = round_trip_through_stream(&e);
        assert_eq!(parsed, e);
    }

    #[test]
    fn protected_values_are_inner_stream_encrypted_in_serialized_bytes() {
        // C19 test 1/2: a Protected value inside the serialized entry must NOT appear in plaintext
        // (it's ChaCha20'd), yet a same-key parse recovers it and a wrong-key parse does not.
        let e = sample();
        let (bytes, parsed) = round_trip_through_stream(&e);
        assert!(
            !contains(&bytes, b"supersecret123"),
            "password must be encrypted"
        );
        assert!(
            !contains(&bytes, b"otpseed"),
            "otp secret must be encrypted"
        );
        assert!(
            !contains(&bytes, b"sk-xyz"),
            "protected custom value must be encrypted"
        );
        // Non-protected metadata stays readable inside the (AEAD-protected) payload.
        assert!(
            contains(&bytes, b"github-prod"),
            "title is not inner-stream encrypted"
        );
        assert_eq!(&parsed.password.expose()[..], b"supersecret123");

        let mut o = 0u64;
        let wrong = Entry::parse(&bytes, &seal_key(&[0x11; INNER_STREAM_KEY_LEN]), &mut o).unwrap();
        assert_ne!(&wrong.password.expose()[..], b"supersecret123");
    }

    #[test]
    fn opened_protected_fields_are_ciphertext_in_memory_until_exposed() {
        // C19 test 4: after parse, the in-memory Protected holds ciphertext (not the plaintext
        // secret); only the field accessor expose() yields the plaintext.
        let (_, parsed) = round_trip_through_stream(&sample());
        let ct = parsed
            .password
            .sealed_ct()
            .expect("a loaded field is sealed in memory");
        assert_ne!(ct, b"supersecret123", "in-memory bytes must be ciphertext");
        assert_eq!(
            &parsed.password.expose()[..],
            b"supersecret123",
            "accessor decrypts"
        );
        // A freshly created (not-yet-saved) value is Plain — no sealed ciphertext form.
        assert!(Protected::new(b"x".to_vec()).sealed_ct().is_none());
    }

    #[test]
    fn protected_is_redacted_and_constant_time_eq() {
        let p = Protected::new(b"hunter2".to_vec());
        assert_eq!(format!("{p:?}"), "Protected([REDACTED])");
        assert_eq!(p, Protected::new(b"hunter2".to_vec()));
        assert_ne!(p, Protected::new(b"hunter3".to_vec()));
    }

    #[test]
    fn unknown_tag_is_skipped() {
        let mut bytes = sample().serialize(&mut InnerStream::new(&INNER_KEY));
        // Append an unknown record (tag 0x7FFF) — must be ignored, entry still parses. It is not a
        // Protected tag, so it does not consume the inner stream.
        tlv::write_record(&mut bytes, 0x7FFF, b"future-field");
        let mut o = 0u64;
        assert_eq!(
            Entry::parse(&bytes, &seal_key(&INNER_KEY), &mut o).unwrap(),
            sample()
        );
    }

    #[test]
    fn bad_id_length_rejected() {
        let mut bytes = Vec::new();
        tlv::write_record(&mut bytes, super::tag::ID, &[0u8; 8]); // wrong width
        let mut o = 0u64;
        assert!(Entry::parse(&bytes, &seal_key(&INNER_KEY), &mut o).is_err());
    }
}
