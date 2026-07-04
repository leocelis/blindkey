//! The plaintext vault header (constraints C7, C8, C9, C2).
//!
//! Byte layout (all multi-byte integers little-endian), authoritative in `docs/FILE_FORMAT.md`:
//!
//! ```text
//! magic[4] | format_version u16 | vault_id[16] | kdf_algorithm u8 |
//! m_cost u32 | t_cost u32 | p_cost u32 | argon2id_salt[32] | master_seed[32] |
//! nonce_prefix[16] | stanza_count u8 | stanzas[..] | header_hash[32] | header_hmac[32]
//! ```
//!
//! The header carries only non-secret material (salts and seeds are public); no entry content lives
//! here (constraint C18). `header_hash` is a keyless corruption check; `header_hmac` is keyed from
//! the **data key** (not the password-derived master key) so any unlock path — password, hardware,
//! or OS keystore — can authenticate the header (constraint C9, amendment G0.2).

use super::cursor::Cursor;
use super::stanza::{self, Stanza};
use crate::crypto::validate_kdf_params;
use crate::{ContainerKind, Error, Result, FORMAT_VERSION};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The only KDF algorithm valid in v1 (constraint C8).
pub const KDF_ALGORITHM_ARGON2ID: u8 = 1;

const HASH_LEN: usize = 32;
const HMAC_LEN: usize = 32;
const HEADER_HMAC_INFO: &[u8] = b"vault-header-hmac-v1";

type HmacSha256 = Hmac<Sha256>;

/// Argon2id parameters, read verbatim from the file — never compiled-in defaults (constraint C8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// KDF algorithm tag (must be [`KDF_ALGORITHM_ARGON2ID`] in v1).
    pub algorithm: u8,
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
    /// Argon2id salt — CSPRNG, fixed at vault creation.
    pub salt: [u8; 32],
}

/// The parsed plaintext header. Contains no secret material, so it may derive `Debug`/`Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Container magic — [`MAGIC`] or [`crate::MAGIC_VLTF`] (UC-23 §3.1).
    pub magic: [u8; 4],
    /// On-disk format version (constraint C7).
    pub format_version: u16,
    /// Random per-vault id; the HKDF domain-separation salt for stanza derivations (C5/C6/C14).
    pub vault_id: [u8; 16],
    /// File-authoritative KDF parameters (constraint C8).
    pub kdf: KdfParams,
    /// CSPRNG seed regenerated on every body-writing save; salts the per-block HMAC (constraint C10).
    pub master_seed: [u8; 32],
    /// CSPRNG salt for the payload-key HKDF; regenerated on every body write (constraint C1).
    pub nonce_prefix: [u8; 16],
    /// Key-wrapping stanzas (any one unlocks — constraint C5). Bounded to `MAX_STANZAS`.
    pub stanzas: Vec<Stanza>,
    /// Stored keyless SHA-256 over the authenticated span (constraint C9).
    pub header_hash: [u8; HASH_LEN],
    /// Stored keyed HMAC-SHA-256 over the authenticated span (constraint C9). Verified with the
    /// data key once a stanza is unwrapped.
    pub header_hmac: [u8; HMAC_LEN],
}

impl Header {
    /// Container kind derived from the magic prefix.
    pub fn kind(&self) -> ContainerKind {
        ContainerKind::from_magic(self.magic).unwrap_or(ContainerKind::Vault)
    }

    /// The byte span the integrity tags cover: everything from `magic` through the last stanza.
    fn auth_span(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.format_version.to_le_bytes());
        out.extend_from_slice(&self.vault_id);
        out.push(self.kdf.algorithm);
        out.extend_from_slice(&self.kdf.m_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.t_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.p_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.salt);
        out.extend_from_slice(&self.master_seed);
        out.extend_from_slice(&self.nonce_prefix);
        out.push(self.stanzas.len() as u8);
        for s in &self.stanzas {
            s.serialize_into(&mut out);
        }
        out
    }

    /// Full on-disk header bytes: `auth_span || header_hash || header_hmac`.
    ///
    /// Uses the stored tags, so `parse(serialize(h)) == h` byte-for-byte (constraint C8 round-trip).
    /// Build a fresh header with [`Header::seal`] to compute the tags first.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.auth_span();
        out.extend_from_slice(&self.header_hash);
        out.extend_from_slice(&self.header_hmac);
        out
    }

    /// Total on-disk length of the header (offset at which the encrypted body begins).
    pub fn on_disk_len(&self) -> usize {
        self.auth_span().len() + HASH_LEN + HMAC_LEN
    }

    /// Compute the keyless SHA-256 over the authenticated span (constraint C9).
    pub fn compute_hash(&self) -> [u8; HASH_LEN] {
        let mut h = Sha256::new();
        h.update(self.auth_span());
        h.finalize().into()
    }

    /// Derive the header-HMAC key from the data key: `HKDF-SHA-256(ikm=data_key, salt="", info)`.
    fn hmac_key(data_key: &[u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&[]), data_key);
        let mut okm = [0u8; 32];
        hk.expand(HEADER_HMAC_INFO, &mut okm)
            .expect("32 is a valid HKDF-SHA-256 output length");
        okm
    }

    /// Compute the keyed HMAC over the authenticated span (constraint C9, G0.2).
    pub fn compute_hmac(&self, data_key: &[u8; 32]) -> [u8; HMAC_LEN] {
        let key = Self::hmac_key(data_key);
        let mut mac =
            HmacSha256::new_from_slice(&key).expect("HMAC-SHA-256 accepts any key length");
        mac.update(&self.auth_span());
        mac.finalize().into_bytes().into()
    }

    /// Fill `header_hash` and `header_hmac` for a freshly built header (constraint C9).
    pub fn seal(&mut self, data_key: &[u8; 32]) {
        self.header_hash = self.compute_hash();
        self.header_hmac = self.compute_hmac(data_key);
    }

    /// Verify the keyed header HMAC with the data key (constraint C9 step 4, G0.2).
    ///
    /// Constant-time comparison. This is called *after* a stanza has unwrapped the data key, so the
    /// unlock factor is already proven valid — a mismatch here is therefore unambiguous tampering of
    /// the header and returns [`Error::HeaderTampered`] (not the ambiguous stanza-stage error).
    pub fn verify_hmac(&self, data_key: &[u8; 32]) -> Result<()> {
        let expected = self.compute_hmac(data_key);
        if bool::from(expected.ct_eq(&self.header_hmac)) {
            Ok(())
        } else {
            Err(Error::HeaderTampered)
        }
    }

    /// Parse and structurally validate a header from untrusted bytes.
    ///
    /// When `expected` is [`Some`], rejects files whose magic does not match (UC-23 kind mismatch).
    pub fn parse(bytes: &[u8]) -> Result<Header> {
        Self::parse_with_kind(bytes, None)
    }

    /// Parse a header, optionally requiring a specific [`ContainerKind`].
    pub fn parse_with_kind(bytes: &[u8], expected: Option<ContainerKind>) -> Result<Header> {
        let mut cur = Cursor::new(bytes);

        let magic = cur.take_array::<4>()?;
        let kind = ContainerKind::from_magic(magic).ok_or(Error::NotAVault)?;
        if let Some(want) = expected {
            if kind != want {
                return Err(Error::WrongContainerKind);
            }
        }
        let format_version = cur.read_u16_le()?;
        if format_version > FORMAT_VERSION {
            return Err(Error::NewerVersion);
        }

        let vault_id = cur.take_array::<16>()?;
        let algorithm = cur.read_u8()?;
        if algorithm != KDF_ALGORITHM_ARGON2ID {
            return Err(Error::UnsupportedKdf);
        }
        let m_cost = cur.read_u32_le()?;
        let t_cost = cur.read_u32_le()?;
        let p_cost = cur.read_u32_le()?;
        let salt = cur.take_array::<32>()?;
        let master_seed = cur.take_array::<32>()?;
        let nonce_prefix = cur.take_array::<16>()?;
        let stanza_count = cur.read_u8()?;
        let stanzas = stanza::parse_all(&mut cur, stanza_count)?;

        // Everything consumed so far is the integrity-protected span.
        let auth_span = cur.consumed().to_vec();
        let header_hash = cur.take_array::<HASH_LEN>()?;
        let header_hmac = cur.take_array::<HMAC_LEN>()?;

        // C9 step 1: keyless corruption check, before any keyed/expensive work.
        let mut h = Sha256::new();
        h.update(&auth_span);
        let computed: [u8; HASH_LEN] = h.finalize().into();
        if computed != header_hash {
            return Err(Error::HeaderCorrupt);
        }

        // C2 step 2: reject above-ceiling KDF params before any Argon2id allocation. Below-floor
        // params are accepted here (the open flow warns + offers an upgrade — constraint C2).
        validate_kdf_params(m_cost, t_cost, p_cost)?;

        Ok(Header {
            magic,
            format_version,
            vault_id,
            kdf: KdfParams {
                algorithm,
                m_cost,
                t_cost,
                p_cost,
                salt,
            },
            master_seed,
            nonce_prefix,
            stanzas,
            header_hash,
            header_hmac,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ARGON2_DEFAULT_M_COST_KIB, ARGON2_DEFAULT_P_COST, ARGON2_DEFAULT_T_COST};
    use crate::format::stanza::{kind, Stanza};

    fn sample_header() -> Header {
        let mut h = Header {
            magic: crate::MAGIC,
            format_version: FORMAT_VERSION,
            vault_id: [0x11; 16],
            kdf: KdfParams {
                algorithm: KDF_ALGORITHM_ARGON2ID,
                m_cost: ARGON2_DEFAULT_M_COST_KIB,
                t_cost: ARGON2_DEFAULT_T_COST,
                p_cost: ARGON2_DEFAULT_P_COST,
                salt: [0x22; 32],
            },
            master_seed: [0x33; 32],
            nonce_prefix: [0x44; 16],
            stanzas: vec![Stanza {
                stanza_type: kind::PASSWORD,
                data: vec![0x55; 72],
            }],
            header_hash: [0; 32],
            header_hmac: [0; 32],
        };
        h.seal(&[0xAB; 32]);
        h
    }

    #[test]
    fn round_trip_byte_identity() {
        // C8: serialise → parse → identical struct; and parse → serialise → identical bytes.
        let h = sample_header();
        let bytes = h.serialize();
        let parsed = Header::parse(&bytes).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(parsed.serialize(), bytes);
        assert_eq!(h.on_disk_len(), bytes.len());
    }

    #[test]
    fn reader_uses_file_params_not_defaults() {
        // C8: a header carrying m=131072 parses back as 131072 (not the compiled-in default).
        let mut h = sample_header();
        h.kdf.m_cost = 131_072;
        h.seal(&[0xAB; 32]);
        let parsed = Header::parse(&h.serialize()).unwrap();
        assert_eq!(parsed.kdf.m_cost, 131_072);
    }

    #[test]
    fn vltf_magic_round_trip() {
        let mut h = sample_header();
        h.magic = crate::MAGIC_VLTF;
        h.seal(&[0xAB; 32]);
        let parsed =
            Header::parse_with_kind(&h.serialize(), Some(ContainerKind::SealedFile)).unwrap();
        assert_eq!(parsed.magic, crate::MAGIC_VLTF);
        assert_eq!(parsed, h);
    }

    #[test]
    fn wrong_kind_rejected() {
        let mut h = sample_header();
        h.magic = crate::MAGIC_VLTF;
        h.seal(&[0xAB; 32]);
        assert!(matches!(
            Header::parse_with_kind(&h.serialize(), Some(ContainerKind::Vault)),
            Err(Error::WrongContainerKind)
        ));
    }

    #[test]
    fn bad_magic_rejected() {
        // C7: wrong magic → "not a vault file".
        let bytes = [0u8; 64];
        assert!(matches!(Header::parse(&bytes), Err(Error::NotAVault)));
    }

    #[test]
    fn newer_version_rejected() {
        // C7: format_version above supported → NewerVersion.
        let mut h = sample_header();
        h.format_version = 999;
        h.seal(&[0xAB; 32]);
        assert!(matches!(
            Header::parse(&h.serialize()),
            Err(Error::NewerVersion)
        ));
    }

    #[test]
    fn unknown_kdf_algorithm_rejected() {
        // C8: kdf_algorithm = 2 → "unsupported KDF algorithm".
        let mut h = sample_header();
        h.kdf.algorithm = 2;
        h.seal(&[0xAB; 32]);
        assert!(matches!(
            Header::parse(&h.serialize()),
            Err(Error::UnsupportedKdf)
        ));
    }

    #[test]
    fn one_bit_flip_in_mcost_fails_hash_before_kdf() {
        // C9 step 1: flipping a header byte breaks header_hash → HeaderCorrupt (keyless), and we
        // never even reach KDF validation.
        let h = sample_header();
        let mut bytes = h.serialize();
        // vault_id starts at offset 6 (magic[4] + version[2]); flip a byte there.
        bytes[6] ^= 0x01;
        assert!(matches!(Header::parse(&bytes), Err(Error::HeaderCorrupt)));
    }

    #[test]
    fn above_ceiling_kdf_rejected_after_valid_hash() {
        // C2 ceiling: a header with an out-of-ceiling m_cost and a VALID hash over it is rejected by
        // the KDF range check (not the hash).
        let mut h = sample_header();
        h.kdf.m_cost = crate::crypto::ARGON2_CEILING_M_COST_KIB + 1;
        h.seal(&[0xAB; 32]); // valid hash over the hostile params
        assert!(matches!(
            Header::parse(&h.serialize()),
            Err(Error::KdfParamsOutOfRange)
        ));
    }

    #[test]
    fn hmac_verifies_with_data_key_and_is_unlock_path_agnostic() {
        // C9/G0.2: header_hmac verifies with the data key — no password/Argon2id involved.
        let h = sample_header();
        assert!(h.verify_hmac(&[0xAB; 32]).is_ok());
        // Wrong data key (or tampered header) → unambiguous HeaderTampered (factor already valid).
        assert!(matches!(
            h.verify_hmac(&[0xAC; 32]),
            Err(Error::HeaderTampered)
        ));
    }

    #[test]
    fn truncated_header_is_clean_error() {
        let h = sample_header();
        let bytes = h.serialize();
        for cut in [0usize, 3, 6, 30, bytes.len() - 1] {
            assert!(Header::parse(&bytes[..cut]).is_err());
        }
    }
}
