//! TPM 2.0 PCR-sealed OR stanza — constraint **C15**.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use secrecy::Secret;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::format::stanza::{kind, Stanza};
use crate::memory::DataKey;
use crate::{Error, Result};

use super::{WRAPPED_KEY_LEN, WRAP_NONCE_LEN};

/// HKDF info for TPM hardware wrapping (constraint C15).
pub const TPM_WRAP_INFO: &[u8] = b"vault-tpm-wrap-v1";
/// Default PCR index (Secure Boot state — UC-09 §3.3).
pub const DEFAULT_PCR_INDEX: u32 = 7;
/// Maximum sealed blob size in stanza extra.
pub const MAX_SEALED_BLOB_LEN: usize = 2048;

/// Public TPM stanza tail fields (C15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmExtra {
    /// TPM PCR bank selector (v1 uses bank 0).
    pub pcr_bank: u8,
    /// Bit mask of PCR indices included in the seal policy.
    pub pcr_mask: u32,
    /// TPM2B sealed blob (bounded by [`MAX_SEALED_BLOB_LEN`]).
    pub sealed_blob: Vec<u8>,
}

impl TpmExtra {
    /// Serialize extra bytes (bank, mask, LE blob length, blob).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        if self.sealed_blob.len() > MAX_SEALED_BLOB_LEN {
            return Err(Error::BodyMalformed);
        }
        let len = u16::try_from(self.sealed_blob.len()).map_err(|_| Error::BodyMalformed)?;
        let mut out = Vec::with_capacity(1 + 4 + 2 + self.sealed_blob.len());
        out.push(self.pcr_bank);
        out.extend_from_slice(&self.pcr_mask.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.sealed_blob);
        Ok(out)
    }

    /// Parse extra from stanza tail (bounded).
    pub fn parse(extra: &[u8]) -> Result<Self> {
        if extra.len() < 1 + 4 + 2 {
            return Err(Error::BodyMalformed);
        }
        let pcr_bank = extra[0];
        let pcr_mask = u32::from_le_bytes([extra[1], extra[2], extra[3], extra[4]]);
        let blob_len = u16::from_le_bytes([extra[5], extra[6]]) as usize;
        if blob_len > MAX_SEALED_BLOB_LEN {
            return Err(Error::BodyMalformed);
        }
        if extra.len() != 7 + blob_len {
            return Err(Error::BodyMalformed);
        }
        Ok(TpmExtra {
            pcr_bank,
            pcr_mask,
            sealed_blob: extra[7..].to_vec(),
        })
    }

    /// PCR index from low set bit in mask (v1 uses single PCR).
    pub fn primary_pcr(&self) -> u32 {
        self.pcr_mask.trailing_zeros()
    }
}

fn tpm_wrapping_key(tpm_ikm: &[u8; 32], vault_id: &[u8; 16]) -> [u8; 32] {
    crypto::hkdf32(tpm_ikm, vault_id, TPM_WRAP_INFO)
}

/// Wrap the data key in a TPM OR stanza (C15).
pub fn wrap_tpm_stanza(
    data_key: &[u8; 32],
    tpm_ikm: &[u8; 32],
    vault_id: &[u8; 16],
    extra: &TpmExtra,
) -> Result<Stanza> {
    let mut wrapping_key = tpm_wrapping_key(tpm_ikm, vault_id);
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Crypto)?;
    let wrapped = cipher
        .encrypt(XNonce::from_slice(&nonce), &data_key[..])
        .map_err(|_| Error::Crypto)?;

    let extra_bytes = extra.serialize()?;
    let mut data = Vec::with_capacity(WRAP_NONCE_LEN + WRAPPED_KEY_LEN + extra_bytes.len());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&wrapped);
    data.extend_from_slice(&extra_bytes);
    Ok(Stanza {
        stanza_type: kind::TPM,
        data,
    })
}

/// Parse TPM extra from a stanza record.
pub fn tpm_extra(stanza: &Stanza) -> Result<TpmExtra> {
    if stanza.stanza_type != kind::TPM {
        return Err(Error::Crypto);
    }
    if stanza.data.len() < WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
        return Err(Error::HeaderAuth);
    }
    TpmExtra::parse(&stanza.data[WRAP_NONCE_LEN + WRAPPED_KEY_LEN..])
}

/// Unwrap the data key from a TPM stanza (C15).
pub fn unwrap_tpm_stanza(
    stanza: &Stanza,
    tpm_ikm: &[u8; 32],
    vault_id: &[u8; 16],
) -> Result<DataKey> {
    if stanza.stanza_type != kind::TPM {
        return Err(Error::Crypto);
    }
    if stanza.data.len() < WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
        return Err(Error::HeaderAuth);
    }
    let _extra = TpmExtra::parse(&stanza.data[WRAP_NONCE_LEN + WRAPPED_KEY_LEN..])?;
    let nonce = &stanza.data[..WRAP_NONCE_LEN];
    let wrapped = &stanza.data[WRAP_NONCE_LEN..WRAP_NONCE_LEN + WRAPPED_KEY_LEN];

    let mut wrapping_key = tpm_wrapping_key(tpm_ikm, vault_id);
    let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).map_err(|_| Error::Crypto)?;
    wrapping_key.zeroize();

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), wrapped)
            .map_err(|_| Error::HeaderAuth)?,
    );
    if plaintext.len() != 32 {
        return Err(Error::HeaderAuth);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    let secret = Secret::new(key);
    key.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn tpm_extra_round_trip() {
        let extra = TpmExtra {
            pcr_bank: 0,
            pcr_mask: 1 << DEFAULT_PCR_INDEX,
            sealed_blob: vec![1, 2, 3, 4],
        };
        let parsed = TpmExtra::parse(&extra.serialize().unwrap()).unwrap();
        assert_eq!(parsed, extra);
    }

    #[test]
    fn tpm_stanza_wrap_unwrap() {
        let vid = [0x55u8; 16];
        let ikm = [0x66u8; 32];
        let dk = [0x77u8; 32];
        let extra = TpmExtra {
            pcr_bank: 0,
            pcr_mask: 1 << 7,
            sealed_blob: vec![0xAB; 64],
        };
        let stanza = wrap_tpm_stanza(&dk, &ikm, &vid, &extra).unwrap();
        let out = unwrap_tpm_stanza(&stanza, &ikm, &vid).unwrap();
        assert_eq!(out.expose_secret(), &dk);
    }
}
