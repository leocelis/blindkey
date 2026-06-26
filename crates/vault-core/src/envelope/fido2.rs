//! FIDO2 OR stanza — constraints **C6**, **C14** (additive hardware factor).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use secrecy::Secret;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::format::stanza::{kind, Stanza};
use crate::memory::DataKey;
use crate::{Error, Result};

use super::{WRAP_NONCE_LEN, WRAPPED_KEY_LEN};

/// HKDF info for FIDO2 hardware wrapping (constraint C6 / C14).
pub const FIDO2_WRAP_INFO: &[u8] = b"vault-hw-wrap-v1";
/// Maximum credential id length in stanza extra (UC-09).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Maximum relying-party id length in stanza extra.
pub const MAX_RP_ID_LEN: usize = 253;

/// Public fields stored in the FIDO2 stanza after the wrapped key (C14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Extra {
    pub credential_id: Vec<u8>,
    pub relying_party_id: String,
    pub salt_hash: [u8; 32],
}

impl Fido2Extra {
    /// Serialize extra bytes (LE length-prefixed fields).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        if self.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(Error::BodyMalformed);
        }
        let rp_bytes = self.relying_party_id.as_bytes();
        if rp_bytes.is_empty() || rp_bytes.len() > MAX_RP_ID_LEN {
            return Err(Error::BodyMalformed);
        }
        let mut out = Vec::with_capacity(2 + self.credential_id.len() + 1 + rp_bytes.len() + 32);
        out.extend_from_slice(&(self.credential_id.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.credential_id);
        out.push(rp_bytes.len() as u8);
        out.extend_from_slice(rp_bytes);
        out.extend_from_slice(&self.salt_hash);
        Ok(out)
    }

    /// Parse extra from stanza tail (bounded).
    pub fn parse(extra: &[u8]) -> Result<Self> {
        if extra.len() < 2 + 1 + 32 {
            return Err(Error::BodyMalformed);
        }
        let cred_len = u16::from_le_bytes([extra[0], extra[1]]) as usize;
        if cred_len > MAX_CREDENTIAL_ID_LEN {
            return Err(Error::BodyMalformed);
        }
        let cred_start: usize = 2;
        let cred_end = cred_start
            .checked_add(cred_len)
            .ok_or(Error::BodyMalformed)?;
        if extra.len() < cred_end + 1 + 32 {
            return Err(Error::BodyMalformed);
        }
        let rp_len = extra[cred_end] as usize;
        if rp_len == 0 || rp_len > MAX_RP_ID_LEN {
            return Err(Error::BodyMalformed);
        }
        let rp_start = cred_end + 1;
        let rp_end = rp_start
            .checked_add(rp_len)
            .ok_or(Error::BodyMalformed)?;
        if extra.len() != rp_end + 32 {
            return Err(Error::BodyMalformed);
        }
        let rp_id = std::str::from_utf8(&extra[rp_start..rp_end])
            .map_err(|_| Error::BodyMalformed)?
            .to_string();
        let mut salt_hash = [0u8; 32];
        salt_hash.copy_from_slice(&extra[rp_end..]);
        Ok(Fido2Extra {
            credential_id: extra[cred_start..cred_end].to_vec(),
            relying_party_id: rp_id,
            salt_hash,
        })
    }
}

fn fido2_wrapping_key(prf_output: &[u8; 32], vault_id: &[u8; 16]) -> [u8; 32] {
    crypto::hkdf32(prf_output, vault_id, FIDO2_WRAP_INFO)
}

/// Wrap the data key in a FIDO2 OR stanza (C14).
pub fn wrap_fido2_stanza(
    data_key: &[u8; 32],
    prf_output: &[u8; 32],
    vault_id: &[u8; 16],
    extra: &Fido2Extra,
) -> Result<Stanza> {
    let mut wrapping_key = fido2_wrapping_key(prf_output, vault_id);
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
        stanza_type: kind::FIDO2,
        data,
    })
}

/// Parse FIDO2 extra from a stanza record.
pub fn fido2_extra(stanza: &Stanza) -> Result<Fido2Extra> {
    if stanza.stanza_type != kind::FIDO2 {
        return Err(Error::Crypto);
    }
    if stanza.data.len() < WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
        return Err(Error::HeaderAuth);
    }
    Fido2Extra::parse(&stanza.data[WRAP_NONCE_LEN + WRAPPED_KEY_LEN..])
}

/// Unwrap the data key from a FIDO2 stanza (C14).
pub fn unwrap_fido2_stanza(
    stanza: &Stanza,
    prf_output: &[u8; 32],
    vault_id: &[u8; 16],
) -> Result<DataKey> {
    if stanza.stanza_type != kind::FIDO2 {
        return Err(Error::Crypto);
    }
    if stanza.data.len() < WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
        return Err(Error::HeaderAuth);
    }
    let extra = Fido2Extra::parse(&stanza.data[WRAP_NONCE_LEN + WRAPPED_KEY_LEN..])?;
    if extra.salt_hash != vault_hardware_salt(vault_id) {
        return Err(Error::HeaderAuth);
    }
    let nonce = &stanza.data[..WRAP_NONCE_LEN];
    let wrapped = &stanza.data[WRAP_NONCE_LEN..WRAP_NONCE_LEN + WRAPPED_KEY_LEN];

    let mut wrapping_key = fido2_wrapping_key(prf_output, vault_id);
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

/// C6 salt recipe (duplicated here so vault-core tests do not depend on vault-hardware).
pub fn vault_hardware_salt(vault_id: &[u8; 16]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(vault_id);
    h.update(b"fido2-hw-v1");
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn fido2_extra_round_trip() {
        let extra = Fido2Extra {
            credential_id: vec![1, 2, 3],
            relying_party_id: "vault.local".into(),
            salt_hash: [0xAA; 32],
        };
        let parsed = Fido2Extra::parse(&extra.serialize().unwrap()).unwrap();
        assert_eq!(parsed, extra);
    }

    #[test]
    fn fido2_stanza_wrap_unwrap() {
        let vid = [0x11u8; 16];
        let prf = [0x22u8; 32];
        let dk = [0x33u8; 32];
        let extra = Fido2Extra {
            credential_id: vec![9, 8, 7],
            relying_party_id: "vault.local".into(),
            salt_hash: vault_hardware_salt(&vid),
        };
        let stanza = wrap_fido2_stanza(&dk, &prf, &vid, &extra).unwrap();
        let out = unwrap_fido2_stanza(&stanza, &prf, &vid).unwrap();
        assert_eq!(out.expose_secret(), &dk);
    }
}
