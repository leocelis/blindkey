//! Time-based one-time passwords (TOTP, RFC 6238 over HOTP RFC 4226) for 2FA codes.
//!
//! An entry may carry an `otp_secret` (a Protected, base32-encoded shared secret as used by
//! `otpauth://` / authenticator apps). This module turns it into the current 6-digit code so Vault
//! can stand in for a separate authenticator app. The standard parameters are used (HMAC-**SHA-1**,
//! 6 digits, 30 s period) — SHA-1 here is the RFC-mandated TOTP construction, not an at-rest hash.
//!
//! The decoded key lives only in a zeroizing buffer for the duration of one HMAC.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

/// TOTP time step in seconds (RFC 6238 default).
const PERIOD: u64 = 30;
/// Number of code digits (RFC 6238 default).
const DIGITS: u32 = 6;

/// A generated code plus how many seconds it remains valid (for a UI countdown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    /// The zero-padded 6-digit code.
    pub code: String,
    /// Seconds until the code rolls over.
    pub valid_for_secs: u64,
}

/// Generate the TOTP code for `secret_base32` at a specific unix time (constraint: RFC 6238).
pub fn generate_at(secret_base32: &[u8], unix_secs: u64) -> Result<TotpCode> {
    let key = base32_decode(secret_base32).ok_or(Error::Crypto)?;
    let counter = unix_secs / PERIOD;
    let code = hotp(&key, counter)?;
    Ok(TotpCode {
        code,
        valid_for_secs: PERIOD - (unix_secs % PERIOD),
    })
}

/// Generate the TOTP code for `secret_base32` at the current time.
pub fn generate_now(secret_base32: &[u8]) -> Result<TotpCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    generate_at(secret_base32, now)
}

/// HOTP (RFC 4226): HMAC-SHA1 of the 8-byte big-endian counter, dynamically truncated to `DIGITS`.
fn hotp(key: &[u8], counter: u64) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|_| Error::Crypto)?;
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes(); // 20 bytes
    let offset = (hs[19] & 0x0f) as usize;
    let bin = (u32::from(hs[offset] & 0x7f) << 24)
        | (u32::from(hs[offset + 1]) << 16)
        | (u32::from(hs[offset + 2]) << 8)
        | u32::from(hs[offset + 3]);
    let code = bin % 10u32.pow(DIGITS);
    Ok(format!("{code:0width$}", width = DIGITS as usize))
}

/// Decode RFC 4648 base32 (case-insensitive; ignores spaces, `-`, and `=` padding). Returns the
/// raw key bytes in a zeroizing buffer, or `None` on an invalid character / empty input.
fn base32_decode(input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut acc = 0u32;
    let mut nbits = 0u32;
    let mut out = Zeroizing::new(Vec::new());
    for &b in input {
        let c = b.to_ascii_uppercase();
        if matches!(c, b'=' | b' ' | b'\t' | b'\n' | b'\r' | b'-') {
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test seed for SHA-1 ("12345678901234567890" base32-encoded).
    const RFC_SEED: &[u8] = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_test_vectors_sha1_6_digits() {
        // The RFC publishes 8-digit codes; the trailing 6 are our 6-digit output.
        assert_eq!(generate_at(RFC_SEED, 59).unwrap().code, "287082");
        assert_eq!(generate_at(RFC_SEED, 1_111_111_109).unwrap().code, "081804");
        assert_eq!(generate_at(RFC_SEED, 1_234_567_890).unwrap().code, "005924");
        assert_eq!(generate_at(RFC_SEED, 2_000_000_000).unwrap().code, "279037");
    }

    #[test]
    fn code_is_six_digits_and_valid_window_bounded() {
        let c = generate_at(RFC_SEED, 45).unwrap();
        assert_eq!(c.code.len(), 6);
        assert!(c.code.bytes().all(|b| b.is_ascii_digit()));
        // at t=45 → 15s into the second step → 15s remain
        assert_eq!(c.valid_for_secs, 15);
    }

    #[test]
    fn base32_is_case_and_space_insensitive() {
        let a = generate_at(b"gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 59).unwrap();
        assert_eq!(a.code, "287082");
    }

    #[test]
    fn invalid_secret_errors() {
        assert!(generate_at(b"not base32!!!", 59).is_err());
        assert!(generate_at(b"", 59).is_err());
    }
}
