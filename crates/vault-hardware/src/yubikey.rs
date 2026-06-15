//! YubiKey HMAC-SHA1 challenge-response via the `ykman` CLI (subprocess).
//!
//! Why a subprocess and not a libusb FFI: it mirrors how the rest of Vault already shells out to
//! OS tools (the clipboard `pbcopy`/`xclip` path), so it needs **no extra build dependency, no C
//! library, and no `unsafe`** — the crate keeps `#![forbid(unsafe_code)]`. The cost is a runtime
//! dependency on `ykman` (YubiKey Manager CLI), only when you opt into YubiKey 2FA.
//!
//! The product drives `ykman` for the user (programming slot 2 and computing responses); the user
//! never types `ykman` commands by hand. Older YubiKeys (4 / NEO) have no FIDO2 `hmac-secret`, so
//! HMAC-SHA1 challenge-response on slot 2 is the supported path (KeePassXC lineage, UC-09 §2).

use std::process::Command;

use zeroize::Zeroizing;

/// The OTP slot used for challenge-response (slot 1 keeps the factory Yubico-OTP credential).
const SLOT: &str = "2";

/// Whether `ykman` is installed and at least one YubiKey is connected.
pub fn available() -> bool {
    match Command::new("ykman").arg("list").output() {
        Ok(out) => out.status.success() && !out.stdout.is_empty(),
        Err(_) => false,
    }
}

/// Program slot 2 for HMAC-SHA1 challenge-response with a fresh random secret, touch-required.
///
/// This is the product-owned enrollment step (the user does not run `ykman` by hand). It overwrites
/// slot 2 — the caller must have confirmed with the user first. The generated secret stays on the
/// key; Vault only ever sends challenges and reads responses.
pub fn program_chalresp_slot2() -> Result<(), String> {
    let out = Command::new("ykman")
        .args(["otp", "chalresp", "--generate", "--touch", "--force", SLOT])
        .output()
        .map_err(|_| ykman_missing())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("ykman could not program slot 2: {}", stderr(&out)))
    }
}

/// Compute the YubiKey's HMAC-SHA1 response to `challenge`. Blocks while the user taps the key.
/// Returns the raw response bytes (zeroizing).
pub fn challenge_response(challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let hex = to_hex(challenge);
    let out = Command::new("ykman")
        .args(["otp", "calculate", SLOT, &hex])
        .output()
        .map_err(|_| ykman_missing())?;
    if !out.status.success() {
        return Err(format!(
            "ykman challenge-response failed (is slot 2 set up? is the key plugged in?): {}",
            stderr(&out)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    from_hex(text.trim()).ok_or_else(|| "could not parse the YubiKey response".to_string())
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn ykman_missing() -> String {
    "ykman not found — install YubiKey Manager (e.g. `brew install ykman`) to use a YubiKey".into()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_string()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[allow(clippy::manual_is_multiple_of)] // `% 2` keeps the crate 1.82-source-clean (see stream.rs)
fn from_hex(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let data = [0x00u8, 0x0f, 0xa5, 0xff, 0x10, 0x55];
        let hex = to_hex(&data);
        assert_eq!(hex, "000fa5ff1055");
        assert_eq!(&from_hex(&hex).unwrap()[..], &data[..]);
    }

    #[test]
    fn from_hex_rejects_malformed() {
        assert!(from_hex("").is_none());
        assert!(from_hex("abc").is_none()); // odd length
        assert!(from_hex("zz").is_none()); // non-hex
        assert!(from_hex("00 11").is_none()); // embedded space
    }

    #[test]
    fn available_does_not_panic() {
        // ykman is usually absent in CI; just assert it returns without panicking.
        let _ = available();
    }
}
