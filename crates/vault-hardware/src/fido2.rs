//! FIDO2 hardware path via `fido2-token` (libfido2 CLI) — constraint **C14**.
//!
//! Mirrors the YubiKey/`ykman` subprocess pattern: no `unsafe`, runtime dependency on
//! `fido2-token` from libfido2-tools.

use std::path::{Path, PathBuf};
use std::process::Command;

use getrandom::getrandom;
use vault_core::envelope::fido2::Fido2Extra;

use crate::fido2_salt::authenticator_salt;

const DEFAULT_RP_ID: &str = "vault.local";

/// Whether `fido2-token` is on PATH.
pub fn available() -> bool {
    Command::new("fido2-token")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// First FIDO device path from `fido2-token -L`, or error.
pub fn first_device() -> Result<String, String> {
    let out = Command::new("fido2-token")
        .arg("-L")
        .output()
        .map_err(|_| tool_missing())?;
    if !out.status.success() {
        return Err(format!("fido2-token -L failed: {}", stderr(&out)));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("dev:") {
            return Ok(line.trim_start_matches("dev:").trim().to_string());
        }
        if line.starts_with("/dev/") {
            return Ok(line.to_string());
        }
    }
    Err("no FIDO2 device detected — plug in a security key".into())
}

/// Enroll: create credential with hmac-secret and return stanza extra + PRF output for wrapping.
pub fn enroll(vault_id: &[u8; 16], rp_id: Option<&str>) -> Result<(Fido2Extra, [u8; 32]), String> {
    let rp = rp_id.unwrap_or(DEFAULT_RP_ID);
    let dev = first_device()?;
    let salt_hash = authenticator_salt(vault_id);
    let dir = temp_dir()?;
    let salt_path = dir.join("salt.bin");
    let cred_path = dir.join("cred_id.bin");
    std::fs::write(&salt_path, salt_hash).map_err(|e| e.to_string())?;

    let out = Command::new("fido2-token")
        .args([
            "-M",
            "-d",
            &dev,
            "cred",
            "make",
            "-h",
            "-r",
            "-i",
            cred_path.to_str().unwrap(),
            "-R",
            rp,
        ])
        .output()
        .map_err(|_| tool_missing())?;
    if !out.status.success() {
        return Err(format!(
            "FIDO2 enrollment failed (does the key support hmac-secret?): {}",
            stderr(&out)
        ));
    }

    let credential_id = std::fs::read(&cred_path).map_err(|e| e.to_string())?;
    let prf = assert_prf_internal(&dev, rp, &credential_id, &salt_hash, &salt_path)?;

    let extra = Fido2Extra {
        credential_id,
        relying_party_id: rp.to_string(),
        salt_hash,
    };
    Ok((extra, prf))
}

/// Unlock: CTAP2 assertion with hmac-secret for an enrolled stanza.
pub fn assert_prf(extra: &Fido2Extra) -> Result<[u8; 32], String> {
    let dev = first_device()?;
    let dir = temp_dir()?;
    let salt_path = dir.join("salt.bin");
    std::fs::write(&salt_path, extra.salt_hash).map_err(|e| e.to_string())?;
    assert_prf_internal(
        &dev,
        &extra.relying_party_id,
        &extra.credential_id,
        &extra.salt_hash,
        &salt_path,
    )
}

fn assert_prf_internal(
    dev: &str,
    rp_id: &str,
    credential_id: &[u8],
    _salt_hash: &[u8; 32],
    salt_path: &Path,
) -> Result<[u8; 32], String> {
    let dir = salt_path.parent().unwrap();
    let cred_path = dir.join("cred_id.bin");
    std::fs::write(&cred_path, credential_id).map_err(|e| e.to_string())?;
    let hmac_path = dir.join("hmac.bin");

    let out = Command::new("fido2-token")
        .args([
            "-M",
            "-d",
            dev,
            "cred",
            "auth",
            "-h",
            hmac_path.to_str().unwrap(),
            "-s",
            salt_path.to_str().unwrap(),
            "-a",
            cred_path.to_str().unwrap(),
            "-R",
            rp_id,
        ])
        .output()
        .map_err(|_| tool_missing())?;
    if !out.status.success() {
        return Err(format!(
            "FIDO2 assertion failed (wrong key or touch skipped?): {}",
            stderr(&out)
        ));
    }
    let secret = std::fs::read(&hmac_path).map_err(|e| e.to_string())?;
    if secret.len() != 32 {
        return Err("FIDO2 hmac-secret output was not 32 bytes".into());
    }
    let mut prf = [0u8; 32];
    prf.copy_from_slice(&secret);
    Ok(prf)
}

fn temp_dir() -> Result<PathBuf, String> {
    let mut p = std::env::temp_dir();
    let mut rnd = [0u8; 8];
    getrandom(&mut rnd).map_err(|e| e.to_string())?;
    p.push(format!("vault-fido2-{}", hex8(&rnd)));
    std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(p)
}

fn hex8(b: &[u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn tool_missing() -> String {
    "fido2-token not found — install libfido2 / libfido2-tools (e.g. `apt install libfido2-dev` \
     or `brew install libfido2`)"
        .into()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_does_not_panic() {
        let _ = available();
    }
}
