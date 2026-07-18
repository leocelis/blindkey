//! TPM 2.0 PCR seal via `tpm2-tools` subprocess — constraint **C15**.

use std::path::PathBuf;
use std::process::Command;

use blindkey_core::envelope::tpm::{TpmExtra, MAX_SEALED_BLOB_LEN};
use getrandom::getrandom;
use zeroize::Zeroizing;

use crate::tpm_policy::PCR_MISMATCH_MESSAGE;

/// Whether core tpm2-tools are on PATH.
pub fn available() -> bool {
    Command::new("tpm2_pcrread")
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && Command::new("tpm2_create")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

/// Seal a fresh `tpm_ikm` to the given PCR (default PCR 7).
pub fn seal(pcr_index: u32) -> Result<(Zeroizing<[u8; 32]>, TpmExtra), String> {
    let dir = temp_dir()?;
    let mut ikm = [0u8; 32];
    getrandom(&mut ikm).map_err(|e| e.to_string())?;
    let ikm_path = dir.join("tpm_ikm.bin");
    std::fs::write(&ikm_path, ikm).map_err(|e| e.to_string())?;

    let policy_path = dir.join("policy.dat");
    let primary_ctx = dir.join("primary.ctx");
    let sealed_pub = dir.join("sealed.pub");
    let sealed_priv = dir.join("sealed.priv");
    let sealed_ctx = dir.join("sealed.ctx");
    let sealed_blob = dir.join("sealed.blob");

    let pcr_sel = format!("sha256:{pcr_index}");

    run(&["tpm2_startauthsession", "-S", "session.dat"], &dir)?;
    run(
        &[
            "tpm2_policypcr",
            "-S",
            "session.dat",
            "-L",
            policy_path.to_str().unwrap(),
            "-l",
            &pcr_sel,
        ],
        &dir,
    )?;
    run(
        &[
            "tpm2_createprimary",
            "-C",
            "o",
            "-g",
            "sha256",
            "-G",
            "rsa",
            "-c",
            primary_ctx.to_str().unwrap(),
        ],
        &dir,
    )?;
    let create_out = Command::new("tpm2_create")
        .current_dir(&dir)
        .args([
            "-C",
            primary_ctx.to_str().unwrap(),
            "-g",
            "sha256",
            "-G",
            "keyedhash",
            "-i",
            ikm_path.to_str().unwrap(),
            "-L",
            policy_path.to_str().unwrap(),
            "-u",
            sealed_pub.to_str().unwrap(),
            "-v",
            sealed_priv.to_str().unwrap(),
        ])
        .output()
        .map_err(|_| tool_missing())?;
    if !create_out.status.success() {
        return Err(format!("tpm2_create failed: {}", stderr(&create_out)));
    }
    run(
        &[
            "tpm2_load",
            "-C",
            primary_ctx.to_str().unwrap(),
            "-u",
            sealed_pub.to_str().unwrap(),
            "-r",
            sealed_priv.to_str().unwrap(),
            "-c",
            sealed_ctx.to_str().unwrap(),
        ],
        &dir,
    )?;
    run(
        &[
            "tpm2_evictcontrol",
            "-C",
            "o",
            "-c",
            sealed_ctx.to_str().unwrap(),
            "-o",
            "0x81010001",
        ],
        &dir,
    )
    .ok(); // best-effort persist

    // Pack pub+priv for stanza storage (simplified blob).
    let mut blob = Vec::new();
    let pub_bytes = std::fs::read(&sealed_pub).map_err(|e| e.to_string())?;
    let priv_bytes = std::fs::read(&sealed_priv).map_err(|e| e.to_string())?;
    if pub_bytes.len() + priv_bytes.len() > MAX_SEALED_BLOB_LEN {
        return Err("sealed TPM object too large for stanza".into());
    }
    blob.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(&pub_bytes);
    blob.extend_from_slice(&priv_bytes);
    std::fs::write(&sealed_blob, &blob).map_err(|e| e.to_string())?;

    let extra = TpmExtra {
        pcr_bank: 0,
        pcr_mask: 1u32 << pcr_index,
        sealed_blob: blob,
    };
    Ok((Zeroizing::new(ikm), extra))
}

/// Unseal `tpm_ikm` from stanza extra; PCR mismatch → C15 message.
pub fn unseal(extra: &TpmExtra) -> Result<Zeroizing<[u8; 32]>, String> {
    let pcr = extra.primary_pcr();
    let dir = temp_dir()?;
    let policy_path = dir.join("policy.dat");
    let primary_ctx = dir.join("primary.ctx");
    let sealed_ctx = dir.join("sealed.ctx");
    let out_path = dir.join("out.bin");

    let pcr_sel = format!("sha256:{pcr}");
    run(
        &[
            "tpm2_policypcr",
            "-S",
            "session.dat",
            "-L",
            policy_path.to_str().unwrap(),
            "-l",
            &pcr_sel,
        ],
        &dir,
    )
    .map_err(|_| pcr_mismatch())?;

    let pub_len = u32::from_le_bytes(extra.sealed_blob[0..4].try_into().unwrap()) as usize;
    if extra.sealed_blob.len() < 4 + pub_len {
        return Err("corrupt TPM stanza blob".into());
    }
    let pub_bytes = &extra.sealed_blob[4..4 + pub_len];
    let priv_bytes = &extra.sealed_blob[4 + pub_len..];
    let sealed_pub = dir.join("sealed.pub");
    let sealed_priv = dir.join("sealed.priv");
    std::fs::write(&sealed_pub, pub_bytes).map_err(|e| e.to_string())?;
    std::fs::write(&sealed_priv, priv_bytes).map_err(|e| e.to_string())?;

    run(
        &[
            "tpm2_createprimary",
            "-C",
            "o",
            "-g",
            "sha256",
            "-G",
            "rsa",
            "-c",
            primary_ctx.to_str().unwrap(),
        ],
        &dir,
    )
    .map_err(|_| pcr_mismatch())?;
    run(
        &[
            "tpm2_load",
            "-C",
            primary_ctx.to_str().unwrap(),
            "-u",
            sealed_pub.to_str().unwrap(),
            "-r",
            sealed_priv.to_str().unwrap(),
            "-c",
            sealed_ctx.to_str().unwrap(),
        ],
        &dir,
    )
    .map_err(|_| pcr_mismatch())?;

    let unseal_out = Command::new("tpm2_unseal")
        .current_dir(&dir)
        .args([
            "-c",
            sealed_ctx.to_str().unwrap(),
            "-p",
            &format!("pcr:{pcr_sel}"),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|_| tool_missing())?;
    if !unseal_out.status.success() {
        return Err(pcr_mismatch());
    }
    let raw = std::fs::read(&out_path).map_err(|e| e.to_string())?;
    if raw.len() != 32 {
        return Err("TPM unseal returned wrong length".into());
    }
    let mut ikm = [0u8; 32];
    ikm.copy_from_slice(&raw);
    Ok(Zeroizing::new(ikm))
}

fn pcr_mismatch() -> String {
    PCR_MISMATCH_MESSAGE.to_string()
}

fn run(args: &[&str], dir: &PathBuf) -> Result<(), String> {
    if args.is_empty() {
        return Ok(());
    }
    let out = Command::new(args[0])
        .current_dir(dir)
        .args(&args[1..])
        .output()
        .map_err(|_| tool_missing())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(stderr(&out))
    }
}

fn temp_dir() -> Result<PathBuf, String> {
    let mut p = std::env::temp_dir();
    let mut rnd = [0u8; 8];
    getrandom(&mut rnd).map_err(|e| e.to_string())?;
    p.push(format!(
        "vault-tpm-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(p)
}

fn tool_missing() -> String {
    "tpm2-tools not found — install tpm2-tools (Linux) or TPM 2.0 TSS (Windows)".into()
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
