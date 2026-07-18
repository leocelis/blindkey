//! Keyfile 2FA helpers for the GUI shell (UC-09 / UC-21) — thin wrappers, crypto in blindkey-core.

use std::io::Write;
use std::path::Path;

use blindkey_core::gen::{password as gen_password, Charset};
use zeroize::Zeroizing;

/// A high-entropy recovery code: 24 alphanumerics grouped 4-by-4 (matches CLI).
pub fn recovery_code() -> Result<String, String> {
    let raw = gen_password(Charset::Alnum, 24).map_err(|e| e.to_string())?;
    let chars: Vec<char> = raw.chars().collect();
    Ok(chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-"))
}

/// Write a new keyfile atomically with mode 0600 (create-new only).
pub fn write_keyfile(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
    }
    let mut oo = std::fs::OpenOptions::new();
    oo.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.mode(0o600);
    }
    let mut f = oo.open(path).map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().ok();
    Ok(())
}

/// Load keyfile bytes or generate a fresh 32-byte CSPRNG file at `path`.
pub fn load_or_create_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    if path.exists() {
        return Ok(Zeroizing::new(
            std::fs::read(path).map_err(|e| e.to_string())?,
        ));
    }
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
    write_keyfile(path, &bytes)?;
    Ok(Zeroizing::new(bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_has_groups() {
        let c = recovery_code().unwrap();
        assert!(c.contains('-'));
        assert_eq!(c.replace('-', "").len(), 24);
    }
}
