//! Non-interactive master-password channels (UC-05 §3.2, C31).
//!
//! Priority: `--password-fd` → `--password-stdin` → `VAULT_PASSWORD_FILE` → TTY prompt.
//! Secrets are never read from argv.

use std::io::{BufRead, BufReader, IsTerminal, Read};
use std::path::Path;
use zeroize::Zeroizing;

pub const AUTH_ERROR_PREFIX: &str = "auth:";

pub fn auth_err(msg: impl Into<String>) -> String {
    format!("{AUTH_ERROR_PREFIX} {}", msg.into())
}

/// Global unlock flags (mirrors clap on `Cli`).
#[derive(Debug, Clone, Default)]
pub struct UnlockSecretOpts {
    pub password_fd: Option<u32>,
    pub password_stdin: bool,
}

/// Read the master password for unlock/init. `confirm_match` applies only on an interactive TTY.
pub fn read_master_password(
    confirm_match: bool,
    opts: &UnlockSecretOpts,
) -> Result<Zeroizing<String>, String> {
    if let Some(fd) = opts.password_fd {
        return read_password_from_fd(fd as i32);
    }
    if opts.password_stdin {
        return read_line_from_stdin();
    }
    if let Ok(path) = std::env::var("VAULT_PASSWORD_FILE") {
        if !path.is_empty() {
            return read_password_file(Path::new(&path));
        }
    }
    if !std::io::stdin().is_terminal() {
        return Err(auth_err(
            "non-interactive session — supply --password-fd, --password-stdin, or \
             VAULT_PASSWORD_FILE",
        ));
    }
    prompt_tty(confirm_match)
}

fn read_line_from_stdin() -> Result<Zeroizing<String>, String> {
    read_line_from_reader(BufReader::new(std::io::stdin()))
}

fn read_password_from_fd(fd: i32) -> Result<Zeroizing<String>, String> {
    let line = vault_sys::read_line_from_fd(fd)
        .map_err(|e| format!("cannot read master password from fd {fd}: {e}"))?;
    if line.is_empty() {
        return Err(auth_err("empty master password"));
    }
    Ok(Zeroizing::new(line))
}

fn read_line_from_reader<R: Read>(reader: R) -> Result<Zeroizing<String>, String> {
    let mut buf = BufReader::new(reader);
    let mut line = Zeroizing::new(String::new());
    buf.read_line(&mut line)
        .map_err(|e| format!("cannot read master password: {e}"))?;
    if line.is_empty() {
        return Err(auth_err("empty master password"));
    }
    Ok(Zeroizing::new(
        line.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    #[cfg(unix)]
    check_mode_0600(path)?;
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read VAULT_PASSWORD_FILE {}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(auth_err("VAULT_PASSWORD_FILE is empty"));
    }
    let line = bytes
        .split(|&b| b == b'\n' || b == b'\r')
        .next()
        .unwrap_or(&bytes);
    Ok(Zeroizing::new(
        std::str::from_utf8(line)
            .map_err(|_| "VAULT_PASSWORD_FILE must be valid UTF-8".to_string())?
            .to_string(),
    ))
}

#[cfg(unix)]
fn check_mode_0600(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat VAULT_PASSWORD_FILE {}: {e}", path.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "VAULT_PASSWORD_FILE {} must be mode 0600 (no group/other permissions)",
            path.display()
        ));
    }
    Ok(())
}

fn prompt_tty(confirm_match: bool) -> Result<Zeroizing<String>, String> {
    let p = Zeroizing::new(
        rpassword::prompt_password("Master password: ").map_err(|e| e.to_string())?,
    );
    if confirm_match {
        let again = Zeroizing::new(
            rpassword::prompt_password("Confirm password: ").map_err(|e| e.to_string())?,
        );
        if *p != *again {
            return Err("passwords do not match".to_string());
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn vault_password_file_requires_0600_on_unix() {
        let dir = std::env::temp_dir().join(format!("vault-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&path)
                .unwrap();
            f.write_all(b"secret\n").unwrap();
        }
        let err = read_password_file(&path).unwrap_err();
        assert!(err.contains("0600"), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn vault_password_file_reads_first_line() {
        let dir = std::env::temp_dir().join(format!("vault-pw2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(b"line-one\nignored\n").unwrap();
        }
        let pw = read_password_file(&path).unwrap();
        assert_eq!(pw.as_str(), "line-one");
        std::fs::remove_dir_all(dir).ok();
    }
}
