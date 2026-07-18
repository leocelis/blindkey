//! UC-23 sealed-file CLI — `vault seal` / `open` / `peek` (Phase B).

use std::io::Write;
use std::path::{Path, PathBuf};

use blindkey_core::sealed::{
    SealOptions, SealedContainer, SealedIoOpts, SealedUnlock, SEALED_OPEN_ERROR,
};
use blindkey_core::Error;
use zeroize::Zeroizing;

use super::{open_sealed_for_edit, pre_release_notice, write_vault, OpenOpts, USAGE_ERROR_PREFIX};
use crate::unlock_secret;

type CmdResult = Result<(), String>;

fn usage_err(msg: impl Into<String>) -> String {
    format!("{USAGE_ERROR_PREFIX} {}", msg.into())
}

fn map_open_err(e: Error) -> String {
    match e {
        Error::HeaderAuth => unlock_secret::auth_err("wrong password or tampered header"),
        Error::WrongContainerKind => "wrong container type for this command".to_string(),
        Error::SealedOpenFailed => SEALED_OPEN_ERROR.to_string(),
        Error::Io(e) => e.to_string(),
        _ => SEALED_OPEN_ERROR.to_string(),
    }
}

fn default_output_path(paths: &[PathBuf]) -> Result<PathBuf, String> {
    let first = paths
        .first()
        .ok_or_else(|| usage_err("seal requires at least one path"))?;
    if first.as_os_str() == "-" {
        return Ok(PathBuf::from("stdin.vltf"));
    }
    let stem = if first.is_dir() {
        first.file_name()
    } else {
        first.file_stem()
    }
    .ok_or_else(|| format!("cannot derive output name from {}", first.display()))?;
    Ok(PathBuf::from(format!("{}.vltf", stem.to_string_lossy())))
}

fn build_unlock<'a>(
    bytes: &[u8],
    password: &'a [u8],
    opts: &OpenOpts,
    keyfile_store: &'a mut Option<Zeroizing<Vec<u8>>>,
) -> Result<SealedUnlock<'a>, String> {
    if SealedContainer::requires_keyfile(bytes) && !opts.recovery {
        let kf_path = opts.keyfile.as_ref().ok_or_else(|| {
            "this container requires a keyfile — pass `--keyfile <PATH>` (or `--recovery` to use \
             the recovery code)"
                .to_string()
        })?;
        let kf = Zeroizing::new(
            std::fs::read(kf_path)
                .map_err(|e| format!("cannot read keyfile {}: {e}", kf_path.display()))?,
        );
        *keyfile_store = Some(kf);
        Ok(SealedUnlock {
            password,
            keyfile: keyfile_store.as_ref().map(|v| v.as_slice()),
        })
    } else {
        Ok(SealedUnlock::password_only(password))
    }
}

fn open_sealed<R, F>(bytes: &[u8], password: &[u8], opts: &OpenOpts, f: F) -> Result<R, String>
where
    F: FnOnce(
        &SealedUnlock<'_>,
        Option<&mut dyn FnMut(&[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Error>>,
    ) -> Result<R, Error>,
{
    let mut keyfile_store = None;
    let unlock = build_unlock(bytes, password, opts, &mut keyfile_store)?;
    if SealedContainer::requires_yubikey(bytes) && !opts.recovery {
        eprintln!("Touch your YubiKey…");
        let mut respond = |challenge: &[u8; 32]| -> Result<Zeroizing<Vec<u8>>, Error> {
            blindkey_hardware::yubikey::challenge_response(challenge).map_err(Error::Hardware)
        };
        f(&unlock, Some(&mut respond)).map_err(map_open_err)
    } else {
        f(&unlock, None).map_err(map_open_err)
    }
}

pub fn cmd_seal(
    paths: Vec<PathBuf>,
    output: Option<PathBuf>,
    append: bool,
    seal_opts: SealOptions,
    open_opts: &OpenOpts,
) -> CmdResult {
    let unlock = &open_opts.unlock;
    if paths.is_empty() {
        return Err(usage_err("seal requires at least one path"));
    }

    let stdin_mode = paths.len() == 1 && paths[0].as_os_str() == "-";
    if stdin_mode && unlock.password_stdin {
        return Err(usage_err(
            "cannot combine `seal -` with --password-stdin — use TTY, --password-fd, or \
             BLINDKEY_PASSWORD_FILE for the passphrase; stdin carries payload only",
        ));
    }
    if append && stdin_mode {
        return Err(usage_err("cannot combine `seal -` with --append"));
    }
    if !stdin_mode {
        for p in &paths {
            if !p.exists() {
                return Err(format!("{}: no such file or directory", p.display()));
            }
        }
    }

    let out = output.unwrap_or_else(|| default_output_path(&paths).unwrap());
    if append {
        if !out.is_file() {
            return Err(format!(
                "--append requires an existing sealed container at {}",
                out.display()
            ));
        }
    } else if out.exists() {
        return Err(format!(
            "refusing to overwrite existing file {}",
            out.display()
        ));
    }

    pre_release_notice();

    if append {
        let (container, original, _password) = open_sealed_for_edit(&out, open_opts)?;
        let path_refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let mut io = SealedIoOpts::default();
        let bytes = container
            .append_paths(&original, &path_refs, &mut io)
            .map_err(|e| e.to_string())?;
        write_vault(&out, &bytes)?;
        eprintln!("Appended {} path(s) → {}", paths.len(), out.display());
        return Ok(());
    }

    let password = unlock_secret::read_master_password(true, unlock)?;
    eprintln!("Deriving key (Argon2id)…");

    let bytes = if stdin_mode {
        let mut stdin = std::io::stdin();
        let mut io = SealedIoOpts::default();
        SealedContainer::seal_reader(password.as_bytes(), seal_opts, "-", &mut stdin, &mut io)
            .map_err(|e| e.to_string())?
    } else {
        let container =
            SealedContainer::create(password.as_bytes(), seal_opts).map_err(|e| e.to_string())?;
        let path_refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        container
            .seal_paths(&path_refs)
            .map_err(|e| e.to_string())?
    };

    write_vault(&out, &bytes)?;
    if stdin_mode {
        eprintln!("Sealed stdin → {}", out.display());
    } else {
        eprintln!("Sealed {} → {}", paths.len(), out.display());
    }
    Ok(())
}

pub fn cmd_open(file: PathBuf, dest: Option<PathBuf>, stdout: bool, opts: &OpenOpts) -> CmdResult {
    if !file.is_file() {
        return Err(format!("{}: not a sealed container file", file.display()));
    }
    let bytes = std::fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;

    if stdout {
        eprintln!(
            "WARNING: file contents written to stdout; ensure no AI agent or untrusted process \
             captures this stream."
        );
        open_sealed(bytes.as_slice(), password.as_bytes(), opts, |unlock, yk| {
            let body = SealedContainer::read_single_stdout_with(&bytes, unlock, yk)?;
            std::io::stdout().write_all(&body).map_err(Error::Io)?;
            Ok(())
        })?;
        return Ok(());
    }

    let dest = dest.unwrap_or_else(|| PathBuf::from("."));
    open_sealed(bytes.as_slice(), password.as_bytes(), opts, |unlock, yk| {
        let mut io = SealedIoOpts::default();
        SealedContainer::open_to_dir_with(&bytes, unlock, &dest, &mut io, yk)
    })?;
    eprintln!("Extracted {} → {}", file.display(), dest.display());
    Ok(())
}

pub fn cmd_peek(file: PathBuf, opts: &OpenOpts) -> CmdResult {
    if !file.is_file() {
        return Err(format!("{}: not a sealed container file", file.display()));
    }
    let bytes = std::fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;

    let entries = open_sealed(bytes.as_slice(), password.as_bytes(), opts, |unlock, yk| {
        if let Some(respond) = yk {
            SealedContainer::peek_entries_with_yubikey(&bytes, unlock, Some(respond))
        } else {
            SealedContainer::peek_entries(&bytes, unlock)
        }
    })?;

    if entries.is_empty() {
        eprintln!("(empty container)");
        return Ok(());
    }

    let mut max_path = 4usize;
    for e in &entries {
        max_path = max_path.max(e.path.len());
    }
    for e in &entries {
        println!(
            "{:<width$}  {:>10}  {:>8o}  {}",
            e.path,
            e.size,
            e.mode & 0o7777,
            e.mtime,
            width = max_path
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_uses_stem() {
        let p = default_output_path(&[PathBuf::from("report.pdf")]).unwrap();
        assert_eq!(p, PathBuf::from("report.vltf"));
        let d = default_output_path(&[PathBuf::from("/tmp/myproject")]).unwrap();
        assert_eq!(d, PathBuf::from("myproject.vltf"));
        let stdin = default_output_path(&[PathBuf::from("-")]).unwrap();
        assert_eq!(stdin, PathBuf::from("stdin.vltf"));
    }
}
