//! Command handlers (constraints C20–C22, C27, C29, C30).
//!
//! File I/O, the no-echo password prompt, and clipboard delivery live here — the thin shell over
//! `vault_core`. The same `vault_core` operations (`create`/`open`/`save`/`import`/`search`) will be
//! driven by the future desktop app, so all logic that touches secrets stays in the core.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use vault_core::format::entry::{CustomValue, Entry, Protected};
use vault_core::gen::{password as gen_password, Charset};
use vault_core::Vault;
use zeroize::Zeroizing;

use crate::Command;

type CmdResult = Result<(), String>;

/// Route a parsed command to its handler.
pub fn dispatch(vault_opt: Option<PathBuf>, command: Command) -> CmdResult {
    match command {
        Command::Init {
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
        } => cmd_init(&vault_path(vault_opt)?, kdf_m_cost, kdf_t_cost, kdf_p_cost),
        Command::Import { format, source } => cmd_import(&vault_path(vault_opt)?, &format, &source),
        Command::Ls { search } => cmd_ls(&vault_path(vault_opt)?, search.as_deref()),
        Command::Get {
            name,
            field,
            stdout,
            timeout,
        } => cmd_get(&vault_path(vault_opt)?, &name, &field, stdout, timeout),
        Command::HoldClipboard { secs } => run_clipboard_holder(secs),
        Command::Gen {
            length,
            charset,
            words,
        } => cmd_gen(length, &charset, words),
        Command::Add { name } => cmd_add(&vault_path(vault_opt)?, &name),
        Command::Edit { name } => cmd_edit(&vault_path(vault_opt)?, &name),
        Command::Rm { name } => cmd_rm(&vault_path(vault_opt)?, &name),
        Command::Lock | Command::Tune => Err("that command is not implemented yet".to_string()),
    }
}

// ─── commands ──────────────────────────────────────────────────────────────

fn cmd_init(path: &Path, m_cost: u32, t_cost: u32, p_cost: u32) -> CmdResult {
    if path.exists() {
        return Err(format!(
            "a vault already exists at {} (refusing to overwrite)",
            path.display()
        ));
    }
    let password = prompt_password(true)?;
    eprintln!("Deriving key (Argon2id)…");
    let mut vault =
        Vault::create(password.as_bytes(), m_cost, t_cost, p_cost).map_err(|e| e.to_string())?;
    let bytes = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &bytes)?;
    eprintln!("Created vault at {}", path.display());
    Ok(())
}

fn cmd_import(path: &Path, format: &str, source: &Path) -> CmdResult {
    if format != "raw" {
        return Err(format!(
            "unknown import format {format:?} (only `raw` is supported)"
        ));
    }
    let text = Zeroizing::new(
        std::fs::read_to_string(source)
            .map_err(|e| format!("cannot read {}: {e}", source.display()))?,
    );
    let result = vault_core::import::parse_raw(&text);
    if result.entries.is_empty() {
        return Err("no secrets found in that file".to_string());
    }

    // Masked review (never print the secret — C27).
    eprintln!(
        "Parsed {} entr{} ({} block{} skipped):",
        result.entries.len(),
        if result.entries.len() == 1 {
            "y"
        } else {
            "ies"
        },
        result.blocks_skipped,
        if result.blocks_skipped == 1 { "" } else { "s" },
    );
    for e in &result.entries {
        eprintln!("  {:<28} {}", sanitize(&e.title), mask(e.password.expose()));
    }

    if std::io::stdin().is_terminal() && !confirm("Import these into the vault?")? {
        return Err("aborted".to_string());
    }

    let password = prompt_password(false)?;
    let bytes = read_vault(path)?;
    let mut vault = Vault::open(&bytes, password.as_bytes()).map_err(|e| e.to_string())?;
    let n = result.entries.len();
    for entry in result.entries {
        vault.add_entry(entry);
    }
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    eprintln!("Imported {n} entries into {}.", path.display());
    Ok(())
}

fn cmd_ls(path: &Path, search: Option<&str>) -> CmdResult {
    let password = prompt_password(false)?;
    let bytes = read_vault(path)?;
    let vault = Vault::open(&bytes, password.as_bytes()).map_err(|e| e.to_string())?;
    let entries = match search {
        Some(q) => vault.search(q),
        None => vault.entries().iter().collect(),
    };
    if entries.is_empty() {
        eprintln!("no matching entries");
        return Ok(());
    }
    for e in entries {
        // Titles are user/import-controlled → sanitize before the terminal (C30).
        println!("{}", sanitize(&e.title));
    }
    Ok(())
}

fn cmd_get(path: &Path, name: &str, field: &str, stdout: bool, timeout: u64) -> CmdResult {
    if field != "password" {
        return Err("only the `password` field is supported in this version".to_string());
    }
    let password = prompt_password(false)?;
    let bytes = read_vault(path)?;
    let vault = Vault::open(&bytes, password.as_bytes()).map_err(|e| e.to_string())?;
    let entry = vault
        .get(name)
        .ok_or_else(|| format!("no entry titled {name:?}"))?;
    let secret = entry.password.expose();

    if stdout {
        // C27: explicit, warned opt-in.
        eprintln!(
            "WARNING: plaintext written to stdout; ensure no AI agent or untrusted process \
             captures this stream."
        );
        std::io::stdout()
            .write_all(secret)
            .and_then(|_| std::io::stdout().write_all(b"\n"))
            .map_err(|e| e.to_string())?;
    } else {
        copy_to_clipboard(secret)?;
        spawn_clipboard_holder(secret, timeout)?; // C13: auto-clear, clears iff unchanged
        if timeout == 0 {
            eprintln!("Copied {name:?} to the clipboard (model-blind).");
        } else {
            eprintln!("Copied {name:?} to the clipboard (model-blind). Clears in {timeout}s.");
        }
    }

    // A tiny convenience: note any extra secret fields the entry carries.
    let extras: Vec<&str> = entry
        .custom_fields
        .iter()
        .filter(|f| matches!(f.value, CustomValue::Protected(_)))
        .map(|f| f.name.as_str())
        .collect();
    if !extras.is_empty() {
        eprintln!("(entry also has protected fields: {})", extras.join(", "));
    }
    Ok(())
}

fn cmd_gen(length: usize, charset: &str, words: Option<usize>) -> CmdResult {
    use vault_core::gen::{entropy_bits, password, Charset};
    if words.is_some() || charset == "words" {
        return Err(
            "the diceware `words` charset needs the EFF wordlist, not bundled yet".to_string(),
        );
    }
    if !(8..=256).contains(&length) {
        return Err("length must be between 8 and 256".to_string());
    }
    let cs = match charset {
        "alnum" => Charset::Alnum,
        "ascii" => Charset::Ascii,
        other => return Err(format!("unknown charset {other:?} (use alnum or ascii)")),
    };
    let pw = password(cs, length).map_err(|e| e.to_string())?;
    println!("{}", &*pw); // the generated password is the command's output
    eprintln!("({:.0} bits of entropy)", entropy_bits(cs, length));
    Ok(())
}

fn cmd_add(path: &Path, name: &str) -> CmdResult {
    let password = prompt_password(false)?;
    let bytes = read_vault(path)?;
    let mut vault = Vault::open(&bytes, password.as_bytes()).map_err(|e| e.to_string())?;
    if vault.get(name).is_some() {
        return Err(format!(
            "an entry titled {name:?} already exists; use `edit`"
        ));
    }
    let username = prompt_line("Username (optional): ")?;
    let url = prompt_line("URL (optional): ")?;
    let entered = prompt_secret_value("Password (Enter to generate): ")?;
    let mut generated = false;
    let secret = if entered.is_empty() {
        generated = true;
        gen_password(Charset::Alnum, 20).map_err(|e| e.to_string())?
    } else {
        entered
    };
    let notes = prompt_line("Notes (optional): ")?;

    let now = now_unix();
    vault.add_entry(Entry {
        id: random_id()?,
        title: name.to_string(),
        username,
        password: Protected::new(secret.as_bytes().to_vec()),
        url,
        notes,
        tags: Vec::new(),
        otp_secret: None,
        created_at: now,
        modified_at: now,
        expires_at: None,
        custom_fields: Vec::new(),
    });
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    if generated {
        eprintln!(
            "Added {name:?} with a generated 20-char password — `vault get {name}` to copy it."
        );
    } else {
        eprintln!("Added {name:?}.");
    }
    Ok(())
}

fn cmd_edit(path: &Path, name: &str) -> CmdResult {
    let password = prompt_password(false)?;
    let bytes = read_vault(path)?;
    let mut vault = Vault::open(&bytes, password.as_bytes()).map_err(|e| e.to_string())?;
    let (cur_user, cur_url, cur_notes) = {
        let e = vault
            .get(name)
            .ok_or_else(|| format!("no entry titled {name:?}"))?;
        (e.username.clone(), e.url.clone(), e.notes.clone())
    };
    let username = prompt_line_default("Username", &cur_user)?;
    let url = prompt_line_default("URL", &cur_url)?;
    let new_secret = if confirm("Change the password?")? {
        let entered = prompt_secret_value("New password (Enter to generate): ")?;
        Some(if entered.is_empty() {
            gen_password(Charset::Alnum, 20).map_err(|e| e.to_string())?
        } else {
            entered
        })
    } else {
        None
    };
    let notes = prompt_line_default("Notes", &cur_notes)?;

    let e = vault.entry_mut(name).expect("entry existed a moment ago");
    e.username = username;
    e.url = url;
    e.notes = notes;
    if let Some(s) = &new_secret {
        e.password = Protected::new(s.as_bytes().to_vec());
    }
    e.modified_at = now_unix();
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    eprintln!("Updated {name:?}.");
    Ok(())
}

fn cmd_rm(path: &Path, name: &str) -> CmdResult {
    let password = prompt_password(false)?;
    let bytes = read_vault(path)?;
    let mut vault = Vault::open(&bytes, password.as_bytes()).map_err(|e| e.to_string())?;
    if vault.get(name).is_none() {
        return Err(format!("no entry titled {name:?}"));
    }
    if std::io::stdin().is_terminal()
        && !confirm(&format!("Delete {name:?}? This cannot be undone."))?
    {
        return Err("aborted".to_string());
    }
    vault.remove(name);
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    eprintln!("Deleted {name:?}.");
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_id() -> Result<[u8; 16], String> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| e.to_string())?;
    Ok(id)
}

/// Prompt for a non-secret line (echoed).
fn prompt_line(label: &str) -> Result<String, String> {
    eprint!("{label}");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(s.trim().to_string())
}

/// Prompt for a non-secret line showing a default; empty input keeps the default.
fn prompt_line_default(label: &str, default: &str) -> Result<String, String> {
    eprint!("{label} [{default}]: ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| e.to_string())?;
    let t = s.trim();
    Ok(if t.is_empty() {
        default.to_string()
    } else {
        t.to_string()
    })
}

/// Prompt for a secret value without echo (entry passwords). Never from argv (C29).
fn prompt_secret_value(label: &str) -> Result<Zeroizing<String>, String> {
    Ok(Zeroizing::new(
        rpassword::prompt_password(label).map_err(|e| e.to_string())?,
    ))
}

fn vault_path(opt: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = opt {
        return Ok(p);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or("cannot determine your home directory; pass --vault <PATH>")?;
    Ok(PathBuf::from(home).join(".vault").join("vault.vlt"))
}

fn read_vault(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path)
        .map_err(|_| format!("no vault at {} — run `vault init` first", path.display()))
}

/// Atomic write: temp file (0600 on Unix) in the same dir → fsync → rename over the target.
fn write_vault(path: &Path, bytes: &[u8]) -> CmdResult {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
    }
    let tmp = path.with_extension("vlt.tmp");
    {
        let mut oo = std::fs::OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o600);
        }
        let mut f = oo.open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Read the master password without echo (TTY) or from stdin (non-interactive). Never from argv.
fn prompt_password(confirm_match: bool) -> Result<Zeroizing<String>, String> {
    if !std::io::stdin().is_terminal() {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        let line = s.lines().next().unwrap_or("").to_string();
        return Ok(Zeroizing::new(line));
    }
    let p =
        Zeroizing::new(rpassword::prompt_password("Master password: ").map_err(|e| e.to_string())?);
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

fn confirm(question: &str) -> Result<bool, String> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(matches!(s.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Write `data` to the OS clipboard via the platform tool, passed on **stdin** (never argv — C29).
/// Used both to deliver a secret and (with empty `data`) to clear the clipboard.
fn copy_to_clipboard(data: &[u8]) -> CmdResult {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else if cfg!(target_os = "windows") {
        &[("clip", &[])]
    } else {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["-b", "-i"]),
        ]
    };
    for (cmd, args) in candidates {
        let child = std::process::Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(_) => continue, // tool not installed; try the next
        };
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data).map_err(|e| e.to_string())?;
        }
        if child.wait().map_err(|e| e.to_string())?.success() {
            return Ok(());
        }
    }
    Err("no clipboard tool found (install pbcopy / wl-copy / xclip), or use --stdout".to_string())
}

/// Read the current clipboard contents via the platform tool, if available.
fn read_clipboard() -> Option<Vec<u8>> {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbpaste", &[])]
    } else if cfg!(target_os = "windows") {
        &[("powershell", &["-NoProfile", "-Command", "Get-Clipboard"])]
    } else {
        &[
            ("wl-paste", &["--no-newline"]),
            ("xclip", &["-selection", "clipboard", "-o"]),
            ("xsel", &["-b", "-o"]),
        ]
    };
    for (cmd, args) in candidates {
        if let Ok(out) = std::process::Command::new(cmd)
            .args(*args)
            .stderr(Stdio::null())
            .output()
        {
            if out.status.success() {
                return Some(out.stdout);
            }
        }
    }
    None
}

/// Spawn a **detached** helper that clears the clipboard after `timeout` seconds — but only if the
/// clipboard still holds our secret (UC-04 / C13). The secret reaches the helper over an inherited
/// stdin pipe, never argv or environment (C29); the parent returns immediately.
fn spawn_clipboard_holder(secret: &[u8], timeout: u64) -> CmdResult {
    if timeout == 0 {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new(exe)
        .arg("hold-clipboard")
        .arg(timeout.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret).map_err(|e| e.to_string())?;
    }
    // Do NOT wait: the child runs detached and the parent exits; init reaps it after it clears.
    Ok(())
}

/// The detached holder (internal subcommand): read the secret on stdin, sleep, then clear the
/// clipboard iff it is still byte-for-byte our secret (tolerating a trailing newline some tools add).
fn run_clipboard_holder(secs: u64) -> CmdResult {
    let mut secret: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut secret).ok();
    if secs == 0 || secret.is_empty() {
        return Ok(());
    }
    std::thread::sleep(std::time::Duration::from_secs(secs));
    if let Some(cur) = read_clipboard() {
        let cur = Zeroizing::new(cur);
        let (cur_s, sec_s): (&[u8], &[u8]) = (&cur, &secret);
        let unchanged = cur_s == sec_s
            || cur_s.strip_suffix(b"\n") == Some(sec_s)
            || cur_s.strip_suffix(b"\r\n") == Some(sec_s);
        if unchanged {
            let _ = copy_to_clipboard(&[]); // clear — still ours
        }
    }
    Ok(())
}

/// Mask a secret for review: first/last 4 chars + length, never the middle.
fn mask(secret: &[u8]) -> String {
    let s = String::from_utf8_lossy(secret);
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= 8 {
        format!("{} ({n})", "•".repeat(n))
    } else {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[n - 4..].iter().collect();
        format!("{head}…{tail} ({n})")
    }
}

/// Render control / ANSI bytes as visible escapes before writing to a terminal (constraint C30).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || !c.is_control() {
                c.to_string()
            } else {
                format!("\\x{:02x}", c as u32)
            }
        })
        .collect()
}
