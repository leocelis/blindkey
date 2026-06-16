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

/// Options that affect how a vault is opened — the rollback policy (constraint C16).
pub struct OpenOpts {
    /// Proceed past a regression without prompting (the anchor is never lowered).
    pub allow_rollback: bool,
    /// On a fresh machine (no anchor), require at least this version (TOFU mitigation).
    pub expect_min_version: Option<u64>,
    /// Unlock a YubiKey-2FA vault with its recovery code instead of the key (UC-09 anti-lockout).
    pub recovery: bool,
}

/// Route a parsed command to its handler.
pub fn dispatch(vault_opt: Option<PathBuf>, opts: &OpenOpts, command: Command) -> CmdResult {
    match command {
        Command::Init {
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
            allow_weak_password,
        } => cmd_init(
            &vault_path(vault_opt)?,
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
            allow_weak_password,
        ),
        Command::Import { format, source } => {
            cmd_import(&vault_path(vault_opt)?, &format, &source, opts)
        }
        Command::Ls { search } => cmd_ls(&vault_path(vault_opt)?, search.as_deref(), opts),
        Command::Audit => cmd_audit(&vault_path(vault_opt)?, opts),
        Command::Get {
            name,
            field,
            stdout,
            timeout,
        } => cmd_get(
            &vault_path(vault_opt)?,
            &name,
            &field,
            stdout,
            timeout,
            opts,
        ),
        Command::Otp { name, stdout } => cmd_otp(&vault_path(vault_opt)?, &name, stdout, opts),
        Command::HoldClipboard { secs } => run_clipboard_holder(secs),
        Command::Gen {
            length,
            charset,
            words,
            wordlist,
        } => cmd_gen(length, &charset, words, wordlist.as_deref()),
        Command::Add { name } => cmd_add(&vault_path(vault_opt)?, &name, opts),
        Command::Edit { name } => cmd_edit(&vault_path(vault_opt)?, &name, opts),
        Command::Rm { name } => cmd_rm(&vault_path(vault_opt)?, &name, opts),
        Command::UpgradeKdf {
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
        } => cmd_upgrade_kdf(
            &vault_path(vault_opt)?,
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
            opts,
        ),
        Command::Pad { state } => cmd_pad(&vault_path(vault_opt)?, &state, opts),
        Command::Tune => cmd_tune(),
        Command::Enroll { factor } => cmd_enroll(&vault_path(vault_opt)?, &factor, opts),
        Command::Lock => Err("that command is not implemented yet".to_string()),
    }
}

// ─── commands ──────────────────────────────────────────────────────────────

fn cmd_init(
    path: &Path,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    allow_weak_password: bool,
) -> CmdResult {
    if path.exists() {
        return Err(format!(
            "a vault already exists at {} (refusing to overwrite)",
            path.display()
        ));
    }
    let password = prompt_password(true)?;
    // Root-of-trust check: a weak master password defeats every other layer (it faces offline
    // brute force). Warn loudly; on a TTY require confirmation. `--allow-weak-password` skips it.
    if !allow_weak_password {
        let bits = vault_core::audit::password_entropy_bits(password.as_bytes());
        if bits < vault_core::audit::WEAK_MASTER_BITS {
            eprintln!(
                "warning: that master password is weak (~{bits:.0} bits) — it protects everything \
                 and faces offline cracking. A passphrase is far stronger (try `vault gen --words 6`)."
            );
            if std::io::stdin().is_terminal() && !confirm("Use this weak master password anyway?")?
            {
                return Err("aborted — choose a stronger master password".to_string());
            }
        }
    }
    eprintln!("Deriving key (Argon2id)…");
    let mut vault =
        Vault::create(password.as_bytes(), m_cost, t_cost, p_cost).map_err(|e| e.to_string())?;
    let bytes = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &bytes)?;
    note_saved(&vault); // C16: seed the local anchor at the initial version
    eprintln!("Created vault at {}", path.display());
    Ok(())
}

fn cmd_import(path: &Path, format: &str, source: &Path, opts: &OpenOpts) -> CmdResult {
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
        eprintln!(
            "  {:<28} {}",
            sanitize(&e.title),
            mask(&e.password.expose())
        );
    }

    if std::io::stdin().is_terminal() && !confirm("Import these into the vault?")? {
        return Err("aborted".to_string());
    }

    let password = prompt_password(false)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    let n = result.entries.len();
    for entry in result.entries {
        vault.add_entry(entry);
    }
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("Imported {n} entries into {}.", path.display());
    Ok(())
}

fn cmd_ls(path: &Path, search: Option<&str>, opts: &OpenOpts) -> CmdResult {
    let password = prompt_password(false)?;
    let vault = open_vault(path, password.as_bytes(), opts)?;
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

fn cmd_audit(path: &Path, opts: &OpenOpts) -> CmdResult {
    use vault_core::audit::{analyze, AuditConfig};
    let password = prompt_password(false)?;
    let vault = open_vault(path, password.as_bytes(), opts)?;
    let report = analyze(vault.entries(), now_unix(), &AuditConfig::default());

    println!("Audited {} entries.", report.total);
    if report.is_clean() {
        println!("✅ No issues found.");
        return Ok(());
    }
    if !report.weak.is_empty() {
        println!("\n⚠ Weak passwords ({}):", report.weak.len());
        for t in &report.weak {
            println!("  {}", sanitize(t));
        }
    }
    if !report.reused.is_empty() {
        println!("\n⚠ Reused passwords ({} group(s)):", report.reused.len());
        for group in &report.reused {
            let titles: Vec<String> = group.iter().map(|t| sanitize(t)).collect();
            println!("  {}", titles.join(", "));
        }
    }
    if !report.stale.is_empty() {
        println!("\n⚠ Not changed in over a year ({}):", report.stale.len());
        for t in &report.stale {
            println!("  {}", sanitize(t));
        }
    }
    if !report.expiring.is_empty() {
        println!("\n⚠ Expiring/expired ({}):", report.expiring.len());
        for (t, days) in &report.expiring {
            let when = if *days < 0 {
                format!("expired {}d ago", -days)
            } else {
                format!("in {days}d")
            };
            println!("  {} ({when})", sanitize(t));
        }
    }
    Ok(())
}

fn cmd_get(
    path: &Path,
    name: &str,
    field: &str,
    stdout: bool,
    timeout: u64,
    opts: &OpenOpts,
) -> CmdResult {
    if field != "password" {
        return Err("only the `password` field is supported in this version".to_string());
    }
    let password = prompt_password(false)?;
    let vault = open_vault(path, password.as_bytes(), opts)?;
    let entry = vault
        .get(name)
        .ok_or_else(|| format!("no entry titled {name:?}"))?;
    let secret = entry.password.expose(); // owned, zeroizing (decrypt-on-access, C19)

    if stdout {
        // C27: explicit, warned opt-in.
        eprintln!(
            "WARNING: plaintext written to stdout; ensure no AI agent or untrusted process \
             captures this stream."
        );
        std::io::stdout()
            .write_all(&secret)
            .and_then(|_| std::io::stdout().write_all(b"\n"))
            .map_err(|e| e.to_string())?;
    } else {
        copy_to_clipboard(&secret)?;
        spawn_clipboard_holder(&secret, timeout)?; // C13: auto-clear, clears iff unchanged
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

fn cmd_otp(path: &Path, name: &str, stdout: bool, opts: &OpenOpts) -> CmdResult {
    let password = prompt_password(false)?;
    let vault = open_vault(path, password.as_bytes(), opts)?;
    let entry = vault
        .get(name)
        .ok_or_else(|| format!("no entry titled {name:?}"))?;
    let otp = entry
        .otp_secret
        .as_ref()
        .ok_or_else(|| format!("{name:?} has no 2FA secret (add one with `vault edit`)"))?;
    let code = vault_core::totp::generate_now(&otp.expose())
        .map_err(|_| "the stored 2FA secret is not valid base32".to_string())?;

    if stdout {
        println!("{}", code.code);
        eprintln!("(valid for {}s)", code.valid_for_secs);
    } else {
        copy_to_clipboard(code.code.as_bytes())?;
        // Clear when the code rolls over so a stale code doesn't linger on the clipboard (C13).
        spawn_clipboard_holder(code.code.as_bytes(), code.valid_for_secs.max(1))?;
        eprintln!(
            "Copied 2FA code for {name:?} (valid {}s).",
            code.valid_for_secs
        );
    }
    Ok(())
}

fn cmd_gen(
    length: usize,
    charset: &str,
    words: Option<usize>,
    wordlist: Option<&Path>,
) -> CmdResult {
    use vault_core::gen::{entropy_bits, password, Charset};

    // Diceware passphrase mode: `--words N` (or `--charset words`, defaulting to 6 words).
    if let Some(n) = words.or(if charset == "words" { Some(6) } else { None }) {
        return cmd_gen_passphrase(n, wordlist);
    }

    if !(8..=256).contains(&length) {
        return Err("length must be between 8 and 256".to_string());
    }
    let cs = match charset {
        "alnum" => Charset::Alnum,
        "ascii" => Charset::Ascii,
        other => {
            return Err(format!(
                "unknown charset {other:?} (use alnum, ascii, or words)"
            ))
        }
    };
    let pw = password(cs, length).map_err(|e| e.to_string())?;
    println!("{}", &*pw); // the generated password is the command's output
    eprintln!("({:.0} bits of entropy)", entropy_bits(cs, length));
    Ok(())
}

fn cmd_gen_passphrase(n: usize, wordlist: Option<&Path>) -> CmdResult {
    use vault_core::gen::{passphrase, passphrase_entropy_bits};
    if !(3..=64).contains(&n) {
        return Err("words must be between 3 and 64".to_string());
    }
    // Either a user-supplied wordlist (e.g. the EFF large list) or the built-in 256-word list.
    let (list, source): (Vec<String>, &str) = match wordlist {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
            // Accept plain "word\n" lines and EFF "<dice>\t<word>" lines (take the last token).
            let list: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| {
                    l.rsplit(char::is_whitespace)
                        .next()
                        .unwrap_or(l)
                        .to_string()
                })
                .collect();
            (list, "supplied")
        }
        None => (
            vault_core::wordlist::BUILTIN
                .iter()
                .map(|s| s.to_string())
                .collect(),
            "built-in 256-word",
        ),
    };
    if list.len() < 16 {
        return Err("wordlist too small (need at least 16 words)".to_string());
    }
    let refs: Vec<&str> = list.iter().map(String::as_str).collect();
    let pp = passphrase(n, &refs).map_err(|e| e.to_string())?;
    println!("{}", &*pp); // the passphrase is the command's output
    eprintln!(
        "({:.0} bits of entropy — {n} words from the {source} list of {})",
        passphrase_entropy_bits(n, refs.len()),
        refs.len()
    );
    if wordlist.is_none() {
        eprintln!("(tip: for ~12.9 bits/word, use --wordlist with the EFF large list from https://www.eff.org/dice)");
    }
    Ok(())
}

fn cmd_add(path: &Path, name: &str, opts: &OpenOpts) -> CmdResult {
    let password = prompt_password(false)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
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
    let otp_in = prompt_secret_value("2FA secret (base32, blank for none): ")?;
    let otp_secret = if otp_in.is_empty() {
        None
    } else {
        Some(Protected::new(otp_in.as_bytes().to_vec()))
    };

    let now = now_unix();
    vault.add_entry(Entry {
        id: random_id()?,
        title: name.to_string(),
        username,
        password: Protected::new(secret.as_bytes().to_vec()),
        url,
        notes,
        tags: Vec::new(),
        otp_secret,
        created_at: now,
        modified_at: now,
        expires_at: None,
        custom_fields: Vec::new(),
    });
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    note_saved(&vault);
    if generated {
        eprintln!(
            "Added {name:?} with a generated 20-char password — `vault get {name}` to copy it."
        );
    } else {
        eprintln!("Added {name:?}.");
    }
    Ok(())
}

fn cmd_edit(path: &Path, name: &str, opts: &OpenOpts) -> CmdResult {
    let password = prompt_password(false)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
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
    // 2FA: change/set/clear the TOTP secret. Blank keeps the current one; "-" clears it.
    let otp_change = if confirm("Change the 2FA secret?")? {
        Some(prompt_secret_value("2FA secret (base32, '-' to clear): ")?)
    } else {
        None
    };

    let e = vault.entry_mut(name).expect("entry existed a moment ago");
    e.username = username;
    e.url = url;
    e.notes = notes;
    if let Some(s) = &new_secret {
        e.password = Protected::new(s.as_bytes().to_vec());
    }
    if let Some(otp) = &otp_change {
        let t = otp.trim();
        if t == "-" {
            e.otp_secret = None; // explicit clear
        } else if !t.is_empty() {
            e.otp_secret = Some(Protected::new(t.as_bytes().to_vec()));
        }
        // blank → keep the current 2FA secret unchanged
    }
    e.modified_at = now_unix();
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("Updated {name:?}.");
    Ok(())
}

fn cmd_rm(path: &Path, name: &str, opts: &OpenOpts) -> CmdResult {
    let password = prompt_password(false)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
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
    note_saved(&vault);
    eprintln!("Deleted {name:?}.");
    Ok(())
}

fn cmd_upgrade_kdf(path: &Path, m: u32, t: u32, p: u32, opts: &OpenOpts) -> CmdResult {
    let password = prompt_password(false)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    eprintln!("Re-deriving with Argon2id (m={m} KiB, t={t}, p={p})…");
    vault
        .change_kdf(password.as_bytes(), m, t, p)
        .map_err(|e| e.to_string())?;
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("Upgraded KDF parameters.");
    Ok(())
}

fn cmd_tune() -> CmdResult {
    eprintln!("Benchmarking Argon2id on this machine (targeting ~300 ms)…");
    let r = vault_core::crypto::tune::recommend().map_err(|e| e.to_string())?;
    let mib = r.m_cost_kib / 1024;
    // The recommendation goes to stdout (scriptable); the measured time + apply hint to stderr.
    println!(
        "Recommended Argon2id: m={} KiB ({mib} MiB), t={}, p={} — measured {} ms",
        r.m_cost_kib, r.t_cost, r.p_cost, r.measured_ms
    );
    eprintln!(
        "Apply with: vault upgrade-kdf --kdf-m-cost {} --kdf-t-cost {} --kdf-p-cost {}",
        r.m_cost_kib, r.t_cost, r.p_cost
    );
    Ok(())
}

fn cmd_enroll(path: &Path, factor: &str, opts: &OpenOpts) -> CmdResult {
    match factor.to_lowercase().as_str() {
        "yubikey" | "yk" => cmd_enroll_yubikey(path, opts),
        other => Err(format!(
            "unknown factor {other:?} (currently supported: yubikey)"
        )),
    }
}

fn cmd_enroll_yubikey(path: &Path, opts: &OpenOpts) -> CmdResult {
    use vault_hardware::yubikey;
    if !yubikey::available() {
        return Err(
            "no YubiKey detected — plug it in and install YubiKey Manager (`brew install ykman`)"
                .to_string(),
        );
    }
    // Unlock first: the data key must be in memory to re-wrap it under the new 2FA stanza.
    let password = prompt_password(false)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    if vault.is_2fa() {
        return Err("this vault already has a YubiKey enrolled".to_string());
    }
    if std::io::stdin().is_terminal()
        && !confirm(
            "This programs slot 2 of your YubiKey (OVERWRITING it) and will require the key on \
             every unlock. Continue?",
        )?
    {
        return Err("aborted".to_string());
    }

    eprintln!("Programming slot 2 — touch the key when it blinks…");
    yubikey::program_chalresp_slot2()?;

    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge).map_err(|e| e.to_string())?;
    eprintln!("Touch your YubiKey again to finish enrollment…");
    let hw_response = yubikey::challenge_response(&challenge)?;

    let recovery = recovery_code()?;
    vault
        .enroll_yubikey_2fa(
            password.as_bytes(),
            &hw_response,
            &challenge,
            recovery.as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    note_saved(&vault);

    eprintln!("\n✅ YubiKey enrolled — this vault now requires the master password AND the key.\n");
    eprintln!("   RECOVERY CODE — write it down and store it OFFLINE. It unlocks WITHOUT the key,");
    eprintln!("   so it is the only way back in if the key is lost:\n");
    eprintln!("       {recovery}\n");
    eprintln!("   Unlock with it using:  vault --recovery <command>");
    Ok(())
}

/// A high-entropy recovery code: 24 alphanumerics (~143 bits) grouped 4-by-4 for readability.
fn recovery_code() -> Result<String, String> {
    let raw = gen_password(Charset::Alnum, 24).map_err(|e| e.to_string())?;
    let chars: Vec<char> = raw.chars().collect();
    Ok(chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-"))
}

fn cmd_pad(path: &Path, state: &str, opts: &OpenOpts) -> CmdResult {
    use vault_core::pad::PadMode;
    let mode = match state.to_lowercase().as_str() {
        "on" | "padme" | "true" => PadMode::Padme,
        "off" | "none" | "false" => PadMode::None,
        other => return Err(format!("unknown pad state {other:?} (use `on` or `off`)")),
    };
    let password = prompt_password(false)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    vault.set_padding(mode);
    let out = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!(
        "Size-padding {}.",
        if matches!(mode, PadMode::Padme) {
            "enabled (Padmé) — the file's exact size is now hidden"
        } else {
            "disabled"
        }
    );
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

/// Read + unlock the vault, warning if its KDF is below the recommended floor (constraint C2), then
/// run the rollback guard (constraint C16 — may `exit(2)` if the user won't accept a regression).
fn open_vault(path: &Path, password: &[u8], opts: &OpenOpts) -> Result<Vault, String> {
    let bytes = read_vault(path)?;
    // Progress indicator for the Argon2id unlock so the user doesn't think it hung (constraint C22).
    eprintln!("Deriving key (Argon2id)…");
    // A YubiKey-2FA vault needs the key's tap — unless `--recovery`, which opens via the recovery
    // code (entered at the password prompt) through the password path (UC-09 anti-lockout).
    let vault = if Vault::requires_yubikey(&bytes) && !opts.recovery {
        eprintln!("Touch your YubiKey…");
        Vault::open_2fa(&bytes, password, |challenge| {
            vault_hardware::yubikey::challenge_response(challenge)
                .map_err(vault_core::Error::Hardware)
        })
        .map_err(|e| e.to_string())?
    } else {
        Vault::open(&bytes, password).map_err(|e| e.to_string())?
    };
    if matches!(
        vault.kdf_strength(),
        vault_core::crypto::KdfStrength::BelowFloor
    ) {
        eprintln!(
            "vault: warning — this vault's Argon2id cost is below the recommended floor; \
             run `vault upgrade-kdf` to strengthen it."
        );
    }
    rollback_guard(&vault, opts);
    Ok(vault)
}

/// Compare the opened vault's version against the local anchor (C16). On a regression: warn, then
/// prompt (TTY) or exit 2 (non-TTY) unless `--allow-rollback`. On success: advance the anchor.
fn rollback_guard(vault: &Vault, opts: &OpenOpts) {
    use vault_core::rollback::{self, RollbackCheck};
    let Ok(anchor) = rollback::anchor_path(vault.vault_id()) else {
        return; // cannot locate a data dir → skip the alarm wire (best-effort)
    };
    let last_seen = rollback::read_anchor(&anchor);
    let floor = opts.expect_min_version.unwrap_or(0).max(last_seen);
    match rollback::check(vault.version(), floor) {
        RollbackCheck::Ok => {
            let _ = rollback::advance_anchor(&anchor, vault.version());
        }
        RollbackCheck::Regressed { expected, got } => {
            eprintln!(
                "WARNING: vault version regressed (expected >= {expected}, got {got}). \
                 The sync backend may have served an older copy."
            );
            if opts.allow_rollback {
                eprintln!("Proceeding (--allow-rollback); the local anchor is left unchanged.");
                return;
            }
            if std::io::stdin().is_terminal() {
                eprint!("Proceed anyway? [y/N] ");
                std::io::stderr().flush().ok();
                let mut s = String::new();
                let _ = std::io::stdin().read_line(&mut s);
                if matches!(s.trim().to_lowercase().as_str(), "y" | "yes") {
                    return; // proceed; do not lower the anchor
                }
            }
            // Non-TTY, or a TTY that answered no: abort with the reserved rollback exit code (C16).
            std::process::exit(2);
        }
    }
}

/// After a save, advance the local anchor to the new version so a later open can detect a backend
/// serving the pre-save copy (constraint C16 / UC-07 §3.4). Best-effort.
fn note_saved(vault: &Vault) {
    if let Ok(anchor) = vault_core::rollback::anchor_path(vault.vault_id()) {
        let _ = vault_core::rollback::advance_anchor(&anchor, vault.version());
    }
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
        // Read exactly one line so the remaining stdin is available to later prompts (scriptable
        // `add`/`edit`); strip the trailing newline.
        let mut s = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut s)
            .map_err(|e| e.to_string())?;
        let line = s.trim_end_matches(['\n', '\r']).to_string();
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
