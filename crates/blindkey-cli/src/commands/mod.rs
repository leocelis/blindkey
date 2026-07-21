//! Command handlers (constraints C20–C22, C27, C29, C30).
//!
//! File I/O, the no-echo password prompt, and clipboard delivery live here — the thin shell over
//! `blindkey_core`. The same `blindkey_core` operations (`create`/`open`/`save`/`import`/`search`) will be
//! driven by the future desktop app, so all logic that touches secrets stays in the core.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use blindkey_core::format::entry::{CustomValue, Entry, Protected};
use blindkey_core::gen::{password as gen_password, Charset};
use blindkey_core::Vault;
use zeroize::Zeroizing;

use crate::export::{self, EXPORT_CONFIRM, EXPORT_WARNING};
use crate::unlock_secret::{self, UnlockSecretOpts};
use crate::Command;

mod sealed;

type CmdResult = Result<(), String>;
type SaveResult = Result<Vec<u8>, String>;

pub const USAGE_ERROR_PREFIX: &str = "usage:";
pub const CLIPBOARD_UNAVAILABLE_PREFIX: &str = "clipboard-unavailable:";
const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

fn usage_err(msg: impl Into<String>) -> String {
    format!("{USAGE_ERROR_PREFIX} {}", msg.into())
}

fn clipboard_unavailable_err() -> String {
    format!(
        "{CLIPBOARD_UNAVAILABLE_PREFIX} no clipboard available on this session; use --stdout \
         (prints a security warning) if you accept plaintext on stdout."
    )
}

fn require_clipboard() -> CmdResult {
    if blindkey_clip::clipboard_available() {
        Ok(())
    } else {
        Err(clipboard_unavailable_err())
    }
}

fn copy_secret_to_clipboard(secret: &[u8], timeout: u64, label: &str) -> CmdResult {
    require_clipboard()?;
    copy_to_clipboard(secret)?;
    spawn_clipboard_holder(secret, timeout)?;
    if timeout == 0 {
        eprintln!("Copied {label} to the clipboard (model-blind).");
    } else {
        eprintln!("Copied {label} to the clipboard (model-blind). Clears in {timeout}s.");
    }
    Ok(())
}

/// Shown on init/import/open paths — honest unaudited posture (third-party audit optional per).
/// On-disk format v1 is stable (ADR-0005); this notice covers audit/backup only.
pub const PRE_RELEASE_NOTICE: &str =
    "note: Blindkey has not had an independent third-party security audit — \
keep a separate backup; do not make this your only copy of irreplaceable secrets.";

fn pre_release_notice() {
    eprintln!("{PRE_RELEASE_NOTICE}");
}

/// `vault.vlt` → `vault.vlt.bak` (constraint C32 naming).
fn vault_backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".bak");
    PathBuf::from(s)
}

/// Copy the current vault to a `.bak` sibling before overwriting it.
fn backup_vault_if_exists(path: &Path) -> CmdResult {
    if !path.exists() {
        return Ok(());
    }
    let bak = vault_backup_path(path);
    std::fs::copy(path, &bak).map_err(|e| format!("cannot write backup {}: {e}", bak.display()))?;
    eprintln!("Backup written to {}", bak.display());
    Ok(())
}

/// Options that affect how a vault is opened — the rollback policy (constraint C16).
pub(crate) struct OpenOpts {
    /// Proceed past a regression without prompting (the anchor is never lowered).
    pub allow_rollback: bool,
    /// On a fresh machine (no anchor), require at least this version (TOFU mitigation).
    pub expect_min_version: Option<u64>,
    /// Force strict YubiKey-at-save (constraint C5).
    pub strict_yubikey: bool,
    /// Allow graceful stale YubiKey stanza on save (constraint C5).
    pub allow_stale_yubikey: bool,
    /// Unlock a YubiKey-2FA vault with its recovery code instead of the key (UC-09 anti-lockout).
    pub recovery: bool,
    /// Keyfile path supplied as the second factor for a keyfile-2FA vault.
    pub keyfile: Option<PathBuf>,
    /// Non-interactive master-password channels (UC-05 §3.2).
    pub unlock: UnlockSecretOpts,
}

fn effective_yubikey_strict(vault: &blindkey_core::Vault, opts: &OpenOpts) -> bool {
    if opts.allow_stale_yubikey {
        return false;
    }
    if opts.strict_yubikey {
        return true;
    }
    vault.yubikey_strict()
}

/// Body-writing save with YubiKey refresh policy (constraint C5).
fn save_vault(vault: &mut blindkey_core::Vault, password: &[u8], opts: &OpenOpts) -> SaveResult {
    use blindkey_core::{Error, SaveOptions, YUBIKEY_STALE_WARNING};
    let strict = effective_yubikey_strict(vault, opts);
    if vault.has_yubikey_2fa() {
        let mut respond = |challenge: &[u8; 32]| -> Result<Zeroizing<Vec<u8>>, Error> {
            blindkey_hardware::yubikey::challenge_response(challenge).map_err(Error::Hardware)
        };
        let report = vault
            .save_with(SaveOptions {
                password: Some(password),
                yubikey_strict: Some(strict),
                yubikey_respond: Some(&mut respond),
            })
            .map_err(|e| e.to_string())?;
        if report.yubikey_stale {
            eprintln!("{YUBIKEY_STALE_WARNING}");
        }
        Ok(report.bytes)
    } else {
        vault.save().map_err(|e| e.to_string())
    }
}

/// Route a parsed command to its handler.
pub fn dispatch(vault_opt: Option<PathBuf>, opts: &OpenOpts, command: Command) -> CmdResult {
    match command {
        Command::Init {
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
            allow_weak_password,
            allow_weak_kdf,
            with_recovery_code,
        } => cmd_init(
            &vault_path(vault_opt)?,
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
            allow_weak_password,
            allow_weak_kdf,
            with_recovery_code,
            &opts.unlock,
        ),
        Command::Import {
            format,
            source,
            yes,
        } => cmd_import(&vault_path(vault_opt)?, &format, &source, yes, opts),
        Command::Ls { search } => cmd_ls(&vault_path(vault_opt)?, search.as_deref(), opts),
        Command::Audit => cmd_audit(&vault_path(vault_opt)?, opts),
        Command::Export { format, yes } => cmd_export(&vault_path(vault_opt)?, &format, yes, opts),
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
        Command::Find {
            query,
            stdout,
            timeout,
        } => cmd_find(
            &vault_path(vault_opt)?,
            query.as_deref().unwrap_or(""),
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
        Command::RotateDataKey { re_seal_recovery } => {
            cmd_rotate_data_key(&vault_path(vault_opt)?, re_seal_recovery, opts)
        }
        Command::Pad { state } => cmd_pad(&vault_path(vault_opt)?, &state, opts),
        Command::Tune => cmd_tune(),
        Command::Enroll {
            factor,
            path,
            graceful_yubikey,
        } => cmd_enroll(
            &vault_path(vault_opt)?,
            &factor,
            path.as_deref(),
            graceful_yubikey,
            opts,
        ),
        Command::EnrollTpm => cmd_enroll_tpm(&vault_path(vault_opt)?, opts),
        Command::ReEnrollTpm => cmd_re_enroll_tpm(&vault_path(vault_opt)?, opts),
        Command::Agent { action } => crate::agent::dispatch(&vault_path(vault_opt)?, opts, action),
        Command::Mcp => cmd_mcp(),
        Command::Lock => cmd_lock(),
        Command::Stanzas { action } => cmd_stanzas(&vault_path(vault_opt)?, action, opts),
        Command::Seal {
            paths,
            output,
            no_pad,
            allow_weak_kdf,
            kdf_m_cost,
            kdf_t_cost,
            kdf_p_cost,
            append,
        } => {
            use blindkey_core::pad::PadMode;
            use blindkey_core::sealed::SealOptions;
            let seal_opts = SealOptions {
                m_cost: kdf_m_cost,
                t_cost: kdf_t_cost,
                p_cost: kdf_p_cost,
                allow_weak_kdf,
                pad_mode: if no_pad {
                    PadMode::None
                } else {
                    PadMode::Padme
                },
            };
            sealed::cmd_seal(paths, output, append, seal_opts, opts)
        }
        Command::Open { file, dest, stdout } => sealed::cmd_open(file, dest, stdout, opts),
        Command::Peek { file } => sealed::cmd_peek(file, opts),
    }
}

// ─── commands ──────────────────────────────────────────────────────────────

fn cmd_init(
    path: &Path,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    allow_weak_password: bool,
    allow_weak_kdf: bool,
    with_recovery_code: bool,
    unlock: &UnlockSecretOpts,
) -> CmdResult {
    if path.exists() {
        return Err(format!(
            "a vault already exists at {} (refusing to overwrite)",
            path.display()
        ));
    }
    let password = unlock_secret::read_master_password(true, unlock)?;
    // Root-of-trust check: a weak master password defeats every other layer (it faces offline
    // brute force). Warn loudly; on a TTY require confirmation. `--allow-weak-password` skips it.
    if !allow_weak_password {
        let bits = blindkey_core::audit::password_entropy_bits(password.as_bytes());
        if bits < blindkey_core::audit::WEAK_MASTER_BITS {
            eprintln!(
                "warning: that master password is weak (~{bits:.0} bits) — it protects everything \
                 and faces offline cracking. A passphrase is far stronger (try `blindkey gen --words 6`)."
            );
            if std::io::stdin().is_terminal() && !confirm("Use this weak master password anyway?")?
            {
                return Err("aborted — choose a stronger master password".to_string());
            }
        }
    }
    eprintln!("Deriving key (Argon2id)…");
    let mut vault = Vault::create(password.as_bytes(), m_cost, t_cost, p_cost, allow_weak_kdf)
        .map_err(|e| e.to_string())?;

    let add_recovery = with_recovery_code
        || (std::io::stdin().is_terminal()
            && confirm(
                "Add an offline recovery code? There is NO password reset — lose master password \
                 AND recovery code = lose the vault forever.",
            )?);
    let mut printed_recovery: Option<String> = None;
    if add_recovery {
        let recovery = recovery_code()?;
        vault
            .add_recovery_stanza(recovery.as_bytes())
            .map_err(|e| e.to_string())?;
        printed_recovery = Some(recovery);
    }

    let bytes = vault.save().map_err(|e| e.to_string())?;
    write_vault(path, &bytes)?;
    // Seed a recoverable copy alongside the new vault (pre-1.0: never the only copy).
    let bak = vault_backup_path(path);
    if std::fs::copy(path, &bak).is_ok() {
        eprintln!("Initial backup written to {}", bak.display());
    }
    note_saved(&vault); // C16: seed the local anchor at the initial version
    pre_release_notice();
    if let Some(recovery) = printed_recovery {
        eprintln!(
            "\n   RECOVERY CODE — write it down OFFLINE. Shown once; not stored in plaintext:"
        );
        eprintln!("       {recovery}\n");
        eprintln!("   Unlock with:  blindkey --recovery <command>");
        eprintln!(
            "   (Master password still works. No server reset — lose both secrets = vault lost.)"
        );
    }
    eprintln!("Created vault at {}", path.display());
    Ok(())
}

fn cmd_import(path: &Path, format: &str, source: &Path, yes: bool, opts: &OpenOpts) -> CmdResult {
    pre_release_notice();
    let text = read_import_text(source)?;
    let (entries, detail) = match format {
        "raw" => {
            let result = blindkey_core::import::parse_raw(&text);
            (
                result.entries,
                format!(
                    "{} block{} skipped",
                    result.blocks_skipped,
                    if result.blocks_skipped == 1 { "" } else { "s" }
                ),
            )
        }
        "keepass-csv" | "keepassxc-csv" => {
            let result = blindkey_core::import::parse_keepassxc_csv(&text)?;
            (
                result.entries,
                format!(
                    "{} unknown column{} ignored",
                    result.unknown_columns,
                    if result.unknown_columns == 1 { "" } else { "s" }
                ),
            )
        }
        _ => {
            return Err(format!(
                "unknown import format {format:?} (supported: `raw`, `keepass-csv`, `keepassxc-csv`)"
            ));
        }
    };
    if entries.is_empty() {
        return Err("no secrets found in that file".to_string());
    }

    // Masked review (never print the secret — C27).
    eprintln!(
        "Parsed {} entr{} ({detail}):",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
    );
    for e in &entries {
        eprintln!(
            "  {:<28} {}",
            sanitize(&e.title),
            mask(&e.password.expose())
        );
    }

    let tty = std::io::stdin().is_terminal();
    if !yes {
        if tty {
            if !confirm("Import these into the vault?")? {
                return Err("aborted".to_string());
            }
        } else {
            return Err(usage_err(
                "piped/non-interactive import requires --yes (parsed entries shown above)",
            ));
        }
    }

    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    let n = entries.len();
    for entry in entries {
        vault.add_entry(entry);
    }
    backup_vault_if_exists(path)?;
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("Imported {n} entries into {}.", path.display());
    Ok(())
}

fn read_import_text(source: &Path) -> Result<Zeroizing<String>, String> {
    let file = std::fs::File::open(source)
        .map_err(|e| format!("cannot read {}: {e}", source.display()))?;
    let size = file
        .metadata()
        .map_err(|e| format!("cannot inspect {}: {e}", source.display()))?
        .len();
    if size > MAX_IMPORT_BYTES {
        return Err(format!(
            "import source exceeds the {} MiB limit",
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }

    let mut text = Zeroizing::new(String::new());
    file.take(MAX_IMPORT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read {} as UTF-8: {e}", source.display()))?;
    if text.len() as u64 > MAX_IMPORT_BYTES {
        return Err(format!(
            "import source exceeds the {} MiB limit",
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    Ok(text)
}

fn cmd_ls(path: &Path, search: Option<&str>, opts: &OpenOpts) -> CmdResult {
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
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
        // Titles are user/import-controlled → sanitize before the terminal (C28).
        println!("{}", sanitize(&e.title));
    }
    Ok(())
}

fn cmd_audit(path: &Path, opts: &OpenOpts) -> CmdResult {
    use blindkey_core::audit::{analyze, AuditConfig};
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
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

fn cmd_export(path: &Path, format: &str, yes: bool, opts: &OpenOpts) -> CmdResult {
    if format != "json" {
        return Err(usage_err("only --format json is supported"));
    }
    eprintln!("{EXPORT_WARNING}");
    let stdout_tty = std::io::stdout().is_terminal();
    if !yes {
        if stdout_tty {
            if !confirm(EXPORT_CONFIRM)? {
                return Err("aborted".to_string());
            }
        } else {
            return Err(usage_err("piped/non-interactive export requires --yes"));
        }
    }
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let vault = open_vault(path, password.as_bytes(), opts)?;
    let json = export::build_export_json(vault.entries())?;
    std::io::stdout()
        .write_all(json.as_bytes())
        .and_then(|_| std::io::stdout().write_all(b"\n"))
        .map_err(|e| e.to_string())
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
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let vault = open_vault(path, password.as_bytes(), opts)?;
    let entry = vault
        .get(name)
        .ok_or_else(|| format!("no entry titled {name:?}"))?;
    let secret = entry.password.expose(); // owned, zeroizing (decrypt-on-access, C19)

    if stdout {
        // C27: explicit, warned opt-in. C28: sanitize before the terminal.
        eprintln!(
            "WARNING: plaintext written to stdout; ensure no AI agent or untrusted process \
             captures this stream."
        );
        let rendered = sanitize(&String::from_utf8_lossy(&secret));
        std::io::stdout()
            .write_all(rendered.as_bytes())
            .and_then(|_| std::io::stdout().write_all(b"\n"))
            .map_err(|e| e.to_string())?;
    } else {
        copy_secret_to_clipboard(&secret, timeout, &format!("{name:?}"))?;
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

/// UC-19 fuzzy omni-search. Default: copy the best match's password to the clipboard (model-blind,
/// C39) and record the use so it ranks higher next time. `--stdout`: print the ranked match titles
/// only (no secret, no clipboard, no state change) — scriptable. The query is never echoed back or
/// logged (C37); it searches non-secret metadata only (titles/usernames/urls/tags — C35).
fn cmd_find(path: &Path, query: &str, stdout: bool, timeout: u64, opts: &OpenOpts) -> CmdResult {
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    let now = now_unix().max(0) as u64;

    // Results borrow the vault immutably; extract everything needed, then drop the borrow before
    // recording the use (which mutates the vault).
    let (id, title, secret, others) = {
        let hits = vault.find(query, now);
        if hits.is_empty() {
            // Deliberately do NOT echo the query (C37 — queries are never logged).
            return Err(
                "no entry matches that search (searches title, username, url, and tags only — \
                 not passwords, notes, or secret fields; constraint C35)"
                    .to_string(),
            );
        }
        if stdout {
            for h in &hits {
                // Titles are user/import-controlled → sanitize before the terminal (C28).
                println!("{}", sanitize(&h.entry.title));
            }
            return Ok(());
        }
        let top = &hits[0];
        let others: Vec<String> = hits
            .iter()
            .skip(1)
            .take(5)
            .map(|h| sanitize(&h.entry.title))
            .collect();
        (
            top.entry.id,
            sanitize(&top.entry.title),
            top.entry.password.expose(), // owned, zeroizing (decrypt-on-access, C19)
            others,
        )
    };

    copy_secret_to_clipboard(&secret, timeout, &title)?;
    if !others.is_empty() {
        eprintln!(
            "(best of {} matches — others: {})",
            others.len() + 1,
            others.join(", ")
        );
    }

    // Learn: bump the chosen entry's frecency and persist it (inside the encrypted payload — C36).
    vault.record_use(id, now);
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    Ok(())
}

fn cmd_otp(path: &Path, name: &str, stdout: bool, opts: &OpenOpts) -> CmdResult {
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let vault = open_vault(path, password.as_bytes(), opts)?;
    let entry = vault
        .get(name)
        .ok_or_else(|| format!("no entry titled {name:?}"))?;
    let otp = entry
        .otp_secret
        .as_ref()
        .ok_or_else(|| format!("{name:?} has no 2FA secret (add one with `blindkey edit`)"))?;
    let code = blindkey_core::totp::generate_now(&otp.expose())
        .map_err(|_| "the stored 2FA secret is not valid base32".to_string())?;

    if stdout {
        println!("{}", code.code);
        eprintln!("(valid for {}s)", code.valid_for_secs);
    } else {
        copy_secret_to_clipboard(
            code.code.as_bytes(),
            code.valid_for_secs.max(1),
            &format!("2FA code for {name:?}"),
        )?;
        eprintln!("(valid {}s)", code.valid_for_secs);
    }
    Ok(())
}

fn cmd_gen(
    length: usize,
    charset: &str,
    words: Option<usize>,
    wordlist: Option<&Path>,
) -> CmdResult {
    use blindkey_core::gen::{entropy_bits, password, Charset};

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
    use blindkey_core::gen::{passphrase, passphrase_entropy_bits};
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
            blindkey_core::wordlist::BUILTIN
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

/// TPM enroll — seal OR stanza to PCR 7 via tpm2-tools (constraint C15 / S-8c).
fn cmd_enroll_tpm(path: &Path, opts: &OpenOpts) -> CmdResult {
    use blindkey_core::envelope::tpm::DEFAULT_PCR_INDEX;
    use blindkey_core::sealed::SealedContainer;

    if !blindkey_hardware::tpm::available() {
        return Err(
            "tpm2-tools not found or TPM unavailable — install tpm2-tools and ensure a TPM 2.0 device"
                .to_string(),
        );
    }
    let bytes = read_vault(path)?;
    if is_sealed_file(&bytes) {
        if SealedContainer::has_tpm_stanza(&bytes) {
            return Err(
                "this sealed container already has a TPM stanza — run `blindkey re-enroll-tpm` after PCR drift"
                    .into(),
            );
        }
        let (mut container, original, _password) = open_sealed_for_edit(path, opts)?;
        eprintln!("Sealing TPM stanza to PCR {DEFAULT_PCR_INDEX} (Secure Boot state)…");
        let (ikm, extra) =
            blindkey_hardware::tpm::seal(DEFAULT_PCR_INDEX).map_err(|e| e.to_string())?;
        container
            .set_tpm_stanza(&ikm, extra)
            .map_err(|e| e.to_string())?;
        write_sealed_preserving(path, &container, &original)?;
        eprintln!(
            "\n✅ TPM stanza enrolled on {} — unlock without password when PCR {DEFAULT_PCR_INDEX} matches.",
            path.display()
        );
        eprintln!(
            "   Password unlock still works. After firmware/kernel changes, run `blindkey re-enroll-tpm`."
        );
        return Ok(());
    }
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    eprintln!("Sealing TPM stanza to PCR {DEFAULT_PCR_INDEX} (Secure Boot state)…");
    let (ikm, extra) =
        blindkey_hardware::tpm::seal(DEFAULT_PCR_INDEX).map_err(|e| e.to_string())?;
    vault
        .set_tpm_stanza(&ikm, extra)
        .map_err(|e| e.to_string())?;
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!(
        "\n✅ TPM stanza enrolled — you can unlock without the password when PCR {DEFAULT_PCR_INDEX} matches."
    );
    eprintln!(
        "   Password unlock still works. After firmware/kernel changes, run `blindkey re-enroll-tpm`."
    );
    Ok(())
}

/// TPM re-enroll after PCR drift (constraint C15).
fn cmd_re_enroll_tpm(path: &Path, opts: &OpenOpts) -> CmdResult {
    use blindkey_core::envelope::tpm::DEFAULT_PCR_INDEX;
    use blindkey_core::sealed::SealedContainer;

    if !blindkey_hardware::tpm::available() {
        return Err(blindkey_hardware::tpm_policy::PCR_MISMATCH_MESSAGE.to_string());
    }
    let bytes = read_vault(path)?;
    if is_sealed_file(&bytes) {
        if !SealedContainer::has_tpm_stanza(&bytes) {
            return Err(
                "this sealed container has no TPM stanza — run `blindkey enroll-tpm` first".into(),
            );
        }
        let (mut container, original, _password) = open_sealed_for_edit(path, opts)?;
        eprintln!("Re-sealing TPM stanza to current PCR {DEFAULT_PCR_INDEX}…");
        let (ikm, extra) =
            blindkey_hardware::tpm::seal(DEFAULT_PCR_INDEX).map_err(|e| e.to_string())?;
        container
            .set_tpm_stanza(&ikm, extra)
            .map_err(|e| e.to_string())?;
        write_sealed_preserving(path, &container, &original)?;
        eprintln!("✅ TPM stanza re-sealed on sealed container.");
        return Ok(());
    }
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    if !vault
        .stanzas()
        .iter()
        .any(|s| s.stanza_type == blindkey_core::format::stanza::kind::TPM)
    {
        return Err("this vault has no TPM stanza — run `blindkey enroll-tpm` first".into());
    }
    eprintln!("Re-sealing TPM stanza to current PCR {DEFAULT_PCR_INDEX}…");
    let (ikm, extra) =
        blindkey_hardware::tpm::seal(DEFAULT_PCR_INDEX).map_err(|e| e.to_string())?;
    vault
        .set_tpm_stanza(&ikm, extra)
        .map_err(|e| e.to_string())?;
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("✅ TPM stanza re-sealed to current PCR values.");
    Ok(())
}

fn cmd_stanzas(path: &Path, action: crate::StanzasAction, opts: &OpenOpts) -> CmdResult {
    use blindkey_core::format::stanza::{kind, kind_name, parse_kind_name};

    match action {
        crate::StanzasAction::List => {
            let bytes = read_vault(path)?;
            if bytes.len() >= 4 && bytes[0..4] == blindkey_core::MAGIC_VLTF {
                use blindkey_core::format::Header;
                use blindkey_core::ContainerKind;
                let header = Header::parse_with_kind(&bytes, Some(ContainerKind::SealedFile))
                    .map_err(|e| e.to_string())?;
                if header.stanzas.is_empty() {
                    println!("(no stanzas)");
                    return Ok(());
                }
                for s in &header.stanzas {
                    println!("{} ({})", kind_name(s.stanza_type), s.stanza_type);
                }
                return Ok(());
            }
            let password = unlock_secret::read_master_password(false, &opts.unlock)?;
            let vault = open_vault(path, password.as_bytes(), opts)?;
            if vault.stanzas().is_empty() {
                println!("(no stanzas)");
                return Ok(());
            }
            for s in vault.stanzas() {
                println!("{} ({})", kind_name(s.stanza_type), s.stanza_type);
            }
            Ok(())
        }
        crate::StanzasAction::Add { stanza_type } => {
            let msg = match parse_kind_name(&stanza_type) {
                Some(kind::PW_YUBIKEY) | Some(kind::YUBIKEY) => {
                    "use `blindkey enroll yubikey` to add YubiKey 2FA".to_string()
                }
                Some(kind::PW_KEYFILE) => {
                    "use `blindkey enroll keyfile <PATH>` to add keyfile 2FA".to_string()
                }
                Some(kind::TPM) => "use `blindkey enroll-tpm`".to_string(),
                Some(kind::FIDO2) => "use `blindkey enroll fido2`".to_string(),
                Some(kind::PASSWORD) => {
                    "password stanza is always present at init (C5)".to_string()
                }
                Some(kind::KEYCHAIN) | Some(kind::DPAPI) => {
                    "OS keystore stanzas are planned (M7); not yet on the CLI".to_string()
                }
                Some(t) => format!("no enrollment path for `{}` yet", kind_name(t)),
                None => return Err(usage_err(format!("unknown stanza type {stanza_type:?}"))),
            };
            Err(usage_err(format!(
                "{msg}; `blindkey stanzas add` does not enroll directly"
            )))
        }
        crate::StanzasAction::Remove { stanza_type } => {
            let t = parse_kind_name(&stanza_type)
                .ok_or_else(|| usage_err(format!("unknown stanza type {stanza_type:?}")))?;
            let bytes = read_vault(path)?;
            if is_sealed_file(&bytes) {
                let (mut container, original, _password) = open_sealed_for_edit(path, opts)?;
                container.remove_stanza_type(t).map_err(|e| e.to_string())?;
                write_sealed_preserving(path, &container, &original)?;
                eprintln!("Removed {:?} stanza.", kind_name(t));
                eprintln!(
                    "hint: re-seal or rotate factors if a second factor was compromised — the \
                     inner archive body was not re-encrypted."
                );
                return Ok(());
            }
            let password = unlock_secret::read_master_password(false, &opts.unlock)?;
            let mut vault = open_vault(path, password.as_bytes(), opts)?;
            vault.remove_stanza_type(t).map_err(|e| e.to_string())?;
            let out = save_vault(&mut vault, password.as_bytes(), opts)?;
            write_vault(path, &out)?;
            note_saved(&vault);
            eprintln!("Removed {:?} stanza.", kind_name(t));
            eprintln!(
                "hint: old sync copies may still carry the removed factor; run `blindkey rotate-data-key` \
                 after a compromise (not merely device loss)."
            );
            Ok(())
        }
    }
}

/// Clear local session hygiene (UC-06 §3.4). v1 CLI is per-process — no cached unlock between
/// commands; this clears the clipboard and documents forward-compat for a future agent session.
#[cfg(unix)]
fn cmd_mcp() -> CmdResult {
    // Status-only MCP stdio server (constraint C27). The secret type never enters the MCP layer.
    blindkey_agent::serve_mcp_stdio().map_err(|e| format!("mcp server: {e}"))
}

#[cfg(not(unix))]
fn cmd_mcp() -> CmdResult {
    Err("the MCP broker requires Unix (Unix-socket broker; Windows named-pipe transport is tracked upstream)".into())
}

fn cmd_lock() -> CmdResult {
    match copy_to_clipboard(b"") {
        Ok(()) => eprintln!("Locked: clipboard cleared."),
        Err(_) => eprintln!("Locked: no clipboard tool available to clear."),
    }
    eprintln!(
        "note: the CLI keeps no unlock session between commands — secrets are zeroized when \
         each command exits."
    );
    Ok(())
}

fn cmd_add(path: &Path, name: &str, opts: &OpenOpts) -> CmdResult {
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
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
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    if generated {
        eprintln!(
            "Added {name:?} with a generated 20-char password — `blindkey get {name}` to copy it."
        );
    } else {
        eprintln!("Added {name:?}.");
    }
    Ok(())
}

fn cmd_edit(path: &Path, name: &str, opts: &OpenOpts) -> CmdResult {
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
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
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("Updated {name:?}.");
    Ok(())
}

fn cmd_rm(path: &Path, name: &str, opts: &OpenOpts) -> CmdResult {
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
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
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("Deleted {name:?}.");
    eprintln!(
        "note: entry removed from this vault file (crypto-shredded in the new blob); older \
         `.bak`/sync copies may still hold it — see docs/guides/deletion-and-rotation.md"
    );
    Ok(())
}

fn read_recovery_code_for_rotation(re_seal: bool) -> Result<Zeroizing<String>, String> {
    if !re_seal {
        return Err(
            "this vault has a recovery-code stanza — pass --re-seal-recovery and enter the \
             recovery code to keep the anti-lockout path valid"
                .to_string(),
        );
    }
    if !std::io::stdin().is_terminal() {
        return Err(
            "non-interactive session — cannot prompt for recovery code; use a TTY or omit \
             --re-seal-recovery on vaults without a recovery stanza"
                .to_string(),
        );
    }
    rpassword::prompt_password("Recovery code: ")
        .map(Zeroizing::new)
        .map_err(|e| e.to_string())
}

fn cmd_rotate_data_key(path: &Path, re_seal_recovery: bool, opts: &OpenOpts) -> CmdResult {
    use blindkey_core::format::stanza::kind;
    use blindkey_core::{Error, RotateDataKeyOptions};

    let bytes = read_vault(path)?;
    if is_sealed_file(&bytes) {
        let (mut container, original, password) = open_sealed_for_edit(path, opts)?;

        let needs_recovery = container.has_recovery_stanza();
        let recovery = if needs_recovery {
            Some(read_recovery_code_for_rotation(re_seal_recovery)?)
        } else {
            None
        };

        let keyfile: Option<Zeroizing<Vec<u8>>> = if container
            .stanzas()
            .iter()
            .any(|s| s.stanza_type == kind::PW_KEYFILE)
        {
            let kf_path = opts.keyfile.as_ref().ok_or_else(|| {
                "this sealed container requires a keyfile — pass `--keyfile <PATH>` for \
                 rotate-data-key"
                    .to_string()
            })?;
            Some(Zeroizing::new(std::fs::read(kf_path).map_err(|e| {
                format!("cannot read keyfile {}: {e}", kf_path.display())
            })?))
        } else {
            None
        };

        eprintln!("Rotating data key — re-encrypting inner archive…");
        let new_bytes = if container.has_yubikey_2fa() {
            eprintln!("Touch your YubiKey to re-seal the 2FA stanza…");
            let mut respond = |challenge: &[u8; 32]| -> Result<Zeroizing<Vec<u8>>, Error> {
                blindkey_hardware::yubikey::challenge_response(challenge).map_err(Error::Hardware)
            };
            let mut rotate_opts = RotateDataKeyOptions {
                password: password.as_bytes(),
                recovery_code: recovery.as_deref().map(|s| s.as_bytes()),
                keyfile: keyfile.as_deref().map(|k| k.as_slice()),
                yubikey_respond: Some(&mut respond),
            };
            container.rotate_data_key(&original, &mut rotate_opts)
        } else {
            let mut rotate_opts = RotateDataKeyOptions {
                password: password.as_bytes(),
                recovery_code: recovery.as_deref().map(|s| s.as_bytes()),
                keyfile: keyfile.as_deref().map(|k| k.as_slice()),
                yubikey_respond: None,
            };
            container.rotate_data_key(&original, &mut rotate_opts)
        }
        .map_err(|e| e.to_string())?;
        write_vault(path, &new_bytes)?;
        eprintln!(
            "Data key rotated on sealed container. Old exfiltrated copies stay sealed under the \
             previous key only if you stop syncing them — see docs/guides/deletion-and-rotation.md."
        );
        return Ok(());
    }

    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;

    let needs_recovery = vault.has_recovery_stanza();
    let recovery = if needs_recovery {
        Some(read_recovery_code_for_rotation(re_seal_recovery)?)
    } else {
        None
    };

    let keyfile: Option<Zeroizing<Vec<u8>>> = if vault
        .stanzas()
        .iter()
        .any(|s| s.stanza_type == kind::PW_KEYFILE)
    {
        let kf_path = opts.keyfile.as_ref().ok_or_else(|| {
            "this vault requires a keyfile — pass `--keyfile <PATH>` for rotate-data-key"
                .to_string()
        })?;
        Some(Zeroizing::new(std::fs::read(kf_path).map_err(|e| {
            format!("cannot read keyfile {}: {e}", kf_path.display())
        })?))
    } else {
        None
    };

    if vault.has_yubikey_2fa() {
        eprintln!("Touch your YubiKey to re-seal the 2FA stanza…");
        let mut respond = |challenge: &[u8; 32]| -> Result<Zeroizing<Vec<u8>>, Error> {
            blindkey_hardware::yubikey::challenge_response(challenge).map_err(Error::Hardware)
        };
        let mut rotate_opts = RotateDataKeyOptions {
            password: password.as_bytes(),
            recovery_code: recovery.as_deref().map(|s| s.as_bytes()),
            keyfile: keyfile.as_deref().map(|k| k.as_slice()),
            yubikey_respond: Some(&mut respond),
        };
        vault
            .rotate_data_key(&mut rotate_opts)
            .map_err(|e| e.to_string())?;
    } else {
        let mut rotate_opts = RotateDataKeyOptions {
            password: password.as_bytes(),
            recovery_code: recovery.as_deref().map(|s| s.as_bytes()),
            keyfile: keyfile.as_deref().map(|k| k.as_slice()),
            yubikey_respond: None,
        };
        vault
            .rotate_data_key(&mut rotate_opts)
            .map_err(|e| e.to_string())?;
    }

    eprintln!("Rotating data key — re-encrypting payload…");
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!(
        "Data key rotated. Old exfiltrated blobs stay sealed under the previous key only if you \
         stop syncing them — see docs/guides/deletion-and-rotation.md."
    );
    Ok(())
}

fn cmd_upgrade_kdf(path: &Path, m: u32, t: u32, p: u32, opts: &OpenOpts) -> CmdResult {
    blindkey_core::crypto::reject_kdf_below_floor(m, t, p).map_err(|e| e.to_string())?;
    let bytes = read_vault(path)?;
    if is_sealed_file(&bytes) {
        let (mut container, original, password) = open_sealed_for_edit(path, opts)?;
        eprintln!("Re-deriving with Argon2id (m={m} KiB, t={t}, p={p})…");
        container
            .change_kdf(password.as_bytes(), m, t, p)
            .map_err(|e| e.to_string())?;
        write_sealed_preserving(path, &container, &original)?;
        eprintln!("Upgraded KDF parameters (inner archive unchanged).");
        return Ok(());
    }
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    eprintln!("Re-deriving with Argon2id (m={m} KiB, t={t}, p={p})…");
    vault
        .change_kdf(password.as_bytes(), m, t, p)
        .map_err(|e| e.to_string())?;
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!("Upgraded KDF parameters.");
    Ok(())
}

fn cmd_tune() -> CmdResult {
    eprintln!("Benchmarking Argon2id on this machine (targeting ~300 ms)…");
    let r = blindkey_core::crypto::tune::recommend().map_err(|e| e.to_string())?;
    let mib = r.m_cost_kib / 1024;
    // The recommendation goes to stdout (scriptable); the measured time + apply hint to stderr.
    println!(
        "Recommended Argon2id: m={} KiB ({mib} MiB), t={}, p={} — measured {} ms",
        r.m_cost_kib, r.t_cost, r.p_cost, r.measured_ms
    );
    eprintln!(
        "Apply with: blindkey upgrade-kdf --kdf-m-cost {} --kdf-t-cost {} --kdf-p-cost {}",
        r.m_cost_kib, r.t_cost, r.p_cost
    );
    Ok(())
}

fn cmd_enroll(
    path: &Path,
    factor: &str,
    enroll_path: Option<&Path>,
    graceful_yubikey: bool,
    opts: &OpenOpts,
) -> CmdResult {
    match factor.to_lowercase().as_str() {
        "yubikey" | "yk" => cmd_enroll_yubikey(path, graceful_yubikey, opts),
        "keyfile" | "kf" => cmd_enroll_keyfile(path, enroll_path, opts),
        "fido2" | "fido" => cmd_enroll_fido2(path, opts),
        other => Err(format!(
            "unknown factor {other:?} (supported: yubikey, keyfile, fido2)"
        )),
    }
}

fn cmd_enroll_fido2(path: &Path, opts: &OpenOpts) -> CmdResult {
    use blindkey_core::sealed::SealedContainer;

    if !blindkey_hardware::fido2::available() {
        return Err(
            "fido2-token not found — install libfido2-tools (see docs/guides/hardware-factor-status.md)"
                .to_string(),
        );
    }
    let bytes = read_vault(path)?;
    if is_sealed_file(&bytes) {
        if SealedContainer::has_fido2_stanza(&bytes) {
            return Err("this sealed container already has a FIDO2 stanza enrolled".into());
        }
        let (mut container, original, _password) = open_sealed_for_edit(path, opts)?;
        eprintln!("Touch your security key to enroll FIDO2 hmac-secret…");
        let (extra, prf) = blindkey_hardware::fido2::enroll(container.vault_id(), None)
            .map_err(|e| e.to_string())?;
        container
            .add_fido2_stanza(&prf, extra)
            .map_err(|e| e.to_string())?;
        write_sealed_preserving(path, &container, &original)?;
        eprintln!(
            "\n✅ FIDO2 stanza enrolled on {} — touch the same key to unlock without typing the password.",
            path.display()
        );
        eprintln!("   Password unlock still works (OR envelope). Inner archive unchanged.");
        return Ok(());
    }
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    if vault
        .stanzas()
        .iter()
        .any(|s| s.stanza_type == blindkey_core::format::stanza::kind::FIDO2)
    {
        return Err("this vault already has a FIDO2 stanza enrolled".into());
    }
    eprintln!("Touch your security key to enroll FIDO2 hmac-secret…");
    let (extra, prf) =
        blindkey_hardware::fido2::enroll(vault.vault_id(), None).map_err(|e| e.to_string())?;
    vault
        .add_fido2_stanza(&prf, extra)
        .map_err(|e| e.to_string())?;
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);
    eprintln!(
        "\n✅ FIDO2 stanza enrolled — touch the same key to unlock without typing the password."
    );
    eprintln!("   Password unlock still works (OR envelope).");
    Ok(())
}

fn cmd_enroll_keyfile(path: &Path, keyfile_path: Option<&Path>, opts: &OpenOpts) -> CmdResult {
    let kf_path = keyfile_path.ok_or(
        "usage: blindkey enroll keyfile <PATH>  (the keyfile to use or create)".to_string(),
    )?;

    // Read an existing keyfile, or generate a fresh random 32-byte one at the path (0600).
    let keyfile: Zeroizing<Vec<u8>> = if kf_path.exists() {
        Zeroizing::new(std::fs::read(kf_path).map_err(|e| e.to_string())?)
    } else {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
        write_keyfile(kf_path, &bytes)?;
        eprintln!("Generated a new keyfile at {}.", kf_path.display());
        Zeroizing::new(bytes.to_vec())
    };
    if keyfile.is_empty() {
        return Err("keyfile is empty".to_string());
    }

    let bytes = read_vault(path)?;
    if is_sealed_file(&bytes) {
        let (mut container, original, password) = open_sealed_for_edit(path, opts)?;
        if container.is_2fa() {
            return Err("this sealed container already has a second factor enrolled".to_string());
        }
        let recovery = recovery_code()?;
        container
            .enroll_keyfile_2fa(password.as_bytes(), &keyfile, recovery.as_bytes())
            .map_err(|e| e.to_string())?;
        write_sealed_preserving(path, &container, &original)?;
        eprintln!(
            "\n✅ Keyfile enrolled on {} — unlock requires password AND {}.\n",
            path.display(),
            kf_path.display()
        );
        eprintln!(
            "   RECOVERY CODE — store it OFFLINE; it unlocks WITHOUT the keyfile if it's lost:\n"
        );
        eprintln!("       {recovery}\n");
        eprintln!(
            "   Unlock with:  blindkey --vault {} --keyfile {} open …",
            path.display(),
            kf_path.display()
        );
        eprintln!(
            "   Or recovery:  blindkey --vault {} --recovery open …",
            path.display()
        );
        return Ok(());
    }

    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    if vault.is_2fa() {
        return Err("this vault already has a second factor enrolled".to_string());
    }

    let recovery = recovery_code()?;
    vault
        .enroll_keyfile_2fa(password.as_bytes(), &keyfile, recovery.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);

    eprintln!(
        "\n✅ Keyfile enrolled — this vault now requires the master password AND {}.\n",
        kf_path.display()
    );
    eprintln!(
        "   Keep that keyfile on a SEPARATE device (e.g. a USB stick), not next to the vault."
    );
    eprintln!(
        "   Unlock with:  blindkey --keyfile {} <command>\n",
        kf_path.display()
    );
    eprintln!(
        "   RECOVERY CODE — store it OFFLINE; it unlocks WITHOUT the keyfile if it's lost:\n"
    );
    eprintln!("       {recovery}\n");
    eprintln!("   Unlock with it using:  blindkey --recovery <command>");
    Ok(())
}

/// Write a keyfile atomically with 0600 perms (mirrors `write_vault`).
fn write_keyfile(path: &Path, bytes: &[u8]) -> CmdResult {
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

fn cmd_enroll_yubikey(path: &Path, graceful_yubikey: bool, opts: &OpenOpts) -> CmdResult {
    use blindkey_hardware::yubikey;
    if !yubikey::available() {
        return Err(
            "no YubiKey detected — plug it in and install YubiKey Manager (`brew install ykman`)"
                .to_string(),
        );
    }

    let bytes = read_vault(path)?;
    if is_sealed_file(&bytes) {
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
        let (mut container, original, password) = open_sealed_for_edit(path, opts)?;
        if container.is_2fa() {
            return Err("this sealed container already has a second factor enrolled".to_string());
        }
        let recovery = recovery_code()?;
        container
            .enroll_yubikey_2fa(
                password.as_bytes(),
                &hw_response,
                &challenge,
                recovery.as_bytes(),
            )
            .map_err(|e| e.to_string())?;
        write_sealed_preserving(path, &container, &original)?;
        eprintln!(
            "\n✅ YubiKey enrolled on {} — unlock requires password AND the key.\n",
            path.display()
        );
        eprintln!("   RECOVERY CODE — store it OFFLINE:\n");
        eprintln!("       {recovery}\n");
        eprintln!(
            "   Unlock with:  blindkey --vault {} --recovery open …",
            path.display()
        );
        return Ok(());
    }

    // Unlock first: the data key must be in memory to re-wrap it under the new 2FA stanza.
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
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
    if graceful_yubikey {
        vault.set_yubikey_strict(false);
        eprintln!(
            "Note: graceful YubiKey mode — saves without the key will proceed with a warning."
        );
    }
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
    write_vault(path, &out)?;
    note_saved(&vault);

    eprintln!("\n✅ YubiKey enrolled — this vault now requires the master password AND the key.\n");
    eprintln!("   RECOVERY CODE — write it down and store it OFFLINE. It unlocks WITHOUT the key,");
    eprintln!("   so it is the only way back in if the key is lost:\n");
    eprintln!("       {recovery}\n");
    eprintln!("   Unlock with it using:  blindkey --recovery <command>");
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
    use blindkey_core::pad::PadMode;
    let mode = match state.to_lowercase().as_str() {
        "on" | "padme" | "true" => PadMode::Padme,
        "off" | "none" | "false" => PadMode::None,
        other => return Err(format!("unknown pad state {other:?} (use `on` or `off`)")),
    };
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let mut vault = open_vault(path, password.as_bytes(), opts)?;
    vault.set_padding(mode);
    let out = save_vault(&mut vault, password.as_bytes(), opts)?;
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
    if let Ok(p) = std::env::var("BLINDKEY_VAULT_PATH") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or("cannot determine your home directory; pass --vault <PATH>")?;
    Ok(PathBuf::from(home).join(".blindkey").join("vault.vlt"))
}

fn read_vault(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path)
        .map_err(|_| format!("no vault at {} — run `blindkey init` first", path.display()))
}

fn is_sealed_file(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == blindkey_core::MAGIC_VLTF
}

fn sealed_unlock<'a>(
    bytes: &[u8],
    password: &'a [u8],
    opts: &OpenOpts,
    keyfile_store: &'a mut Option<Zeroizing<Vec<u8>>>,
) -> Result<blindkey_core::sealed::SealedUnlock<'a>, String> {
    use blindkey_core::sealed::{SealedContainer, SealedUnlock};
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

pub(crate) fn open_sealed_for_edit(
    path: &Path,
    opts: &OpenOpts,
) -> Result<
    (
        blindkey_core::sealed::SealedContainer,
        Vec<u8>,
        Zeroizing<String>,
    ),
    String,
> {
    use blindkey_core::sealed::SealedContainer;
    let bytes = read_vault(path)?;
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    eprintln!("Deriving key (Argon2id)…");
    let mut keyfile_store = None;
    let unlock = sealed_unlock(
        bytes.as_slice(),
        password.as_bytes(),
        opts,
        &mut keyfile_store,
    )?;
    let container = if SealedContainer::requires_yubikey(&bytes) && !opts.recovery {
        eprintln!("Touch your YubiKey…");
        let mut respond =
            |challenge: &[u8; 32]| -> Result<Zeroizing<Vec<u8>>, blindkey_core::Error> {
                blindkey_hardware::yubikey::challenge_response(challenge)
                    .map_err(blindkey_core::Error::Hardware)
            };
        SealedContainer::open_with(&bytes, &unlock, Some(&mut respond))
            .map_err(|e| e.to_string())?
    } else {
        SealedContainer::open(&bytes, &unlock).map_err(|e| e.to_string())?
    };
    Ok((container, bytes, password))
}

pub(crate) fn write_sealed_preserving(
    path: &Path,
    container: &blindkey_core::sealed::SealedContainer,
    original: &[u8],
) -> Result<(), String> {
    let out = container
        .save_preserving_body(original)
        .map_err(|e| e.to_string())?;
    write_vault(path, &out)
}

/// Read + unlock the vault, warning if its KDF is below the recommended floor (constraint C2), then
/// run the rollback guard (constraint C16 — may `exit(2)` if the user won't accept a regression).
pub(crate) fn open_vault(path: &Path, password: &[u8], opts: &OpenOpts) -> Result<Vault, String> {
    let bytes = read_vault(path)?;
    eprintln!("Deriving key (Argon2id)…");

    // OR hardware stanzas (UC-09 §3.4) — only when not using recovery / 2FA paths.
    if !opts.recovery && !Vault::requires_yubikey(&bytes) && !Vault::requires_keyfile(&bytes) {
        use blindkey_core::envelope::{fido2, tpm};
        use blindkey_core::format::stanza::kind;
        use blindkey_core::format::Header;

        if Vault::has_tpm_stanza(&bytes) && blindkey_hardware::tpm::available() {
            if let Ok(header) = Header::parse(&bytes) {
                if let Some(s) = header.stanzas.iter().find(|s| s.stanza_type == kind::TPM) {
                    if let Ok(extra) = tpm::tpm_extra(s) {
                        if let Ok(ikm) = blindkey_hardware::tpm::unseal(&extra) {
                            if let Ok(v) = Vault::open_tpm(&bytes, &ikm) {
                                if matches!(
                                    v.kdf_strength(),
                                    blindkey_core::crypto::KdfStrength::BelowFloor
                                ) {
                                    eprintln!(
                                        "vault: warning — this vault's Argon2id cost is below the recommended floor; \
                                         run `blindkey upgrade-kdf` to strengthen it."
                                    );
                                }
                                rollback_guard(&v, opts);
                                return Ok(v);
                            }
                        }
                    }
                }
            }
        }
        if Vault::has_fido2_stanza(&bytes) && blindkey_hardware::fido2::available() {
            if let Ok(header) = Header::parse(&bytes) {
                if let Some(s) = header.stanzas.iter().find(|s| s.stanza_type == kind::FIDO2) {
                    if let Ok(extra) = fido2::fido2_extra(s) {
                        eprintln!("Touch your security key…");
                        if let Ok(prf) = blindkey_hardware::fido2::assert_prf(&extra) {
                            if let Ok(v) = Vault::open_fido2(&bytes, &prf) {
                                if matches!(
                                    v.kdf_strength(),
                                    blindkey_core::crypto::KdfStrength::BelowFloor
                                ) {
                                    eprintln!(
                                        "vault: warning — this vault's Argon2id cost is below the recommended floor; \
                                         run `blindkey upgrade-kdf` to strengthen it."
                                    );
                                }
                                rollback_guard(&v, opts);
                                return Ok(v);
                            }
                        }
                    }
                }
            }
        }
    }

    // A YubiKey-2FA vault needs the key's tap — unless `--recovery`, which opens via the recovery
    // code (entered at the password prompt) through the password path (UC-09 anti-lockout).
    let vault = if Vault::requires_yubikey(&bytes) && !opts.recovery {
        eprintln!("Touch your YubiKey…");
        Vault::open_2fa(&bytes, password, |challenge| {
            blindkey_hardware::yubikey::challenge_response(challenge)
                .map_err(blindkey_core::Error::Hardware)
        })
        .map_err(|e| e.to_string())?
    } else if Vault::requires_keyfile(&bytes) && !opts.recovery {
        // A keyfile-2FA vault needs both the password and the keyfile bytes — unless `--recovery`,
        // which opens via the recovery code through the password path (UC-09 anti-lockout).
        let kf_path = opts.keyfile.as_ref().ok_or_else(|| {
            "this vault requires a keyfile — pass `--keyfile <PATH>` (or `--recovery` to use the \
             recovery code)"
                .to_string()
        })?;
        let kf = Zeroizing::new(
            std::fs::read(kf_path)
                .map_err(|e| format!("cannot read keyfile {}: {e}", kf_path.display()))?,
        );
        Vault::open_keyfile(&bytes, password, &kf).map_err(|e| e.to_string())?
    } else {
        Vault::open(&bytes, password).map_err(|e| e.to_string())?
    };
    if matches!(
        vault.kdf_strength(),
        blindkey_core::crypto::KdfStrength::BelowFloor
    ) {
        eprintln!(
            "vault: warning — this vault's Argon2id cost is below the recommended floor; \
             run `blindkey upgrade-kdf` to strengthen it."
        );
    }
    rollback_guard(&vault, opts);
    Ok(vault)
}

/// Compare the opened vault's version against the local anchor (C16). On a regression: warn, then
/// prompt (TTY) or exit 2 (non-TTY) unless `--allow-rollback`. On success: advance the anchor.
fn rollback_guard(vault: &Vault, opts: &OpenOpts) {
    use blindkey_core::rollback::{self, RollbackCheck};
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
    if let Ok(anchor) = blindkey_core::rollback::anchor_path(vault.vault_id()) {
        let _ = blindkey_core::rollback::advance_anchor(&anchor, vault.version());
    }
}

/// Atomic write: temp file (0600 on Unix) in the same dir → fsync → rename over the target.
pub(crate) fn write_vault(path: &Path, bytes: &[u8]) -> CmdResult {
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

fn confirm(question: &str) -> Result<bool, String> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(matches!(s.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Write `data` to the OS clipboard with C33 concealment hints (falls back to CLI tools).
fn copy_to_clipboard(data: &[u8]) -> CmdResult {
    blindkey_clip::copy_secret(data)
}

/// Read the current clipboard contents via the platform tool, if available.
fn read_clipboard() -> Option<Vec<u8>> {
    blindkey_clip::read_clipboard()
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
        if crate::clipboard::clipboard_still_ours(&cur, &secret) {
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

/// Render control / ANSI bytes as visible escapes before writing to a terminal (constraint C28).
fn sanitize(s: &str) -> String {
    crate::terminal::sanitize_for_terminal(s)
}
