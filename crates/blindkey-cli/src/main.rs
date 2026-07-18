//! `blindkey` — the command-line interface (constraints C20–C22, C26, C27, C29, C30).
//!
//! Secret-handling rules enforced here:
//! - Secrets are **never** accepted as CLI arguments (constraint C29) — passwords come from a
//!   no-echo prompt or stdin; entry secrets come from an imported file.
//! - `blindkey get` delivers to the clipboard by default; `--stdout` is a warned opt-in so an AI
//!   agent watching stdout cannot scrape the secret (constraint C27).

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod agent;
mod clipboard;
mod commands;
mod export;
mod terminal;
mod unlock_secret;

/// Blindkey — a local-first credential vault your AI agents can use but never see.
#[derive(Debug, Parser)]
#[command(name = "blindkey", version, about, long_about = None)]
struct Cli {
    /// Vault file (default: `$HOME/.blindkey/vault.vlt`).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Proceed past a rollback warning without prompting (does not lower the anchor). Constraint C16.
    #[arg(long, global = true)]
    allow_rollback: bool,
    /// On a fresh machine (no anchor yet), require the vault to be at least this version — a
    /// trust-on-first-use mitigation against being served an old copy (constraint C16).
    #[arg(long, global = true, value_name = "N")]
    expect_min_version: Option<u64>,
    /// Abort body-writing saves when the YubiKey is absent (constraint C5). Overrides per-vault policy.
    #[arg(long, global = true)]
    strict_yubikey: bool,
    /// Allow a body-writing save without refreshing the YubiKey stanza (graceful staleness).
    #[arg(long, global = true)]
    allow_stale_yubikey: bool,
    /// Unlock a YubiKey-2FA vault with its recovery code instead of the key (anti-lockout, UC-09).
    #[arg(long, global = true)]
    recovery: bool,
    /// Keyfile to supply as the second factor when unlocking a keyfile-2FA vault.
    #[arg(long, global = true, value_name = "PATH")]
    keyfile: Option<PathBuf>,
    /// Read the master password from file descriptor N (gopass-style; UC-05 §3.2).
    #[arg(long, global = true, value_name = "FD")]
    password_fd: Option<u32>,
    /// Read the master password from stdin (one line; required for piped non-TTY unlock).
    #[arg(long, global = true)]
    password_stdin: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new vault (prompts for a master password).
    Init {
        /// Argon2id memory cost in KiB (advanced; default 64 MiB).
        #[arg(long, hide = true, default_value_t = 65_536)]
        kdf_m_cost: u32,
        /// Argon2id time cost (advanced; default 3).
        #[arg(long, hide = true, default_value_t = 3)]
        kdf_t_cost: u32,
        /// Argon2id parallelism (advanced; default 4).
        #[arg(long, hide = true, default_value_t = 4)]
        kdf_p_cost: u32,
        /// Skip the weak-master-password warning/confirmation (for scripted setup).
        #[arg(long)]
        allow_weak_password: bool,
        /// Allow Argon2id params below the enforced floor (tests/scripts only; constraint C2).
        #[arg(long, hide = true)]
        allow_weak_kdf: bool,
        /// Generate and enroll an offline recovery-code stanza at init (gap C3).
        #[arg(long)]
        with_recovery_code: bool,
    },
    /// Import secrets from a file (e.g. a messy `keys.txt`) into the vault.
    Import {
        /// Import format. Currently: `raw` (lenient `keys.txt` parser).
        #[arg(long, default_value = "raw")]
        format: String,
        /// Source file to import.
        source: PathBuf,
        /// Accept the parsed entries without prompting (required when stdin is not a TTY).
        #[arg(long)]
        yes: bool,
    },
    /// List or search entry titles (after unlock; in-memory only).
    Ls {
        #[arg(long)]
        search: Option<String>,
    },
    /// Offline health check — report weak, reused, stale, and expiring passwords (by title only).
    Audit,
    /// Export all entries as decrypted JSON to stdout (security warning + confirmation).
    Export {
        /// Export format (v1: `json` only).
        #[arg(long, default_value = "json")]
        format: String,
        /// Skip the confirmation prompt (required when stdout is not a TTY).
        #[arg(long)]
        yes: bool,
    },
    /// Generate the current 2FA (TOTP) code for an entry — to the clipboard by default.
    Otp {
        name: String,
        /// Print the code to stdout instead of copying it (readable by other processes).
        #[arg(long)]
        stdout: bool,
    },
    /// Fuzzy omni-search (UC-19): type a few characters, copy the best match's password to the
    /// clipboard. `--stdout` lists the ranked matches (titles only) instead. Searches titles,
    /// usernames, urls, and tags — never secret values.
    Find {
        /// Fuzzy query (omit to browse all entries, most-used first).
        query: Option<String>,
        /// List ranked matches (titles only) to stdout instead of copying — scriptable, no secret.
        #[arg(long)]
        stdout: bool,
        /// Seconds before the clipboard auto-clears (0 = never). Constraint C13.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Get a field — to the clipboard by default. `--stdout` prints it (with a warning).
    Get {
        name: String,
        #[arg(long, default_value = "password")]
        field: String,
        /// Print the secret to stdout (WARNING: readable by other processes / AI agents).
        #[arg(long)]
        stdout: bool,
        /// Seconds before the clipboard auto-clears (0 = never). Constraint C13.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Add an entry. Secrets are read interactively, never from a flag.
    Add { name: String },
    /// Generate a CSPRNG password — or a diceware passphrase with `--words N` (constraint C26).
    Gen {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long, default_value = "ascii")]
        charset: String,
        /// Generate a diceware passphrase of N words instead of a character password.
        #[arg(long)]
        words: Option<usize>,
        /// Wordlist file for `--words` (e.g. the EFF large list); defaults to a built-in 256-word list.
        #[arg(long)]
        wordlist: Option<PathBuf>,
    },
    /// Edit an entry.
    Edit { name: String },
    /// Delete an entry (confirmation required).
    Rm { name: String },
    /// Clear the in-memory session (clipboard; v1 CLI has no cross-command unlock cache).
    Lock,
    /// Re-encrypt the vault with stronger Argon2id parameters (constraint C2).
    UpgradeKdf {
        /// Argon2id memory cost in KiB (default 64 MiB).
        #[arg(long, default_value_t = 65_536)]
        kdf_m_cost: u32,
        /// Argon2id time cost (default 3).
        #[arg(long, default_value_t = 3)]
        kdf_t_cost: u32,
        /// Argon2id parallelism (default 4).
        #[arg(long, default_value_t = 4)]
        kdf_p_cost: u32,
    },
    /// Generate a fresh data key and re-wrap all stanzas (gap C2 — forward secrecy).
    RotateDataKey {
        /// Re-seal the anti-lockout recovery-code stanza (required when 2FA enrolled).
        #[arg(long)]
        re_seal_recovery: bool,
    },
    /// Benchmark and recommend Argon2id parameters (constraint C22).
    Tune,
    /// List, add, or remove hardware/OS unlock stanzas (constraint C21).
    Stanzas {
        #[command(subcommand)]
        action: StanzasAction,
    },
    /// Add a required second factor (true 2FA): `blindkey enroll yubikey`, or
    /// `blindkey enroll keyfile <PATH>`. Additive OR factors: `blindkey enroll fido2`.
    Enroll {
        /// Factor to enroll: `yubikey`, `keyfile`, or `fido2`.
        factor: String,
        /// Keyfile path (for `keyfile`): used if it exists, otherwise a random one is created here.
        path: Option<PathBuf>,
        /// Allow saves without the YubiKey present (graceful staleness — not recommended).
        #[arg(long)]
        graceful_yubikey: bool,
    },
    /// Toggle payload size-padding so the file's exact size is hidden (UC-07 §3.2). `blindkey pad on|off`.
    Pad {
        /// `on` to enable Padmé size-padding, `off` to disable it.
        state: String,
    },
    /// Seal a TPM stanza to the current PCR policy (Linux/Windows — requires tpm2-tools).
    ///
    /// Default policy: PCR 7 (Secure Boot certificate state). PCR values change after firmware
    /// or kernel updates — run `blindkey re-enroll-tpm` to re-seal.
    EnrollTpm,
    /// Re-seal the TPM stanza after firmware or kernel updates changed PCR values (constraint C15).
    ///
    /// Unseals with the current PCR policy, re-seals to new PCRs, and updates the TPM stanza.
    ReEnrollTpm,
    /// Model-blind agent broker — opaque handles + OS approval gate (S-13 / UC-16 scaffold).
    Agent {
        #[command(subcommand)]
        action: crate::agent::AgentAction,
    },
    /// Seal files or folders into one `.vltf` container (UC-23).
    Seal {
        /// File or directory paths to seal (sorted deterministically).
        paths: Vec<PathBuf>,
        /// Output container path (default: `<first-stem>.vltf`).
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Disable Padmé size-padding (default: on — C66).
        #[arg(long)]
        no_pad: bool,
        /// Allow Argon2id params below the enforced floor (tests/scripts only).
        #[arg(long, hide = true)]
        allow_weak_kdf: bool,
        /// Argon2id memory cost in KiB (advanced; default 64 MiB).
        #[arg(long, hide = true, default_value_t = 65_536)]
        kdf_m_cost: u32,
        /// Argon2id time cost (advanced; default 3).
        #[arg(long, hide = true, default_value_t = 3)]
        kdf_t_cost: u32,
        /// Argon2id parallelism (advanced; default 4).
        #[arg(long, hide = true, default_value_t = 4)]
        kdf_p_cost: u32,
        /// Merge new paths into an existing `.vltf` (requires `-o` pointing at the container).
        #[arg(long)]
        append: bool,
    },
    /// Extract a sealed `.vltf` container to a directory (UC-23).
    Open {
        /// Sealed container file.
        file: PathBuf,
        /// Destination directory (default: current directory).
        #[arg(short = 'C', value_name = "DIR")]
        dest: Option<PathBuf>,
        /// Write a single small file to stdout (size-capped; warned opt-in — SC9/C27).
        #[arg(long)]
        stdout: bool,
    },
    /// List inner paths and sizes after unlock — never file contents (UC-23 / C27).
    Peek {
        /// Sealed container file.
        file: PathBuf,
    },
    /// Internal: detached clipboard auto-clear helper. Reads the secret on stdin; not for direct
    /// use (constraint C13 / UC-04).
    #[command(hide = true)]
    HoldClipboard { secs: u64 },
}

#[derive(Debug, Subcommand)]
pub enum StanzasAction {
    /// Show enrolled stanza types (no secrets).
    List,
    /// Enroll guidance for a stanza type (delegates to `blindkey enroll …`).
    Add { stanza_type: String },
    /// Remove a non-password stanza (requires unlock).
    Remove { stanza_type: String },
}

fn main() -> std::process::ExitCode {
    blindkey_core::memory::harden_process(); // C25: disable core dumps before touching secrets
    let cli = Cli::parse();
    let opts = commands::OpenOpts {
        allow_rollback: cli.allow_rollback,
        expect_min_version: cli.expect_min_version,
        strict_yubikey: cli.strict_yubikey,
        allow_stale_yubikey: cli.allow_stale_yubikey,
        recovery: cli.recovery,
        keyfile: cli.keyfile,
        unlock: unlock_secret::UnlockSecretOpts {
            password_fd: cli.password_fd,
            password_stdin: cli.password_stdin,
        },
    };
    // A rollback abort exits with code 2 from inside the open path (constraint C16); a normal
    // failure returns Err and maps to 1.
    match commands::dispatch(cli.vault, &opts, cli.command) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let code = if e.starts_with(commands::USAGE_ERROR_PREFIX) {
                8
            } else if e.starts_with(commands::CLIPBOARD_UNAVAILABLE_PREFIX) {
                7
            } else if e.starts_with(unlock_secret::AUTH_ERROR_PREFIX) {
                5
            } else {
                1
            };
            let msg = e
                .strip_prefix(commands::USAGE_ERROR_PREFIX)
                .or_else(|| e.strip_prefix(commands::CLIPBOARD_UNAVAILABLE_PREFIX))
                .map(|s| s.trim_start())
                .unwrap_or(&e);
            eprintln!("vault: {msg}");
            std::process::ExitCode::from(code)
        }
    }
}
