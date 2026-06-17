//! `vault` — the command-line interface (constraints C20–C22, C26, C27, C29, C30).
//!
//! Secret-handling rules enforced here:
//! - Secrets are **never** accepted as CLI arguments (constraint C29) — passwords come from a
//!   no-echo prompt or stdin; entry secrets come from an imported file.
//! - `vault get` delivers to the clipboard by default; `--stdout` is a warned opt-in so an AI agent
//!   watching stdout cannot scrape the secret (constraint C27).
//!
//! MVP surface: `init`, `import`, `ls`, `get`. The rest of the surface is declared (C21) and lands
//! in later segments.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

/// Vault — a security layer for the AI era.
#[derive(Debug, Parser)]
#[command(name = "vault", version, about, long_about = None)]
struct Cli {
    /// Vault file (default: `$HOME/.vault/vault.vlt`).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Proceed past a rollback warning without prompting (does not lower the anchor). Constraint C16.
    #[arg(long, global = true)]
    allow_rollback: bool,
    /// On a fresh machine (no anchor yet), require the vault to be at least this version — a
    /// trust-on-first-use mitigation against being served an old copy (constraint C16).
    #[arg(long, global = true, value_name = "N")]
    expect_min_version: Option<u64>,
    /// Unlock a YubiKey-2FA vault with its recovery code instead of the key (anti-lockout, UC-09).
    #[arg(long, global = true)]
    recovery: bool,
    /// Keyfile to supply as the second factor when unlocking a keyfile-2FA vault.
    #[arg(long, global = true, value_name = "PATH")]
    keyfile: Option<PathBuf>,
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
    },
    /// Import secrets from a file (e.g. a messy `keys.txt`) into the vault.
    Import {
        /// Import format. Currently: `raw` (lenient `keys.txt` parser).
        #[arg(long, default_value = "raw")]
        format: String,
        /// Source file to import.
        source: PathBuf,
    },
    /// List or search entry titles (after unlock; in-memory only).
    Ls {
        #[arg(long)]
        search: Option<String>,
    },
    /// Offline health check — report weak, reused, stale, and expiring passwords (by title only).
    Audit,
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
    /// Add an entry. Secrets are read interactively, never from a flag. *(not yet implemented)*
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
    /// Edit an entry. *(not yet implemented)*
    Edit { name: String },
    /// Delete an entry (confirmation required). *(not yet implemented)*
    Rm { name: String },
    /// Clear the in-memory session. *(not yet implemented)*
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
    /// Benchmark and recommend Argon2id parameters (constraint C22). *(not yet implemented)*
    Tune,
    /// Add a required second factor (true 2FA): `vault enroll yubikey`, or
    /// `vault enroll keyfile <PATH>` (a new keyfile is generated if PATH doesn't exist).
    Enroll {
        /// Factor to enroll: `yubikey` or `keyfile`.
        factor: String,
        /// Keyfile path (for `keyfile`): used if it exists, otherwise a random one is created here.
        path: Option<PathBuf>,
    },
    /// Toggle payload size-padding so the file's exact size is hidden (UC-07 §3.2). `vault pad on|off`.
    Pad {
        /// `on` to enable Padmé size-padding, `off` to disable it.
        state: String,
    },
    /// Internal: detached clipboard auto-clear helper. Reads the secret on stdin; not for direct
    /// use (constraint C13 / UC-04).
    #[command(hide = true)]
    HoldClipboard { secs: u64 },
}

fn main() -> std::process::ExitCode {
    vault_core::memory::harden_process(); // C25: disable core dumps before touching secrets
    let cli = Cli::parse();
    let opts = commands::OpenOpts {
        allow_rollback: cli.allow_rollback,
        expect_min_version: cli.expect_min_version,
        recovery: cli.recovery,
        keyfile: cli.keyfile,
    };
    // A rollback abort exits with code 2 from inside the open path (constraint C16); a normal
    // failure returns Err and maps to 1.
    match commands::dispatch(cli.vault, &opts, cli.command) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
