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
    /// Generate a CSPRNG password (constraint C26). *(not yet implemented)*
    Gen {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long, default_value = "ascii")]
        charset: String,
        #[arg(long)]
        words: Option<usize>,
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
    /// Internal: detached clipboard auto-clear helper. Reads the secret on stdin; not for direct
    /// use (constraint C13 / UC-04).
    #[command(hide = true)]
    HoldClipboard { secs: u64 },
}

fn main() -> std::process::ExitCode {
    vault_core::memory::harden_process(); // C25: disable core dumps before touching secrets
    let cli = Cli::parse();
    match commands::dispatch(cli.vault, cli.command) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
