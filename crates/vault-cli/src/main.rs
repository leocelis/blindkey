//! `vault` — the command-line interface (constraints C20–C22, C26, C27).
//!
//! Secret-handling rules enforced here:
//! - Secrets are **never** accepted as CLI arguments (coverage-gap B1).
//! - `vault get` delivers to the clipboard by default; `--stdout` is a warned opt-in so an AI agent
//!   watching stdout cannot scrape the secret (constraint C27).
//!
//! **Pre-alpha scaffold:** command wiring is sketched; behavior lands in M6 (`ROADMAP.md`).

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

mod commands;

/// Vault — security for the AI era.
#[derive(Debug, Parser)]
#[command(name = "vault", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new vault (prompts for a master password).
    Init {
        /// Vault file path.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
    /// Add an entry. Secrets are read interactively, never from a flag.
    Add { name: String },
    /// Get a field — to the clipboard by default. Use --stdout to print (with a warning).
    Get {
        name: String,
        #[arg(long, default_value = "password")]
        field: String,
        /// Print the secret to stdout (WARNING: readable by other processes / AI agents).
        #[arg(long)]
        stdout: bool,
    },
    /// Generate a CSPRNG password (constraint C26).
    Gen {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long, default_value = "ascii")]
        charset: String,
        #[arg(long)]
        words: Option<usize>,
    },
    /// List or search entry names (after unlock; in-memory only).
    Ls {
        #[arg(long)]
        search: Option<String>,
    },
    /// Edit an entry.
    Edit { name: String },
    /// Delete an entry (confirmation required).
    Rm { name: String },
    /// Clear the in-memory session.
    Lock,
    /// Benchmark and recommend Argon2id parameters for this machine (constraint C22).
    Tune,
}

fn main() -> std::process::ExitCode {
    // Apply process hardening (core-dump off, anti-ptrace) before doing anything (constraint C25).
    // vault_core::memory::harden_process();  // enabled in M4

    let cli = Cli::parse();
    match commands::dispatch(cli.command) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
