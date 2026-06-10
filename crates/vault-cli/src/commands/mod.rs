//! Command dispatch (constraints C20–C22, C26, C27).
//!
//! Each arm is a scaffold; implementations land in M6. The dispatcher exists so the CLI surface
//! and help text are reviewable now.

use crate::Command;

/// Route a parsed command to its handler.
pub fn dispatch(command: Command) -> Result<(), String> {
    match command {
        Command::Init { .. } => todo!("M5/M6: create vault"),
        Command::Add { .. } => todo!("M6: add entry (read secret via no-echo prompt, not argv)"),
        Command::Get { .. } => todo!("M6: clipboard-default delivery; --stdout warned opt-in (C27)"),
        Command::Gen { .. } => todo!("M6: CSPRNG generator with rejection sampling (C26)"),
        Command::Ls { .. } => todo!("M6: in-memory search after unlock (C18/C21)"),
        Command::Edit { .. } => todo!("M6: edit entry"),
        Command::Rm { .. } => todo!("M6: delete entry with confirmation"),
        Command::Lock => todo!("M6: clear in-memory session"),
        Command::Tune => todo!("M6: Argon2id benchmark + recommendation (C22)"),
    }
}
