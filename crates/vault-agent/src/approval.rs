//! OS-owned approval surface (UC-16 §3.3) — not agent-mediated.

use std::io::{IsTerminal, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Denied,
}

/// Prompt on stderr; default deny. Returns Approved when `VAULT_AGENT_AUTO_APPROVE=1` (tests only).
pub fn prompt_use(entry_title: &str, destination_id: &str, uses_remaining: u32) -> ApprovalOutcome {
    if crate::auto_approve_enabled() {
        return ApprovalOutcome::Approved;
    }
    if !std::io::stdin().is_terminal() {
        return ApprovalOutcome::Denied;
    }
    eprintln!(
        "\nvault-agent: allow secret use?\n  entry: {entry_title}\n  destination: {destination_id}\n  uses left: {uses_remaining}\n"
    );
    eprint!("Approve this one use? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return ApprovalOutcome::Denied;
    }
    match line.trim().to_lowercase().as_str() {
        "y" | "yes" => ApprovalOutcome::Approved,
        _ => ApprovalOutcome::Denied,
    }
}
