//! Child-process env injection (UC-16 §3.2) — secret never crosses the agent boundary.

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

/// Spawn `command` with `env_var=secret` set. Returns child exit status.
pub fn spawn_with_env(command: &Path, env_var: &str, secret: &[u8]) -> Result<ExitStatus, String> {
    let value = std::str::from_utf8(secret)
        .map_err(|_| "secret must be utf-8 for env injection in this scaffold".to_string())?;
    let status = Command::new(command)
        .env(env_var, value)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn {}: {e}", command.display()))?;
    Ok(status)
}
