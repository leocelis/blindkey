//! Local persistence for handles and audit (C23 — never leaves the machine).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Serialize};

pub fn data_dir() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("VAULT_AGENT_DATA_DIR") {
        return Ok(PathBuf::from(p));
    }
    #[cfg(target_os = "macos")]
    {
        let home = home_dir()?;
        return Ok(home.join("Library/Application Support/vault"));
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA not set")?;
        return Ok(PathBuf::from(base).join("vault"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir().ok().map(|h| h.join(".local/share")))?;
        return Ok(base.join("vault"));
    }
}

pub fn handles_path() -> PathBuf {
    data_dir()
        .unwrap_or_else(|_| PathBuf::from(".vault-agent-test"))
        .join("agent-handles.json")
}

pub fn audit_path() -> PathBuf {
    data_dir()
        .unwrap_or_else(|_| PathBuf::from(".vault-agent-test"))
        .join("agent-audit.jsonl")
}

pub fn socket_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("vault-agent.sock");
    }
    data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("agent.sock")
}

pub fn paths() -> Result<(PathBuf, PathBuf, PathBuf), String> {
    Ok((handles_path(), audit_path(), socket_path()))
}

pub fn read_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T, String> {
    if !path.exists() {
        return Ok(T::default());
    }
    let s = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if s.trim().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_str(&s).map_err(|e| format!("parse {}: {e}", path.display()))
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let body = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(&tmp, &body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

pub fn append_jsonl(path: &Path, line: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open audit {}: {e}", path.display()))?;
    f.write_all(line.as_bytes())
        .and_then(|_| f.write_all(b"\n"))
        .map_err(|e| format!("append audit: {e}"))
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME not set".to_string())
}
