//! Append-only local audit (UC-16 §3.4) — metadata only, never secrets.

use serde::Serialize;

use crate::store;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry<'a> {
    pub ts: u64,
    pub handle: &'a str,
    pub destination: &'a str,
    pub outcome: &'a str,
}

pub fn log(entry: AuditEntry<'_>) -> Result<(), String> {
    let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
    store::append_jsonl(&store::audit_path(), &line)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn log_use(handle: &str, destination: &str, outcome: &str) {
    let _ = log(AuditEntry {
        ts: now_secs(),
        handle,
        destination,
        outcome,
    });
}
