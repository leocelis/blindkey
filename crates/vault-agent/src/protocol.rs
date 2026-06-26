//! Broker IPC — status-only responses (C27).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseRequest {
    pub op: String,
    pub handle: String,
    pub dest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseStatus {
    Ok,
    Denied,
    Expired,
    Locked,
    NotFound,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseResponse {
    pub status: UseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl UseResponse {
    pub fn ok() -> Self {
        Self {
            status: UseStatus::Ok,
            detail: None,
        }
    }

    pub fn with_status(status: UseStatus, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: Some(detail.into()),
        }
    }

    /// Serialize for the wire — must never embed secret material.
    pub fn to_json_line(&self) -> Result<String, String> {
        let s = serde_json::to_string(self).map_err(|e| e.to_string())?;
        debug_assert!(!s.contains("password") || s.contains("password field"));
        Ok(s)
    }
}

pub fn parse_request(line: &str) -> Result<UseRequest, String> {
    serde_json::from_str(line.trim()).map_err(|e| format!("invalid request: {e}"))
}
