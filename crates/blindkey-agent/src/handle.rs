//! Opaque agent handles — capabilities, not secrets (UC-16 §3.1).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::getrandom;
use serde::{Deserialize, Serialize};

use crate::store;

/// A pre-registered injection target (agent may only choose among these).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// Stable id sent on the wire, e.g. `env:GITHUB_TOKEN:/usr/local/bin/deploy`.
    pub id: String,
    /// Environment variable to set in the child process.
    pub env_var: String,
    /// Command to spawn (argv[0]); broker injects the secret into the child's environment.
    pub command: PathBuf,
}

/// User-created capability token — possession authorizes *asking*, not *reading*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHandle {
    pub id: String,
    pub entry_title: String,
    pub field: String,
    pub destinations: Vec<Destination>,
    pub created_at: u64,
    pub expires_at: u64,
    pub uses_remaining: u32,
}

impl AgentHandle {
    /// Create a new handle with conservative defaults (1 h TTL, 10 uses).
    pub fn new(
        entry_title: impl Into<String>,
        field: impl Into<String>,
        destination: Destination,
    ) -> Self {
        let now = now_secs();
        Self {
            id: random_id(),
            entry_title: entry_title.into(),
            field: field.into(),
            destinations: vec![destination],
            created_at: now,
            expires_at: now + 3600,
            uses_remaining: 10,
        }
    }

    pub fn destination(&self, dest_id: &str) -> Option<&Destination> {
        self.destinations.iter().find(|d| d.id == dest_id)
    }

    pub fn is_expired(&self) -> bool {
        now_secs() >= self.expires_at
    }

    pub fn consume_use(&mut self) -> bool {
        if self.uses_remaining == 0 {
            return false;
        }
        self.uses_remaining -= 1;
        true
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HandleStore {
    pub handles: Vec<AgentHandle>,
}

impl HandleStore {
    pub fn load() -> Result<Self, String> {
        store::read_json(&store::handles_path())
    }

    pub fn save(&self) -> Result<(), String> {
        store::write_json(&store::handles_path(), self)
    }

    pub fn add(&mut self, handle: AgentHandle) -> Result<String, String> {
        let id = handle.id.clone();
        self.handles.push(handle);
        self.save()?;
        Ok(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut AgentHandle> {
        self.handles.iter_mut().find(|h| h.id == id)
    }

    pub fn remove(&mut self, id: &str) -> Result<bool, String> {
        let before = self.handles.len();
        self.handles.retain(|h| h.id != id);
        if self.handles.len() != before {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    getrandom(&mut b).expect("OsRng");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_lookup_is_exact() {
        let h = AgentHandle::new(
            "github",
            "password",
            Destination {
                id: "env:GH:/bin/deploy".into(),
                env_var: "GH".into(),
                command: "/bin/deploy".into(),
            },
        );
        assert!(h.destination("env:GH:/bin/deploy").is_some());
        assert!(h.destination("env:OTHER:/bin/deploy").is_none());
    }
}
