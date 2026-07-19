//! Agent handle broker — S-13 scaffold (UC-16 option a).
//!
//! Opaque handles authorize **use** of a credential at a pre-registered destination. Tool/API
//! responses carry **status only** — never plaintext (constraint C27 forward constraint).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod approval;
mod audit;
mod broker;
mod handle;
mod inject;
mod mcp;
mod protocol;
mod store;

pub use approval::{prompt_use, ApprovalOutcome};
pub use audit::AuditEntry;
pub use broker::{run_broker, BrokerConfig, BrokerSession};
pub use handle::{AgentHandle, Destination, HandleStore};
pub use inject::spawn_with_env;
pub use mcp::{McpServer, NoApprovalExecutor, UseExecutor, PROTOCOL_VERSION};

#[cfg(unix)]
pub use mcp::BrokerProxyExecutor;
pub use protocol::{UseRequest, UseResponse, UseStatus};
pub use store::paths;

#[cfg(unix)]
pub use broker::client_use;

#[cfg(unix)]
pub use mcp::serve_stdio as serve_mcp_stdio;

/// Test-only: skip the human approval prompt when `BLINDKEY_AGENT_AUTO_APPROVE=1`.
pub fn auto_approve_enabled() -> bool {
    std::env::var_os("BLINDKEY_AGENT_AUTO_APPROVE").as_deref() == Some("1".as_ref())
}

#[cfg(test)]
mod tests {
    use super::handle::{AgentHandle, Destination, HandleStore};
    use super::protocol::{UseResponse, UseStatus};

    #[test]
    fn use_response_json_has_no_secret_shape() {
        let r = UseResponse::ok();
        let line = r.to_json_line().unwrap();
        assert!(line.contains("\"status\""));
        assert!(!line.contains("secret"));
    }

    #[test]
    fn handle_store_round_trips_in_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("BLINDKEY_AGENT_DATA_DIR", dir.path());
        let mut store = HandleStore::default();
        let id = store
            .add(AgentHandle::new(
                "svc",
                "password",
                Destination {
                    id: "env:TOKEN:/bin/echo".into(),
                    env_var: "TOKEN".into(),
                    command: "/bin/echo".into(),
                },
            ))
            .unwrap();
        let loaded = HandleStore::load().unwrap();
        assert_eq!(loaded.handles.len(), 1);
        assert_eq!(loaded.handles[0].id, id);
        std::env::remove_var("BLINDKEY_AGENT_DATA_DIR");
    }

    #[test]
    fn denied_status_serializes() {
        let r = UseResponse::with_status(UseStatus::Denied, "user denied");
        let v: serde_json::Value = serde_json::from_str(&r.to_json_line().unwrap()).unwrap();
        assert_eq!(v["status"], "denied");
    }
}
