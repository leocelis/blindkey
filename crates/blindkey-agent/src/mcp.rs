//! MCP (Model Context Protocol) stdio server — `blindkey mcp`.
//!
//! Exposes the handle broker to MCP clients (Claude Code, Cursor, …) over JSON-RPC 2.0 on
//! stdin/stdout. The security contract mirrors the Unix-socket broker (constraint C27):
//!
//! - **The MCP layer never handles secret material.** It routes requests and builds
//!   status/metadata responses only. Actual secret reads + injection happen behind a
//!   [`UseExecutor`], which returns a status-only [`UseResponse`] — the secret type never
//!   crosses into this module, so "no secret in an MCP response" is a *structural* guarantee,
//!   not a runtime check.
//! - `list_handles` returns handle **metadata only** (title, field, destination ids, limits) —
//!   never the credential.
//! - `use_handle` returns **status only**. Because an MCP server is spawned headless by its
//!   client (no TTY for a human approval prompt), delivery is delegated to the already-running
//!   Unix-socket broker (`blindkey agent run`) via [`BrokerProxyExecutor`] — reusing that
//!   broker's existing, already-tested TTY-approval flow ([`crate::approval::prompt_use`]) rather
//!   than inventing a new one. The approval prompt fires on *the broker's* terminal (a real TTY),
//!   never inside this headless process. If no broker is running, delivery gracefully falls back
//!   to `Locked` — this module never silently bypasses the human-in-the-loop. See
//!   docs/specs/UC-24 for the design and the options considered.
//!
//! The JSON-RPC handling is hand-rolled over `serde_json` (already a dependency) rather than
//! pulling an MCP SDK and its transitive tree — a smaller trusted surface for a security tool.

use serde_json::{json, Value};

use crate::handle::HandleStore;
use crate::protocol::{UseResponse, UseStatus};

/// Advertised protocol version (MCP revision this server implements handshake for).
pub const PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "blindkey";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Executes a `use_handle` request and returns a **status-only** result. Implementors read the
/// secret and inject it at the destination out of band; they MUST NOT return it here.
pub trait UseExecutor {
    fn use_handle(&mut self, handle_id: &str, destination_id: &str) -> UseResponse;
}

/// Default executor: refuses to deliver without an approval channel (headless MCP has no TTY).
/// Returns `Locked` — never a silent approval bypass. Replaced once UC-24 lands a channel.
#[derive(Debug, Default)]
pub struct NoApprovalExecutor;

impl UseExecutor for NoApprovalExecutor {
    fn use_handle(&mut self, _handle_id: &str, _destination_id: &str) -> UseResponse {
        UseResponse::with_status(
            UseStatus::Locked,
            "headless approval channel not configured; pre-authorize narrow handles with \
             `blindkey agent allow` and run the broker on a TTY (see docs/specs/UC-24)",
        )
    }
}

/// Delegates each `use_handle` request to the already-running Unix-socket broker
/// (`blindkey agent run`) over the same socket and protocol the CLI's `blindkey agent use`
/// already speaks ([`crate::broker::client_use`]). This is the "companion TTY process" design
/// from docs/specs/UC-24 §4: the human runs `blindkey agent run` interactively once (a real
/// terminal), and every use — whether from `blindkey agent use` or from an MCP client through
/// this executor — is approved on *that* terminal via the broker's existing
/// [`crate::approval::prompt_use`]. No new approval logic is introduced here; this module only
/// wires two already-tested pieces together and never touches the secret itself.
///
/// If no broker is listening (the common case — nothing pre-configured), this fails closed:
/// `Locked` with guidance, identical in spirit to [`NoApprovalExecutor`].
#[cfg(unix)]
#[derive(Debug, Default)]
pub struct BrokerProxyExecutor;

#[cfg(unix)]
impl UseExecutor for BrokerProxyExecutor {
    fn use_handle(&mut self, handle_id: &str, destination_id: &str) -> UseResponse {
        let socket_path = match crate::store::paths() {
            Ok((_, _, socket)) => socket,
            Err(e) => return UseResponse::with_status(UseStatus::Error, e),
        };
        match crate::broker::client_use(&socket_path, handle_id, destination_id) {
            Ok(resp) => resp,
            Err(_) => UseResponse::with_status(
                UseStatus::Locked,
                "no running broker to approve this use; start one on a terminal with \
                 `blindkey agent run`, then retry (see docs/specs/UC-24)",
            ),
        }
    }
}

/// The MCP server: pure request→response routing over a [`HandleStore`] and a [`UseExecutor`].
/// The stdio loop ([`serve_stdio`]) is a thin wrapper over [`Self::handle`].
#[derive(Debug)]
pub struct McpServer<E: UseExecutor> {
    store: HandleStore,
    executor: E,
}

impl<E: UseExecutor> McpServer<E> {
    pub fn new(store: HandleStore, executor: E) -> Self {
        Self { store, executor }
    }

    /// Handle one JSON-RPC message. Returns `Some(response)` for requests, `None` for
    /// notifications (which get no reply, per JSON-RPC 2.0).
    pub fn handle(&mut self, msg: &Value) -> Option<Value> {
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        // Notifications (no `id`) are acknowledged silently, per JSON-RPC 2.0 — `?` returns
        // `None` (no reply) for them.
        let id = msg.get("id").cloned()?;

        match method {
            "initialize" => Some(ok(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                    "instructions": "Blindkey handle broker. Tools return status/metadata only; \
                                     credentials are delivered out of band and never in a tool result."
                }),
            )),
            "ping" => Some(ok(id, json!({}))),
            "tools/list" => Some(ok(id, json!({ "tools": tool_specs() }))),
            "tools/call" => Some(self.call_tool(id, msg)),
            other => Some(err(id, -32601, format!("method not found: {other}"))),
        }
    }

    fn call_tool(&mut self, id: Value, msg: &Value) -> Value {
        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        match name {
            "list_handles" => tool_ok(id, json!({ "handles": self.list_handles() })),
            "use_handle" => {
                let handle_id = args.get("handle_id").and_then(Value::as_str).unwrap_or("");
                let dest_id = args
                    .get("destination_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if handle_id.is_empty() || dest_id.is_empty() {
                    return tool_err(id, "use_handle requires `handle_id` and `destination_id`");
                }
                // Delegated to the executor, which returns STATUS ONLY. The secret never
                // reaches this layer.
                let resp = self.executor.use_handle(handle_id, dest_id);
                let status = serde_json::to_value(resp.status).unwrap_or(json!("error"));
                tool_ok(id, json!({ "status": status, "detail": resp.detail }))
            }
            other => tool_err(id, format!("unknown tool: {other}")),
        }
    }

    /// Metadata-only view of registered handles — never a credential value.
    fn list_handles(&self) -> Vec<Value> {
        self.store
            .handles
            .iter()
            .map(|h| {
                json!({
                    "id": h.id,
                    "entry_title": h.entry_title,
                    "field": h.field,
                    "destinations": h.destinations.iter().map(|d| &d.id).collect::<Vec<_>>(),
                    "uses_remaining": h.uses_remaining,
                    "expires_at": h.expires_at,
                    "expired": h.is_expired(),
                })
            })
            .collect()
    }
}

fn tool_specs() -> Value {
    json!([
        {
            "name": "list_handles",
            "description": "List the credential handles this broker will broker (metadata only — \
                            never the secret). Use the returned id + a destination id with use_handle.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "use_handle",
            "description": "Request that the broker use a handle's credential at a pre-registered \
                            destination. Returns STATUS ONLY (ok/denied/locked/expired/not_found); \
                            the credential is injected at the destination and never returned here.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle_id": { "type": "string" },
                    "destination_id": { "type": "string" }
                },
                "required": ["handle_id", "destination_id"],
                "additionalProperties": false
            }
        }
    ])
}

// ── JSON-RPC 2.0 envelope helpers ────────────────────────────────────────────

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

/// MCP tool result: content array with a single JSON text block (the tool's structured payload).
fn tool_ok(id: Value, payload: Value) -> Value {
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
    ok(
        id,
        json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
    )
}

fn tool_err(id: Value, message: impl Into<String>) -> Value {
    ok(
        id,
        json!({ "content": [{ "type": "text", "text": message.into() }], "isError": true }),
    )
}

/// Serve MCP over stdin/stdout: one JSON object per line (newline-delimited JSON-RPC).
#[cfg(unix)]
pub fn serve_stdio() -> std::io::Result<()> {
    use std::io::{BufRead, Write};
    let store = HandleStore::load().unwrap_or_default();
    let mut server = McpServer::new(store, BrokerProxyExecutor);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let e = err(Value::Null, -32700, format!("parse error: {e}"));
                writeln!(stdout, "{e}")?;
                stdout.flush()?;
                continue;
            }
        };
        if let Some(resp) = server.handle(&msg) {
            writeln!(stdout, "{resp}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{AgentHandle, Destination, HandleStore};

    fn store_with_one() -> HandleStore {
        let mut s = HandleStore::default();
        s.handles.push(AgentHandle::new(
            "github",
            "password",
            Destination {
                id: "env:GH:/bin/deploy".into(),
                env_var: "GH".into(),
                command: "/bin/deploy".into(),
            },
        ));
        s
    }

    fn srv() -> McpServer<NoApprovalExecutor> {
        McpServer::new(store_with_one(), NoApprovalExecutor)
    }

    #[test]
    fn initialize_advertises_protocol_and_tools() {
        let r = srv()
            .handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
            .unwrap();
        assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(r["result"]["serverInfo"]["name"], "blindkey");
        assert!(r["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn notifications_get_no_reply() {
        // No `id` → notification → None.
        assert!(srv()
            .handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .is_none());
    }

    #[test]
    fn tools_list_exposes_the_two_tools() {
        let r = srv()
            .handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
            .unwrap();
        let names: Vec<&str> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"list_handles"));
        assert!(names.contains(&"use_handle"));
    }

    #[test]
    fn list_handles_returns_metadata_never_secret() {
        let r = srv()
            .handle(&json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params": { "name": "list_handles", "arguments": {} }
            }))
            .unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("github")); // metadata present
        assert!(text.contains("env:GH:/bin/deploy"));
        // No credential field names or values leak through.
        assert!(!text.contains("\"secret\""));
        assert!(!text.contains("\"password\":")); // "password" as the *field name* is fine; a value is not
    }

    #[test]
    fn use_handle_is_status_only_and_never_bypasses_approval() {
        let r = srv()
            .handle(&json!({
                "jsonrpc":"2.0","id":4,"method":"tools/call",
                "params": { "name": "use_handle",
                            "arguments": { "handle_id": "x", "destination_id": "env:GH:/bin/deploy" } }
            }))
            .unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        // Default executor refuses without an approval channel — Locked, not Ok.
        assert_eq!(v["status"], "locked");
        // Whatever happens, a tool result is structurally incapable of carrying the secret:
        // it only ever contains a UseStatus + detail string.
        assert!(!text.to_lowercase().contains("ghp_"));
    }

    #[test]
    fn unknown_method_is_jsonrpc_error() {
        let r = srv()
            .handle(&json!({"jsonrpc":"2.0","id":5,"method":"does/not/exist"}))
            .unwrap();
        assert_eq!(r["error"]["code"], -32601);
    }

    #[test]
    fn use_handle_requires_both_args() {
        let r = srv()
            .handle(&json!({
                "jsonrpc":"2.0","id":6,"method":"tools/call",
                "params": { "name": "use_handle", "arguments": { "handle_id": "x" } }
            }))
            .unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    /// Proves `BrokerProxyExecutor` (a) fails closed with `Locked` when no broker is listening,
    /// and (b) genuinely relays whatever status a real running broker returns — it does not
    /// invent success itself. Both cases in one test to avoid racing `XDG_RUNTIME_DIR` (a
    /// process-global env var) against other tests running in parallel.
    #[cfg(unix)]
    #[test]
    fn broker_proxy_relays_running_broker_and_fails_closed_without_one() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", dir.path());

        let mut proxy = BrokerProxyExecutor;

        // (a) Nothing listening on the socket path yet.
        let resp = proxy.use_handle("h1", "d1");
        assert_eq!(resp.status, UseStatus::Locked);
        assert!(resp.detail.unwrap().contains("blindkey agent run"));

        // (b) A fake broker answers on the exact socket path the executor resolves — proves the
        // proxy relays a real peer's response rather than fabricating one.
        let socket_path = dir.path().join("blindkey-agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut stream = stream;
            stream
                .write_all(b"{\"status\":\"denied\",\"detail\":\"fake broker said no\"}\n")
                .unwrap();
        });
        let resp = proxy.use_handle("h1", "d1");
        server.join().unwrap();
        assert_eq!(resp.status, UseStatus::Denied);
        assert_eq!(resp.detail.as_deref(), Some("fake broker said no"));

        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }
}
