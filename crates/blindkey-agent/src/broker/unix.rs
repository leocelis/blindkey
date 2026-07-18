//! Unix-domain broker implementation.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use blindkey_core::Vault;

use crate::approval::{prompt_use, ApprovalOutcome};
use crate::audit;
use crate::handle::HandleStore;
use crate::inject::spawn_with_env;
use crate::protocol::{parse_request, UseRequest, UseResponse, UseStatus};

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub vault_path: PathBuf,
    pub socket_path: PathBuf,
}

#[derive(Debug)]
pub struct BrokerSession {
    vault: Arc<Mutex<Vault>>,
}

impl BrokerSession {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Arc::new(Mutex::new(vault)),
        }
    }

    pub fn handle_use(&self, req: &UseRequest) -> UseResponse {
        if req.op != "use" {
            return UseResponse::with_status(UseStatus::Error, "unknown op");
        }
        let mut store = match HandleStore::load() {
            Ok(s) => s,
            Err(e) => return UseResponse::with_status(UseStatus::Error, e),
        };
        let Some(handle) = store.get_mut(&req.handle) else {
            audit::log_use(&req.handle, &req.dest, "not_found");
            return UseResponse::with_status(UseStatus::NotFound, "unknown handle");
        };
        if handle.is_expired() {
            audit::log_use(&req.handle, &req.dest, "expired");
            return UseResponse::with_status(UseStatus::Expired, "handle expired");
        }
        let Some(dest) = handle.destination(&req.dest).cloned() else {
            audit::log_use(&req.handle, &req.dest, "bad_dest");
            return UseResponse::with_status(UseStatus::Denied, "destination not registered");
        };
        let title = handle.entry_title.clone();
        let field = handle.field.clone();
        let uses_left = handle.uses_remaining;
        match prompt_use(&title, &req.dest, uses_left) {
            ApprovalOutcome::Denied => {
                audit::log_use(&req.handle, &req.dest, "denied");
                return UseResponse::with_status(UseStatus::Denied, "user denied");
            }
            ApprovalOutcome::Approved => {}
        }
        let secret = {
            let vault = self.vault.lock().expect("vault mutex poisoned");
            let entry = match vault.get(&title) {
                Some(e) => e,
                None => {
                    audit::log_use(&req.handle, &req.dest, "missing_entry");
                    return UseResponse::with_status(UseStatus::Error, "entry missing");
                }
            };
            match field.as_str() {
                "password" => entry.password.expose().clone(),
                other => {
                    audit::log_use(&req.handle, &req.dest, "bad_field");
                    return UseResponse::with_status(
                        UseStatus::Error,
                        format!("unsupported field {other}"),
                    );
                }
            }
        };
        if let Err(e) = spawn_with_env(&dest.command, &dest.env_var, &secret) {
            audit::log_use(&req.handle, &req.dest, "spawn_error");
            return UseResponse::with_status(UseStatus::Error, e);
        }
        if let Some(h) = store.get_mut(&req.handle) {
            let _ = h.consume_use();
            let _ = store.save();
        }
        audit::log_use(&req.handle, &req.dest, "ok");
        UseResponse::ok()
    }
}

pub fn run_broker(session: BrokerSession, config: &BrokerConfig) -> Result<(), String> {
    if config.socket_path.exists() {
        fs::remove_file(&config.socket_path).ok();
    }
    if let Some(dir) = config.socket_path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&config.socket_path)
        .map_err(|e| format!("bind {}: {e}", config.socket_path.display()))?;
    eprintln!(
        "blindkey-agent: listening on {} (status-only IPC)",
        config.socket_path.display()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let session = session.clone();
                std::thread::spawn(move || serve_one(session, s));
            }
            Err(e) => eprintln!("blindkey-agent: accept error: {e}"),
        }
    }
    Ok(())
}

impl Clone for BrokerSession {
    fn clone(&self) -> Self {
        Self {
            vault: Arc::clone(&self.vault),
        }
    }
}

fn serve_one(session: BrokerSession, mut stream: UnixStream) {
    let reader = match stream.try_clone() {
        Ok(s) => BufReader::new(s),
        Err(e) => {
            eprintln!("blindkey-agent: clone stream: {e}");
            return;
        }
    };
    let line = match reader.lines().next() {
        Some(Ok(l)) => l,
        _ => {
            let _ = write_response(
                &mut stream,
                &UseResponse::with_status(UseStatus::Error, "empty request"),
            );
            return;
        }
    };
    let req = match parse_request(&line) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_response(&mut stream, &UseResponse::with_status(UseStatus::Error, e));
            return;
        }
    };
    let resp = session.handle_use(&req);
    let _ = write_response(&mut stream, &resp);
    let _ = stream.shutdown(Shutdown::Both);
}

fn write_response(stream: &mut UnixStream, resp: &UseResponse) -> Result<(), String> {
    let line = resp.to_json_line()?;
    stream
        .write_all(line.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| e.to_string())
}

/// Client: send one use request, read status-only response.
pub fn client_use(socket_path: &Path, handle: &str, dest: &str) -> Result<UseResponse, String> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("connect broker: {e}"))?;
    let req = UseRequest {
        op: "use".into(),
        handle: handle.into(),
        dest: dest.into(),
    };
    let body = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    stream
        .write_all(body.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim()).map_err(|e| format!("bad response: {e}"))
}
