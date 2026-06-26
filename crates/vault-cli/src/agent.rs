//! Agent CLI — `vault agent …` (S-13 scaffold).

use std::path::{Path, PathBuf};

use vault_agent::{
    client_use, run_broker, AgentHandle, BrokerConfig, BrokerSession, Destination, HandleStore,
};
use vault_agent::paths;

use crate::commands::{open_vault, OpenOpts};
use crate::unlock_secret;

type AgentResult = Result<(), String>;

pub fn dispatch(vault_path: &Path, opts: &OpenOpts, action: AgentAction) -> AgentResult {
    match action {
        AgentAction::Allow {
            name,
            field,
            dest_env,
            for_cmd,
        } => cmd_allow(vault_path, &name, &field, &dest_env, Some(for_cmd.as_path())),
        AgentAction::List => cmd_list(),
        AgentAction::Revoke { handle } => cmd_revoke(&handle),
        AgentAction::Run => cmd_run(vault_path, opts),
        AgentAction::Use { handle, dest } => cmd_use(&handle, &dest),
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum AgentAction {
    /// Register an opaque handle for agent use at one env-injection destination.
    Allow {
        /// Entry title (must exist in the vault).
        name: String,
        #[arg(long, default_value = "password")]
        field: String,
        /// Environment variable to set in the spawned child.
        #[arg(long)]
        dest_env: String,
        /// Command the broker spawns (secret injected into its environment).
        #[arg(long)]
        for_cmd: PathBuf,
    },
    /// List registered handles (metadata only — no secrets).
    List,
    /// Revoke a handle by id.
    Revoke { handle: String },
    /// Run the local broker (unlock vault, listen on Unix socket).
    Run,
    /// Request a one-shot use via the running broker (status-only response).
    Use { handle: String, dest: String },
}

fn cmd_allow(
    _vault_path: &Path,
    name: &str,
    field: &str,
    dest_env: &str,
    for_cmd: Option<&Path>,
) -> AgentResult {
    let cmd = for_cmd.ok_or("usage: vault agent allow NAME --dest-env VAR --for-cmd /path/to/cmd")?;
    let dest_id = format!("env:{dest_env}:{}", cmd.to_string_lossy());
    let handle = AgentHandle::new(
        name,
        field,
        Destination {
            id: dest_id.clone(),
            env_var: dest_env.to_string(),
            command: cmd.to_path_buf(),
        },
    );
    let mut store = HandleStore::load()?;
    let id = store.add(handle)?;
    eprintln!("Handle created: {id}");
    eprintln!("Destination id: {dest_id}");
    eprintln!("Start broker: vault agent run");
    Ok(())
}

fn cmd_list() -> AgentResult {
    let store = HandleStore::load()?;
    if store.handles.is_empty() {
        eprintln!("No agent handles registered.");
        return Ok(());
    }
    for h in &store.handles {
        eprintln!(
            "{}  entry={:?}  field={}  uses={}  expires={}",
            h.id, h.entry_title, h.field, h.uses_remaining, h.expires_at
        );
        for d in &h.destinations {
            eprintln!("    dest {}", d.id);
        }
    }
    Ok(())
}

fn cmd_revoke(handle: &str) -> AgentResult {
    if HandleStore::load()?.remove(handle)? {
        eprintln!("Revoked {handle}");
    } else {
        return Err(format!("unknown handle {handle}"));
    }
    Ok(())
}

fn cmd_run(vault_path: &Path, opts: &OpenOpts) -> AgentResult {
    let password = unlock_secret::read_master_password(false, &opts.unlock)?;
    let vault = open_vault(vault_path, password.as_bytes(), opts)?;
    let session = BrokerSession::new(vault);
    let config = BrokerConfig {
        vault_path: vault_path.to_path_buf(),
        socket_path: paths()?.2,
    };
    run_broker(session, &config)
}

fn cmd_use(handle: &str, dest: &str) -> AgentResult {
    let resp = client_use(&paths()?.2, handle, dest)?;
    println!("{}", serde_json::to_string(&resp).map_err(|e| e.to_string())?);
    Ok(())
}
