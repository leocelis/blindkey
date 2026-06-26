//! Unix-socket broker — one unlocked vault session, human gate per use.

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::{
    client_use, run_broker, BrokerConfig, BrokerSession,
};

#[cfg(not(unix))]
compile_error!("vault-agent broker requires Unix (S-13 scaffold)");
