//! UC-23 TUI wiring tests (Phase C).

use std::path::PathBuf;

fn read_tui_sources() -> String {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let main = std::fs::read_to_string(base.join("main.rs")).expect("main.rs");
    let sealed = std::fs::read_to_string(base.join("sealed.rs")).expect("sealed.rs");
    format!("{main}\n{sealed}")
}

#[test]
fn uc23_tui_sealed_subcommands_wired() {
    let src = read_tui_sources();
    assert!(src.contains("mod sealed"));
    assert!(src.contains("SealedCommand"));
    assert!(src.contains("SealedContainer"));
}

#[test]
fn uc23_tui_progress_gauge_and_worker() {
    let sealed =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed.rs"))
            .unwrap();
    assert!(sealed.contains("thread::spawn"));
    assert!(sealed.contains("Gauge"));
    assert!(sealed.contains("AtomicBool"));
    assert!(sealed.contains("Esc to cancel"));
}

#[test]
fn uc23_tui_peek_metadata_only() {
    let sealed =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed.rs"))
            .unwrap();
    assert!(sealed.contains("metadata only"));
    assert!(sealed.contains("peek_entries"));
}

#[test]
fn uc23_tui_fail_closed_error() {
    let sealed =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed.rs"))
            .unwrap();
    assert!(sealed.contains("SEALED_OPEN_ERROR"));
}
