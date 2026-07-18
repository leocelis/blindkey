//! GUI in-app TOTP regression .
//!

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn gui_main_shows_totp_in_app_without_clipboard() {
    let gui = read_repo_file("crates/blindkey-gui/src/main.rs");
    assert!(
        gui.contains("otp_display") || gui.contains("generate_now"),
        "GUI must render live TOTP"
    );
    assert!(
        gui.contains("In-app only") && gui.contains("not copied to clipboard"),
        "GUI must state in-app-only TOTP policy"
    );
    assert!(
        !gui.contains("copy_otp") && !gui.contains("CopyOtp"),
        "GUI must not copy TOTP to clipboard"
    );
    assert!(
        gui.contains("enforce_otp_live_refresh"),
        "GUI must tick TOTP countdown"
    );
    assert!(
        gui.contains("copy_password"),
        "password clipboard path must remain"
    );
}

#[test]
fn research_doc_exists() {
    let research = read_repo_file("research/gui_totp_in_app_research.md");
    assert!(research.contains("clipboard") && research.contains("In-app only"));
}
