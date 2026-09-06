//! UC-30 GUI Blindfolder wiring (W3) — static source checks.

use std::path::PathBuf;

fn src(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap_or_else(|_| panic!("read {name}"))
}

#[test]
fn uc30_blindfolder_cta_and_open() {
    let vol = src("volume_gui.rs");
    assert!(
        vol.contains("Open Blindfolder"),
        "Workspace must expose Open Blindfolder"
    );
    assert!(
        vol.contains("open_blindfolder") || vol.contains("choose_and_open_blindfolder"),
        "Blindfolder checkout entry point required"
    );
    assert!(
        vol.contains("Resume Blindfolder?"),
        "E2 resume dialog title required"
    );
    assert!(
        vol.contains("Resume checkin"),
        "E2 resume action required"
    );
    let cta = vol
        .lines()
        .find(|l| l.contains("Open Blindfolder (checkout)") || l.contains("Use Open Blindfolder"))
        .or_else(|| {
            vol.lines()
                .find(|l| l.contains("Blindfolder") && l.contains("Seal"))
        });
    assert!(
        cta.is_some() || vol.contains("Open Blindfolder (checkout)"),
        "C73 CTA must mention Blindfolder + Seal"
    );
}

#[test]
fn uc30_eject_checkin_and_e9() {
    let vol = src("volume_gui.rs");
    assert!(
        vol.contains("checkin_with") || vol.contains(".checkin("),
        "Eject Blindfolder must checkin"
    );
    assert!(
        vol.contains("has_unresolved_conflicts"),
        "E9 conflict refuse required"
    );
    assert!(
        vol.contains("coordinated: cfg!(target_os = \"macos\")")
            || vol.contains("CheckinOpts"),
        "macOS coordinated checkin path required"
    );
}

#[test]
fn uc30_materialized_mount_on_unlock() {
    let vol = src("volume_gui.rs");
    let main = src("main.rs");
    assert!(
        vol.contains("MaterializedMount"),
        "Blindfolder unlock must open a cleartext working folder"
    );
    assert!(
        vol.contains("macos-fuse") || vol.contains("macfuse"),
        "GUI must document optional macos-fuse feature path"
    );
    assert!(
        vol.contains("orphaned_cleartext_sessions"),
        "resume scan must include leftover cleartext mnt"
    );
    assert!(
        vol.contains("MOUNTED"),
        "worker must hand off MOUNTED mount path"
    );
    assert!(
        vol.contains("live_mount"),
        "GUI must hold LiveMount until eject"
    );
    assert!(
        vol.contains("prepare_quit"),
        "VolumeGui must expose prepare_quit"
    );
    assert!(
        main.contains("prepare_quit") && main.contains("close_requested"),
        "app quit must call prepare_quit"
    );
}
