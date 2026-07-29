//! UC-25 volume GUI constraint wiring (Phase C). Static source checks like the UC-23 suite;
//! behavioural unit tests of the pure helpers live in `src/volume_gui.rs` `#[cfg(test)]`.

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
fn uc25_volume_module_wired_into_app() {
    let main = src("main.rs");
    assert!(main.contains("mod volume_gui"));
    assert!(main.contains("volume_gui::VolumeGui"));
    assert!(main.contains("self.volume.poll_worker"));
    assert!(main.contains("self.volume.windows"));
    assert!(main.contains("self.volume.handle_drops"));
    // UC-26: Create / Unlock live on Workspace home (not top-bar Action enum).
    assert!(main.contains("workspace_home") || main.contains("self.volume.workspace_home"));
    let vol = src("volume_gui.rs");
    assert!(vol.contains("open_create_dialog"));
    assert!(
        vol.contains("Button::new(\"Create volume\")")
            || vol.contains("primary_button(ui, \"Create volume\""),
        "Workspace home must expose Create volume"
    );
    assert!(
        vol.contains("Button::new(\"Unlock\")") || vol.contains("primary_button(ui, \"Unlock\""),
        "Workspace home must expose Unlock"
    );
}

#[test]
fn uc25_calls_core_volume_api_only() {
    let v = src("volume_gui.rs");
    assert!(v.contains("blindkey_core::volume") || v.contains("use blindkey_core::"));
    assert!(v.contains("Volume::create"));
    assert!(v.contains("Volume::open"));
    // Thin shell: no bespoke crypto primitives in the UI.
    assert!(!v.contains("XChaCha20"));
    assert!(!v.contains("Argon2"));
}

#[test]
fn uc25_worker_thread_and_cancel_like_sealed() {
    let v = src("volume_gui.rs");
    assert!(v.contains("thread::spawn"));
    assert!(v.contains("AtomicBool"));
    assert!(v.contains("request_repaint_after"));
    assert!(v.contains("fn cancel"));
    assert!(v.contains("Cancel"));
}

#[test]
fn uc25_residual_risk_banner_once_per_session() {
    let v = src("volume_gui.rs");
    assert!(v.contains("RESIDUAL_RISK_BANNER"));
    assert!(v.contains("banner_acknowledged"));
    assert!(v.contains("fn banner_pending"));
    // Honest copy: OS sees cleartext while mounted; C27 does not cover it (SC10 / C72).
    assert!(v.contains("cleartext"));
    assert!(v.contains("C27"));
}

#[test]
fn uc25_cloud_sync_root_seal_cta_present() {
    let v = src("volume_gui.rs");
    assert!(v.contains("fn sync_root_seal_cta"));
    assert!(v.contains("fn is_under_sync_root"));
    assert!(v.contains("blindkey seal"));
    // C73: refuse live mount on a sync root and point to the sealed-file path.
    assert!(v.contains("unsupported"));
}

#[test]
fn uc25_lock_on_sleep_note_is_honest() {
    let v = src("volume_gui.rs");
    assert!(v.contains("LOCK_ON_SLEEP_NOTE"));
    assert!(v.contains("best-effort"));
}

#[test]
fn uc25_uniform_open_error_no_oracle() {
    let v = src("volume_gui.rs");
    assert!(v.contains("VOLUME_OPEN_ERROR"));
    assert!(v.contains("fn map_volume_err"));
    assert!(v.contains("VolumeOpenFailed"));
}

#[test]
fn uc25_auto_lock_and_focus_lock_skipped_during_job() {
    let main = src("main.rs");
    assert!(main.contains("self.volume.job_running()"));
}
