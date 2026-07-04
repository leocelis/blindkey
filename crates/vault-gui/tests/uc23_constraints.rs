//! UC-23 GUI constraint wiring (Phase C).

use std::path::PathBuf;

fn read_gui_sources() -> String {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let main = std::fs::read_to_string(base.join("main.rs")).expect("main.rs");
    let sealed = std::fs::read_to_string(base.join("sealed_gui.rs")).expect("sealed_gui.rs");
    format!("{main}\n{sealed}")
}

#[test]
fn uc23_sealed_module_wired() {
    let src = read_gui_sources();
    assert!(src.contains("mod sealed_gui"));
    assert!(src.contains("sealed_gui::SealedGui"));
    assert!(src.contains("SealedContainer"));
    assert!(src.contains("handle_drops"));
}

#[test]
fn uc23_worker_thread_and_cancel() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("thread::spawn"));
    assert!(sealed.contains("AtomicBool"));
    assert!(sealed.contains("request_repaint_after"));
    assert!(sealed.contains("Cancel"));
}

#[test]
fn uc23_peek_uses_list_virtualization() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("visible_slice_range"));
    assert!(sealed.contains("sizes only, no contents"));
}

#[test]
fn uc23_fail_closed_error_string() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("SEALED_OPEN_ERROR"));
}

#[test]
fn uc23_auto_lock_skipped_during_job() {
    let main =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
            .unwrap();
    assert!(main.contains("sealed.job_running()"));
}

#[test]
fn uc23_password_labels_in_sealed_dialogs() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    for label in [
        "ui.label(\"Passphrase\")",
        "ui.label(\"Confirm passphrase\")",
    ] {
        assert!(sealed.contains(label), "missing {label}");
    }
    let lines: Vec<&str> = sealed.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains(".password(") {
            continue;
        }
        let window = lines
            .iter()
            .skip(i.saturating_sub(8))
            .take(8)
            .any(|l| l.contains("ui.label("));
        assert!(
            window,
            "password field at line {} lacks preceding ui.label",
            i + 1
        );
    }
}

#[test]
fn uc23_seal_dialog_keyfile_and_yubikey_2fa_options() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("enroll_keyfile"));
    assert!(sealed.contains("enroll_yubikey"));
    assert!(sealed.contains("enroll_yubikey_2fa"));
    assert!(sealed.contains("Choose keyfile OR YubiKey"));
}

#[test]
fn uc23_cancel_wired_in_seal_and_open_jobs() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("SealedIoOpts"));
    assert!(sealed.contains("cancel: Some(&cancel)"));
    assert!(sealed.contains("run_seal_job"));
    assert!(sealed.contains("run_open_job"));
}

#[test]
fn uc23_gui_open_error_matches_cli_constant() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("SEALED_OPEN_ERROR"));
    assert!(sealed.contains("map_sealed_err"));
    assert!(sealed.contains("Error::SealedOpenFailed => SEALED_OPEN_ERROR"));
}

#[test]
fn uc23_large_seal_byte_progress_callback() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("progress: Some(&mut progress_cb)"));
    assert!(sealed.contains("JobUpdate::Progress"));
}

#[test]
fn uc23_padme_default_on_in_seal_dialog() {
    let sealed = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sealed_gui.rs"),
    )
    .unwrap();
    assert!(sealed.contains("pad_enabled: true"));
    assert!(sealed.contains("PadMode::Padme"));
}
