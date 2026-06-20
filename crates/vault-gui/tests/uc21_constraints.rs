//! UC-21 constraint tests (C46–C54).

use std::path::PathBuf;

fn read_gui_main() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("main.rs")
}

#[test]
fn c46_reveal_timeout_wired() {
    let src = read_gui_main();
    assert!(src.contains("reveal_until"));
    assert!(src.contains("REVEAL_TIMEOUT_SECS"));
    assert!(src.contains("enforce_reveal_timeout"));
}

#[test]
fn c47_lock_on_blur_wired() {
    let src = read_gui_main();
    assert!(src.contains("lock_on_blur"));
    assert!(src.contains("enforce_focus_lock"));
}

#[test]
fn c48_keyfile_unlock_wired() {
    let src = read_gui_main();
    assert!(src.contains("Vault::requires_keyfile"));
    assert!(src.contains("open_keyfile"));
    assert!(src.contains("use_recovery"));
}

#[test]
fn c49_keyfile_enroll_wired() {
    let src = read_gui_main();
    assert!(src.contains("enroll_keyfile_2fa"));
    assert!(src.contains("keyfile_enroll_window"));
    assert!(src.contains("recovery_reveal"));
}

#[test]
fn c50_pre10_banner_wired() {
    let src = read_gui_main();
    assert!(src.contains("dismissed_pre10"));
    assert!(src.contains("Pre-1.0"));
}

#[test]
fn c51_clipboard_timeout_wired() {
    let src = read_gui_main();
    assert!(src.contains("clipboard_timeout_secs"));
    assert!(src.contains("visible to other apps"));
}

#[test]
fn c52_virtualize_threshold_100() {
    let lv = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/list_virtualize.rs"),
    )
    .unwrap();
    assert!(lv.contains("LIST_VIRTUALIZE_THRESHOLD: usize = 100"));
}

#[test]
fn c53_search_scope_hint() {
    let src = read_gui_main();
    assert!(src.contains("never passwords"));
}

#[test]
fn c54_password_labels() {
    let src = read_gui_main();
    for label in [
        "ui.label(\"Master password\")",
        "ui.label(\"Recovery code\")",
        "ui.label(\"Confirm password\")",
        "ui.label(\"Password\")",
        "ui.label(\"2FA secret\")",
    ] {
        assert!(src.contains(label), "missing label: {label}");
    }
}

/// Every `.password(` field must have a `ui.label` within the prior 8 lines (C54).
#[test]
fn c54_password_fields_preceded_by_labels() {
    let src = read_gui_main();
    let lines: Vec<&str> = src.lines().collect();
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
            "password field at line {} lacks a preceding ui.label:\n{}",
            i + 1,
            line.trim()
        );
    }
}
