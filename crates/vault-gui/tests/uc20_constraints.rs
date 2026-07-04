//! UC-20 constraint tests (C40–C45) — static/manifest checks that do not need a live window.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("vault workspace root")
        .to_path_buf()
}

fn read_workspace_file(rel: &str) -> String {
    std::fs::read_to_string(workspace_root().join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn read_gui_main() -> String {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let main = std::fs::read_to_string(base.join("main.rs")).expect("main.rs");
    let sealed = std::fs::read_to_string(base.join("sealed_gui.rs")).unwrap_or_default();
    format!("{main}\n{sealed}")
}

/// C41 — glow pinned; persistence feature absent from workspace eframe dep.
#[test]
fn c41_eframe_glow_pinned_no_persistence() {
    let cargo = read_workspace_file("Cargo.toml");
    let eframe_line = cargo
        .lines()
        .find(|l| l.trim_start().starts_with("eframe"))
        .expect("eframe dependency line");
    assert!(
        eframe_line.contains("glow"),
        "eframe must pin glow: {eframe_line}"
    );
    assert!(
        eframe_line.contains("default-features = false"),
        "eframe must disable default features: {eframe_line}"
    );
    assert!(
        !eframe_line.contains("persistence"),
        "eframe must not enable persistence: {eframe_line}"
    );

    let gui_cargo = read_workspace_file("crates/vault-gui/Cargo.toml");
    for line in gui_cargo.lines() {
        let dep_part = line.split('#').next().unwrap_or("").trim();
        if dep_part.starts_with("eframe") && dep_part.contains('=') {
            assert!(
                !dep_part.contains("persistence"),
                "vault-gui eframe dep must not enable persistence: {dep_part}"
            );
        }
    }
}

/// C40 — reactive repaint only; auto-lock timer is the sole periodic schedule.
#[test]
fn c40_reactive_repaint_invariants() {
    let src = read_gui_main();
    assert!(
        !src.contains("RunMode::Continuous"),
        "must not use continuous repaint mode"
    );
    let repaint_sites: Vec<_> = src
        .lines()
        .filter(|l| l.contains("request_repaint"))
        .collect();
    assert!(
        repaint_sites.len() <= 4,
        "expected bounded request_repaint_after sites (auto-lock, reveal, otp, sealed poll): {repaint_sites:?}"
    );
    assert!(
        repaint_sites
            .iter()
            .all(|l| l.contains("request_repaint_after")),
        "periodic repaint must use request_repaint_after: {repaint_sites:?}"
    );
}

/// C42 — search cache module wired; find runs only on cache miss.
#[test]
fn c42_search_cache_wired() {
    let src = read_gui_main();
    assert!(src.contains("mod search_cache"), "search_cache module");
    assert!(
        src.contains("search_cache::SearchCache"),
        "SearchCache field"
    );
    assert!(src.contains("ensure_search_cache"), "cache refresh hook");
    assert!(src.contains("display_items"), "cached display rows");
    assert!(
        src.contains("entries_generation"),
        "generation invalidation"
    );
    assert!(
        src.contains("compute_search_items"),
        "find isolated to miss path"
    );
}

/// C43 — list virtualization module and threshold constant.
#[test]
fn c43_list_virtualization_wired() {
    let src = read_gui_main();
    assert!(
        src.contains("mod list_virtualize"),
        "list_virtualize module"
    );
    assert!(src.contains("visible_slice_range"), "viewport slice");
    assert!(src.contains("ENTRY_ROW_HEIGHT"), "row height constant");
}

/// C44 — password fields use masking (unlock, confirm, editor OTP; editor password when hidden).
#[test]
fn c44_password_fields_masked() {
    let src = read_gui_main();
    assert!(
        src.contains("pw_input") && src.contains(".password(true)"),
        "unlock field must use password(true)"
    );
    assert!(
        src.contains("pw_confirm") && src.contains(".password(true)"),
        "confirm field must use password(true)"
    );
    assert!(
        src.contains(".password(!ed.show_password)"),
        "editor password must mask unless user toggles show"
    );
    assert!(
        src.contains("ed.otp") && src.contains(".password(true)"),
        "OTP field must use password(true)"
    );
}

/// C45 — thin shell: no direct crypto imports; Action dispatch pattern.
#[test]
fn c45_thin_shell_no_direct_crypto() {
    let src = read_gui_main();
    for forbidden in ["chacha20poly1305", "argon2::", "vault_core::format::crypto"] {
        assert!(
            !src.contains(forbidden),
            "vault-gui must not import {forbidden}"
        );
    }
    assert!(src.contains("enum Action"), "Action dispatch enum");
    assert!(src.contains("match a"), "Action batch dispatch");
    assert!(src.contains("#![forbid(unsafe_code)]"), "forbid unsafe");
}
