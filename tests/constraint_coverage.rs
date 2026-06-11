//! Constraint coverage map (IVD Rule 3: every constraint has a test).
//!
//! This file is the index that ties each constraint in `vault_intent.yaml` to the integration test
//! that proves it. As constraints are implemented (see `ROADMAP.md`), replace the `#[ignore]`
//! placeholders with real assertions. CI runs the active tests; the ignored ones document what is
//! still owed so a constraint can never be silently left unverified.

/// Helper to make intent explicit in test names.
macro_rules! constraint_test {
    ($name:ident, $constraint:literal, $desc:literal) => {
        #[test]
        #[ignore = "pending implementation — see ROADMAP.md"]
        fn $name() {
            // Constraint $constraint: $desc
            // TODO: implement per vault_intent.yaml `test:` block for $constraint.
        }
    };
}

constraint_test!(c1_stream_aead, "C1", "XChaCha20-Poly1305 STREAM: reorder/truncate detection");
constraint_test!(c2_argon2id_floor, "C2", "Argon2id floor enforced; warn below recommended");
constraint_test!(c2_argon2id_ceiling, "C2", "Reject KDF params above ceiling before allocation");
constraint_test!(c2_nfc_normalization, "C2", "NFC vs NFD master password derives identical key");
constraint_test!(c5_yubikey_staleness, "C5", "YubiKey absent: graceful stale save + warning; strict mode aborts");
constraint_test!(c7_magic_version, "C7", "Reject bad magic and newer format_version");
constraint_test!(c9_header_hmac, "C9", "Data-key-keyed HMAC verifiable on hardware-only unlock; stanza-step error ambiguous");
constraint_test!(c10_block_stream, "C10", "HmacBlockStream: swap/duplicate/truncate detection");
constraint_test!(c11_zeroize, "C11", "Secret buffers are zeroed on drop; no plain Vec<u8> secrets");
constraint_test!(c12_mlock_warn_once, "C12", "mlock failure warns exactly once; KDF buffer exempt");
constraint_test!(c13_helper_clear, "C13", "Detached helper clears after CLI exit; clear-iff-unchanged");
constraint_test!(c16_rollback, "C16", "Regressed version warns/aborts; non-TTY exits code 2");
constraint_test!(c16_tofu_first_open, "C16", "First open with no anchor is TOFU: accepted, anchor created");
constraint_test!(c18_zero_plaintext, "C18", "strings(vault.vlt) reveals no entry content");
constraint_test!(c19_inner_stream_per_save, "C19", "Inner stream key differs between saves; in-RAM protection");
constraint_test!(c21_exit_code_map, "C21", "Frozen exit codes 0-9 per failure class; clap usage exits 8");
constraint_test!(c26_gen_unbiased, "C26", "CSPRNG generator: uniform charset, no modulo bias");
constraint_test!(c27_model_blind, "C27", "get → clipboard by default; --stdout warns on stderr");
constraint_test!(c27_headless_refusal, "C27", "No clipboard: refuse with exit 7, never silent stdout fallback");
constraint_test!(c28_terminal_sanitization, "C28", "Control/ANSI/OSC bytes never reach the terminal raw");
constraint_test!(c29_export_injection, "C29", "CSV formula metacharacters escaped; strict JSON escaping");
constraint_test!(c30_parser_robustness, "C30", "forbid(unsafe_code); hostile lengths rejected pre-allocation");
constraint_test!(c31_no_argv_secrets, "C31", "No secret-accepting flags exist; stdin/prompt/fd only");
constraint_test!(c32_atomic_save, "C32", "Kill -9 during save never loses the vault; flock excludes writers");
constraint_test!(c33_clipboard_concealment, "C33", "Clipboard writes carry concealed/history-exclusion marks");
constraint_test!(c34_release_verification, "C34", "Reproducible build digests match; unsigned release fails closed");
