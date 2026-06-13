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
constraint_test!(c28_kdf_ceiling, "C28", "Reject KDF params above ceiling before allocation");
constraint_test!(c7_magic_version, "C7", "Reject bad magic and newer format_version");
constraint_test!(c9_header_hmac, "C9", "Tamper/wrong-password are indistinguishable; no payload leak");
constraint_test!(c10_block_stream, "C10", "HmacBlockStream: swap/duplicate/truncate detection");
constraint_test!(c11_zeroize, "C11", "Secret buffers are zeroed on drop; no plain Vec<u8> secrets");
constraint_test!(c16_rollback, "C16", "Regressed version warns/aborts; non-TTY exits code 2");
constraint_test!(c18_zero_plaintext, "C18", "strings(vault.vlt) reveals no entry content");
constraint_test!(c26_gen_unbiased, "C26", "CSPRNG generator: uniform charset, no modulo bias");
constraint_test!(c27_model_blind, "C27", "get → clipboard by default; --stdout warns on stderr");
constraint_test!(c29_no_argv_secrets, "C29", "No secret on argv/environ of vault or child processes");
constraint_test!(c30_ansi_sanitize, "C30", "Hostile bytes visibly escaped on TTY; byte-exact when piped");
constraint_test!(c31_api_shape, "C31", "vault-core API: deliver() not return; no secret types over FFI");
