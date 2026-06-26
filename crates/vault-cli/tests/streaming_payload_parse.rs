//! Streaming payload parse regression (security-gap review P3).
//!
//! Patterns: `internal/patterns/vault/streaming_payload_parse_patterns.yaml`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn open_inner_uses_streaming_parse() {
    let vault = read_repo_file("crates/vault-core/src/vault.rs");
    assert!(
        vault.contains("parse_from_stream_ciphertext"),
        "Vault::open_inner must use streaming payload parse"
    );
    assert!(
        !vault.contains("Payload::parse(&plaintext)"),
        "open path must not parse a full decrypted plaintext buffer"
    );
}

#[test]
fn stream_exports_decrypt_streaming_and_incremental_tlv() {
    let stream = read_repo_file("crates/vault-core/src/crypto/stream.rs");
    assert!(stream.contains("pub fn decrypt_streaming"));
    assert!(stream.contains("StreamDecryptor"));
    let tlv = read_repo_file("crates/vault-core/src/format/tlv_incremental.rs");
    assert!(tlv.contains("IncrementalTlv"));
}

#[test]
fn payload_documents_streaming_open_path() {
    let payload = read_repo_file("crates/vault-core/src/format/payload.rs");
    assert!(payload.contains("parse_from_stream_ciphertext"));
    assert!(payload.contains("security-gap review P3"));
}

#[test]
fn research_doc_exists() {
    let research = read_repo_file("research/streaming_payload_parse_research.md");
    assert!(research.contains("IncrementalTlv"));
    assert!(research.contains("StreamDecryptor"));
}
