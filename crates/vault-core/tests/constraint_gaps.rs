//! Dedicated tests for constraints called out in `docs/CONSTRAINT_INDEX.md` coverage gaps.

use secrecy::ExposeSecret;
use vault_core::crypto::kdf;
use vault_core::envelope::{generate_data_key, unwrap_password_stanza, wrap_password_stanza};
use vault_core::format::{Entry, Protected};
use vault_core::Vault;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// C3 — audited crypto crates only; supply-chain policy on disk.
#[test]
fn c3_audited_crypto_deps_and_deny_policy() {
    let core_toml =
        std::fs::read_to_string(repo_root().join("crates/vault-core/Cargo.toml")).unwrap();
    for dep in [
        "chacha20poly1305",
        "argon2",
        "hkdf",
        "hmac",
        "sha2",
        "subtle",
    ] {
        assert!(core_toml.contains(dep), "vault-core must use audited {dep}");
    }
    assert!(
        !core_toml.contains("openssl"),
        "openssl must not appear in vault-core deps (C3)"
    );

    let deny = std::fs::read_to_string(repo_root().join("deny.toml")).unwrap();
    assert!(
        deny.contains("cargo-deny"),
        "deny.toml should document cargo-deny"
    );
    assert!(deny.contains("openssl"), "deny.toml must ban openssl");

    let crypto_mod =
        std::fs::read_to_string(repo_root().join("crates/vault-core/src/crypto/mod.rs")).unwrap();
    assert!(
        crypto_mod.contains("No custom cryptography"),
        "crypto module must state C3 policy"
    );
}

/// C4 — data key is CSPRNG-random, never derived from the password; re-wrap preserves the key.
#[test]
fn c4_data_key_random_and_rewrap_preserves_key() {
    const SALT: [u8; 32] = [0x11; 32];
    const VID: [u8; 16] = [0x22; 16];
    const M: u32 = 64;
    const T: u32 = 1;
    const P: u32 = 1;

    let a = generate_data_key().unwrap();
    let b = generate_data_key().unwrap();
    assert_ne!(a.expose_secret(), b.expose_secret());

    let pw_kdf = kdf::argon2id(b"master-password", &SALT, M, T, P).unwrap();
    assert_ne!(a.expose_secret(), pw_kdf.expose_secret());

    let dk = [0xCDu8; 32];
    let old_stanza = wrap_password_stanza(&dk, b"old-pw", &SALT, &VID, M, T, P).unwrap();
    assert!(old_stanza.data.windows(32).all(|w| w != dk));

    let recovered = unwrap_password_stanza(&old_stanza, b"old-pw", &SALT, &VID, M, T, P).unwrap();
    let new_stanza =
        wrap_password_stanza(recovered.expose_secret(), b"new-pw", &SALT, &VID, M, T, P).unwrap();
    assert_ne!(
        old_stanza.data, new_stanza.data,
        "re-wrap uses fresh wrap nonce"
    );
    let out = unwrap_password_stanza(&new_stanza, b"new-pw", &SALT, &VID, M, T, P).unwrap();
    assert_eq!(out.expose_secret(), &dk);
}

/// C17 — single opaque encrypted blob; no per-entry plaintext files.
#[test]
fn c17_many_entries_one_opaque_file() {
    const M: u32 = 64;
    const T: u32 = 1;
    const P: u32 = 1;

    let mut v = Vault::create(b"pw", M, T, P, true).unwrap();
    for i in 0..8 {
        v.add_entry(Entry {
            id: [i; 16],
            title: format!("service-{i}"),
            username: format!("user{i}"),
            password: Protected::new(format!("secret-{i}").into_bytes()),
            url: format!("https://example{i}.test"),
            notes: String::new(),
            tags: vec![format!("tag{i}")],
            otp_secret: None,
            created_at: 0,
            modified_at: 0,
            expires_at: None,
            custom_fields: vec![],
        });
    }
    let bytes = v.save().unwrap();

    let opened = Vault::open(&bytes, b"pw").unwrap();
    assert_eq!(opened.entries().len(), 8);

    for i in 0..8 {
        let title = format!("service-{i}");
        let secret = format!("secret-{i}");
        assert!(
            !bytes.windows(title.len()).any(|w| w == title.as_bytes()),
            "title must not appear in file (C17/C18)"
        );
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "secret must not appear in file (C17/C18)"
        );
    }
}
