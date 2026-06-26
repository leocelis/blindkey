//! Property-based robustness tests for the hostile-file attack surface (UC-10 / C30) and the core
//! crypto invariants (C1/C9/C10/C18).
//!
//! A malicious vault file served by an untrusted sync backend is the #1 untrusted-input path. These
//! tests assert, over many random inputs, that:
//!   1. every public parser returns `Err`/`Ok` — never panics, hangs, or over-allocates — on
//!      arbitrary bytes, and
//!   2. a real vault always round-trips, never leaks a plaintext secret/title into the ciphertext,
//!      and refuses a wrong password.

use proptest::prelude::*;

use vault_core::format::stanza;
use vault_core::format::{Entry, Header, Payload, Protected};
use vault_core::Vault;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn make_entry(title: &str, secret: &[u8]) -> Entry {
    Entry {
        id: [0u8; 16],
        title: title.into(),
        username: String::new(),
        password: Protected::new(secret.to_vec()),
        url: String::new(),
        notes: String::new(),
        tags: vec![],
        otp_secret: None,
        created_at: 0,
        modified_at: 0,
        expires_at: None,
        custom_fields: vec![],
    }
}

proptest! {
    /// Every public parser must be panic-free on arbitrary bytes (constraint C30, UC-10).
    #[test]
    fn parsers_never_panic_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
        // Each must return without panicking; the result itself is irrelevant.
        let _ = Header::parse(&bytes);
        let _ = Payload::parse(&bytes);
        let _ = stanza::parse_sequence(&bytes);
        let _ = Vault::open(&bytes, b"any-password");
    }
}

proptest! {
    /// A header prefixed with the real magic bytes still parses safely (exercises deeper paths).
    #[test]
    fn parser_safe_with_valid_magic_prefix(rest in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let mut bytes = vault_core::MAGIC.to_vec();
        bytes.extend_from_slice(&rest);
        let _ = Header::parse(&bytes);
        let _ = Vault::open(&bytes, b"pw");
    }
}

proptest! {
    // Argon2 in the loop, so keep the case count modest and the KDF params small.
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// A real vault round-trips, leaks no plaintext into the ciphertext, and refuses a wrong key.
    #[test]
    fn vault_round_trips_and_leaks_nothing(
        password in "[ -~]{1,32}",
        entries in proptest::collection::vec(
            ("[a-zA-Z0-9._-]{4,24}", "[ -~]{8,48}"),
            0..6,
        ),
    ) {
        let mut v = Vault::create(password.as_bytes(), 64, 1, 1, true).unwrap();
        for (title, secret) in &entries {
            v.add_entry(make_entry(title, secret.as_bytes()));
        }
        let bytes = v.save().unwrap();

        // round-trip: opens, same entry count.
        let opened = Vault::open(&bytes, password.as_bytes()).unwrap();
        prop_assert_eq!(opened.entries().len(), entries.len());

        // C18: no plaintext secret or (sufficiently long) title appears in the encrypted file.
        for (title, secret) in &entries {
            prop_assert!(!contains(&bytes, secret.as_bytes()), "secret leaked");
            prop_assert!(!contains(&bytes, title.as_bytes()), "title leaked");
        }

        // A wrong password must fail (ambiguous), never silently open.
        prop_assert!(Vault::open(&bytes, b"wrong-password-\x00\x01").is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// Tamper-evidence (C9/C10/C1): flipping any single byte of a saved vault must make it fail to
    /// open — never decrypt to something else.
    #[test]
    fn single_byte_tamper_is_always_detected(
        secret in "[ -~]{8,32}",
        flip_frac in 0.0f64..1.0,
    ) {
        let mut v = Vault::create(b"tamper-pw", 64, 1, 1, true).unwrap();
        v.add_entry(make_entry("svc", secret.as_bytes()));
        let mut bytes = v.save().unwrap();

        prop_assume!(bytes.len() > 8);
        let idx = ((flip_frac * bytes.len() as f64) as usize).min(bytes.len() - 1);
        bytes[idx] ^= 0x01;

        // Must error — corrupt header, failed auth, or malformed body. Never Ok.
        prop_assert!(Vault::open(&bytes, b"tamper-pw").is_err(), "tamper at {} not detected", idx);
    }
}
