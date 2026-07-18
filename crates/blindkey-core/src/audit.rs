//! Offline password-health audit — find weak, reused, stale, and expiring credentials.
//!
//! Everything runs locally over the already-decrypted entries (no network — constraint C23). The
//! report references entries by **title only**, never by secret. Reuse detection groups entries by a
//! salted SHA-256 of the password computed in a transient, per-call map (a random per-call salt so
//! the digests are not plain `SHA-256(password)`); the hashes never leave the function.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::format::entry::Entry;

/// Seconds in a day, for the staleness/expiry windows.
const DAY: i64 = 86_400;

/// Estimated-entropy floor (bits) below which a **master** password is considered weak. The master
/// password is the root of trust and faces offline brute force, so this is stricter than a typical
/// per-entry threshold. ~60 bits ≈ a strong passphrase (e.g. 5 diceware words) or ~12 random alnum.
pub const WEAK_MASTER_BITS: f64 = 60.0;

/// Thresholds for what counts as weak / stale / expiring.
#[derive(Debug, Clone, Copy)]
pub struct AuditConfig {
    /// A password below this estimated entropy (bits) is flagged weak.
    pub weak_bits: f64,
    /// A password not modified in more than this many days is flagged stale.
    pub stale_days: i64,
    /// An entry expiring within this many days (or already expired) is flagged.
    pub expiring_days: i64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            weak_bits: 50.0,
            stale_days: 365,
            expiring_days: 30,
        }
    }
}

/// The result of an audit. All fields name entries by title only.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Total entries examined.
    pub total: usize,
    /// Titles of entries whose password is below the weak-entropy threshold.
    pub weak: Vec<String>,
    /// Groups of titles that share the same password (each group has ≥ 2 entries).
    pub reused: Vec<Vec<String>>,
    /// Titles of entries not modified within the staleness window.
    pub stale: Vec<String>,
    /// Entries with an expiry within the window: `(title, days_left)` (negative = already expired).
    pub expiring: Vec<(String, i64)>,
}

impl AuditReport {
    /// Whether the audit found nothing to flag.
    pub fn is_clean(&self) -> bool {
        self.weak.is_empty()
            && self.reused.is_empty()
            && self.stale.is_empty()
            && self.expiring.is_empty()
    }
}

/// A rough password-entropy estimate from the character classes present × length (bits). A
/// heuristic — it does not detect dictionary words; the generator/passphrase remain the strong path.
pub fn password_entropy_bits(pw: &[u8]) -> f64 {
    if pw.is_empty() {
        return 0.0;
    }
    let mut pool = 0u32;
    if pw.iter().any(u8::is_ascii_lowercase) {
        pool += 26;
    }
    if pw.iter().any(u8::is_ascii_uppercase) {
        pool += 26;
    }
    if pw.iter().any(u8::is_ascii_digit) {
        pool += 10;
    }
    if pw
        .iter()
        .any(|b| !b.is_ascii_alphanumeric() && !b.is_ascii_whitespace())
    {
        pool += 32;
    }
    if pw.iter().any(u8::is_ascii_whitespace) {
        pool += 1;
    }
    (f64::from(pool.max(2))).log2() * pw.len() as f64
}

/// Audit `entries` against `cfg` at time `now` (unix seconds).
pub fn analyze(entries: &[Entry], now: i64, cfg: &AuditConfig) -> AuditReport {
    let mut report = AuditReport {
        total: entries.len(),
        ..Default::default()
    };

    // Per-call random salt so the grouping digests are not plain SHA-256(password).
    let mut salt = [0u8; 16];
    let _ = getrandom::getrandom(&mut salt);

    let mut by_password: HashMap<[u8; 32], Vec<String>> = HashMap::new();

    for e in entries {
        let pw = e.password.expose(); // Zeroizing<Vec<u8>>

        if password_entropy_bits(&pw) < cfg.weak_bits {
            report.weak.push(e.title.clone());
        }

        // reuse grouping (salted, transient)
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(&pw);
        let digest: [u8; 32] = hasher.finalize().into();
        by_password.entry(digest).or_default().push(e.title.clone());

        if e.modified_at > 0 && now - e.modified_at > cfg.stale_days * DAY {
            report.stale.push(e.title.clone());
        }
        if let Some(exp) = e.expires_at {
            let days_left = (exp - now).div_euclid(DAY);
            if days_left <= cfg.expiring_days {
                report.expiring.push((e.title.clone(), days_left));
            }
        }
    }

    // Keep only password groups shared by ≥ 2 entries.
    report.reused = by_password
        .into_values()
        .filter(|titles| titles.len() > 1)
        .collect();
    report.reused.sort();
    report.expiring.sort_by_key(|(_, d)| *d);

    // The salt is dropped here; keep it zeroizing to be tidy.
    let _ = Zeroizing::new(salt);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::entry::Protected;

    fn entry(title: &str, pw: &[u8], modified_at: i64, expires_at: Option<i64>) -> Entry {
        Entry {
            id: [0; 16],
            title: title.into(),
            username: String::new(),
            password: Protected::new(pw.to_vec()),
            url: String::new(),
            notes: String::new(),
            tags: vec![],
            otp_secret: None,
            created_at: 0,
            modified_at,
            expires_at,
            custom_fields: vec![],
        }
    }

    #[test]
    fn entropy_orders_passwords_sensibly() {
        assert!(password_entropy_bits(b"abc") < password_entropy_bits(b"abcdefghij"));
        assert!(password_entropy_bits(b"aaaaaaaa") < password_entropy_bits(b"A1b!C2d#E3f$G4h%"));
        assert_eq!(password_entropy_bits(b""), 0.0);
    }

    #[test]
    fn flags_weak_reused_stale_and_expiring() {
        let now = 1_000_000_000i64;
        let cfg = AuditConfig::default();
        let entries = vec![
            entry("strong", b"A1b!C2d#E3f$G4h%J5k^", now, None), // ~131 bits, fresh
            entry("weak", b"hunter2", now, None),                // low entropy
            entry("reuse-a", b"sharedpass!", now, None),
            entry("reuse-b", b"sharedpass!", now, None),
            entry("stale", b"Zx9!Qw7@Er5#Ty3$Ui1%", now - 400 * DAY, None),
            entry("soon", b"Zx9!Qw7@Er5#Ty3$Ui1%", now, Some(now + 5 * DAY)),
            entry("expired", b"Zx9!Qw7@Er5#Ty3$Ui1%", now, Some(now - 2 * DAY)),
        ];
        let r = analyze(&entries, now, &cfg);

        assert_eq!(r.total, 7);
        assert!(r.weak.contains(&"weak".to_string()));
        assert!(!r.weak.contains(&"strong".to_string()));
        // reuse group of the two "shared" entries
        assert!(r
            .reused
            .iter()
            .any(|g| g.contains(&"reuse-a".to_string()) && g.contains(&"reuse-b".to_string())));
        assert!(r.stale.contains(&"stale".to_string()));
        // expiring sorted ascending by days_left: "expired" (-2) before "soon" (5)
        assert_eq!(r.expiring.first().unwrap().0, "expired");
        assert!(r.expiring.iter().any(|(t, d)| t == "soon" && *d == 5));
        assert!(!r.is_clean());
    }

    #[test]
    fn clean_vault_reports_clean() {
        let now = 1_000_000_000i64;
        let entries = vec![
            entry("a", b"A1b!C2d#E3f$G4h%J5k^", now, None),
            entry("b", b"Zx9!Qw7@Er5#Ty3$Ui1%", now, None),
        ];
        let r = analyze(&entries, now, &AuditConfig::default());
        assert!(r.is_clean(), "{r:?}");
    }
}
