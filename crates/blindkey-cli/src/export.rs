//! `blindkey export --format json` (UC-05 §3.4, C21/C29).

use std::collections::BTreeMap;

use blindkey_core::format::entry::{CustomValue, Entry};
use serde::Serialize;

pub const EXPORT_WARNING: &str = "WARNING: export writes ALL decrypted entries as plaintext. \
Anything that reads this output (including AI agents) learns every secret.";

pub const EXPORT_CONFIRM: &str = "Export ALL entries as plaintext JSON to stdout?";

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct VaultExport {
    pub vault_export_version: u32,
    pub entries: Vec<ExportEntry>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ExportEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub otp_secret: Option<String>,
    pub custom_fields: BTreeMap<String, String>,
    pub created_at: String,
    pub modified_at: String,
    pub expires_at: Option<String>,
}

/// Build the v1 export document from decrypted entries (strict JSON via serde_json — C29).
pub fn build_export_json(entries: &[Entry]) -> Result<String, String> {
    let mut export_entries: Vec<ExportEntry> = entries
        .iter()
        .map(entry_to_export)
        .collect::<Result<_, _>>()?;
    export_entries.sort_by(|a, b| a.title.cmp(&b.title));
    let doc = VaultExport {
        vault_export_version: 1,
        entries: export_entries,
    };
    serde_json::to_string_pretty(&doc).map_err(|e| format!("JSON encode failed: {e}"))
}

fn entry_to_export(e: &Entry) -> Result<ExportEntry, String> {
    let title = e.title.clone();
    let password = utf8_secret(&title, "password", &e.password.expose())?;
    let otp_secret = match &e.otp_secret {
        Some(s) => Some(utf8_secret(&title, "otp_secret", &s.expose())?),
        None => None,
    };
    let mut custom_fields = BTreeMap::new();
    for cf in &e.custom_fields {
        let value = match &cf.value {
            CustomValue::Plain(s) => s.clone(),
            CustomValue::Protected(p) => utf8_secret(&title, &cf.name, &p.expose())?,
        };
        custom_fields.insert(cf.name.clone(), value);
    }
    Ok(ExportEntry {
        title: title.clone(),
        username: e.username.clone(),
        password,
        url: e.url.clone(),
        notes: e.notes.clone(),
        tags: e.tags.clone(),
        otp_secret,
        custom_fields,
        created_at: rfc3339_utc(e.created_at)?,
        modified_at: rfc3339_utc(e.modified_at)?,
        expires_at: match e.expires_at {
            Some(ts) => Some(rfc3339_utc(ts)?),
            None => None,
        },
    })
}

fn utf8_secret(entry: &str, field: &str, bytes: &[u8]) -> Result<String, String> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|_| {
            format!("entry {entry:?} field {field:?} contains non-UTF-8 bytes; cannot JSON-export")
        })
}

/// Format unix seconds as RFC 3339 UTC (`2026-06-10T12:00:00Z`).
fn rfc3339_utc(secs: i64) -> Result<String, String> {
    if secs < 0 {
        return Err(format!("timestamp {secs} is before Unix epoch"));
    }
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Civil calendar date from days since 1970-01-01 (UTC).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blindkey_core::format::entry::Protected;

    fn sample_entry(title: &str, password: &str, notes: &str) -> Entry {
        Entry {
            id: [0u8; 16],
            title: title.to_string(),
            username: "user".to_string(),
            password: Protected::new(password.as_bytes().to_vec()),
            url: "https://example.com".to_string(),
            notes: notes.to_string(),
            tags: vec!["work".to_string()],
            otp_secret: None,
            created_at: 1_718_000_000,
            modified_at: 1_718_000_100,
            expires_at: None,
            custom_fields: vec![],
        }
    }

    #[test]
    fn c29_json_export_strict_escaping() {
        let e = sample_entry("t", "pass\"word", "line1\nline2\x07");
        let json = build_export_json(&[e]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["entries"][0]["password"], "pass\"word");
        assert_eq!(v["entries"][0]["notes"], "line1\nline2\u{7}");
    }

    #[test]
    fn json_export_schema_version_and_timestamps() {
        let json = build_export_json(&[sample_entry("a", "p", "")]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["vault_export_version"], 1);
        assert!(v["entries"][0]["created_at"]
            .as_str()
            .unwrap()
            .ends_with('Z'));
    }
}
