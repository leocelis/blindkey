//! Lenient importer for an unstructured/semi-structured `keys.txt` (use case UC-17).
//!
//! A real `keys.txt` is a mess: a mix of `KEY=value`, `key: value`, bare tokens, provider-prefixed
//! secrets, labels, blank-line and `---` separators, and `#` comments. This module turns that into
//! [`Entry`] values, classifying each line as a **secret** (by known provider prefix or high Shannon
//! entropy) or a **label**, so the user can review and store them. It lives in `blindkey-core` so the
//! CLI and the desktop app drive the exact same parsing.
//!
//! It is intentionally best-effort: the caller is expected to show the result for confirmation
//! before saving (the parse is cheap to redo and the secrets are masked in review).

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::format::entry::{CustomField, CustomValue, Entry, Protected};
use zeroize::{Zeroize, Zeroizing};

/// Hard caps so a pathological file can't blow up memory (UC-17 hostile-input posture).
const MAX_BLOCKS: usize = 10_000;
const MAX_LINE_LEN: usize = 64 * 1024;
const MAX_CSV_ROWS: usize = 10_000;
const MAX_CSV_FIELD_LEN: usize = 64 * 1024;

/// Known secret prefixes used by the classifier (illustrative; tune against a real ruleset).
const KNOWN_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "AKIA",
    "AIza",
    "xox",
    "AGE-SECRET-KEY-",
    "-----BEGIN",
    "ya29.",
    "AccountKey=",
];

/// Result of a raw import: the entries plus how many blocks had no detectable secret.
#[derive(Debug)]
pub struct RawImport {
    /// Parsed entries (each tagged `imported`).
    pub entries: Vec<Entry>,
    /// Blocks that contained no secret-looking line and were skipped.
    pub blocks_skipped: usize,
}

/// Result of parsing a KeePassXC CSV export.
#[derive(Debug)]
pub struct KeepassCsvImport {
    /// Parsed entries, ready for masked review and a single vault save.
    pub entries: Vec<Entry>,
    /// Header columns not used by Blindkey, reported as a count without exposing cell data.
    pub unknown_columns: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeepassColumn {
    Group,
    Title,
    Username,
    Password,
    Url,
    Notes,
    Totp,
    Ignore,
}

impl KeepassColumn {
    fn from_header(header: &str) -> Self {
        match header {
            "group" => Self::Group,
            "title" => Self::Title,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "url" | "uri" => Self::Url,
            "notes" | "note" => Self::Notes,
            "totp" | "otp" | "otpsecret" => Self::Totp,
            _ => Self::Ignore,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Group => "Group",
            Self::Title => "Title",
            Self::Username => "Username",
            Self::Password => "Password",
            Self::Url => "URL",
            Self::Notes => "Notes",
            Self::Totp => "TOTP",
            Self::Ignore => "unknown",
        }
    }
}

#[derive(Default)]
struct KeepassRow {
    group: String,
    title: Option<String>,
    username: String,
    password: Option<Protected>,
    url: String,
    notes: String,
    totp: Option<Protected>,
}

impl KeepassRow {
    fn set(&mut self, column: KeepassColumn, field: &[u8], row: usize) -> Result<(), String> {
        let value = std::str::from_utf8(field)
            .map_err(|_| format!("KeePassXC CSV row {row} contains invalid UTF-8"))?;
        match column {
            KeepassColumn::Group => self.group = value.to_owned(),
            KeepassColumn::Title => self.title = Some(value.to_owned()),
            KeepassColumn::Username => self.username = value.to_owned(),
            KeepassColumn::Password => self.password = Some(Protected::new(field.to_vec())),
            KeepassColumn::Url => self.url = value.to_owned(),
            KeepassColumn::Notes => self.notes = value.to_owned(),
            KeepassColumn::Totp if !field.is_empty() => {
                self.totp = Some(Protected::new(field.to_vec()));
            }
            KeepassColumn::Totp | KeepassColumn::Ignore => {}
        }
        Ok(())
    }

    fn finish(self, row: usize, now: i64) -> Result<Entry, String> {
        let title = self
            .title
            .ok_or_else(|| format!("KeePassXC CSV row {row} is missing Title"))?;
        if title.is_empty() {
            return Err(format!("KeePassXC CSV row {row} has an empty Title"));
        }
        let password = self
            .password
            .ok_or_else(|| format!("KeePassXC CSV row {row} is missing Password"))?;
        let mut tags = vec!["imported".to_string(), "keepassxc".to_string()];
        if !self.group.is_empty() {
            tags.push(self.group);
        }
        Ok(Entry {
            id: random_id(),
            title,
            username: self.username,
            password,
            url: self.url,
            notes: self.notes,
            tags,
            otp_secret: self.totp,
            created_at: now,
            modified_at: now,
            expires_at: None,
            custom_fields: Vec::new(),
        })
    }
}

/// Parse a KeePassXC CSV export as opaque RFC 4180 data.
///
/// Header names are matched case-insensitively and independently of column order. Both a UTF-8
/// BOM and CRLF input are accepted. Cells are never evaluated or interpolated into commands.
pub fn parse_keepassxc_csv(text: &str) -> Result<KeepassCsvImport, String> {
    use csv_core::ReadFieldResult;

    let mut reader = csv_core::Reader::new();
    let mut input = text.as_bytes();
    let mut field = Zeroizing::new(vec![0u8; MAX_CSV_FIELD_LEN + 1]);
    let mut headers = Vec::new();
    let mut columns: Option<Vec<KeepassColumn>> = None;
    let mut column_index = 0usize;
    let mut row = KeepassRow::default();
    let now = now_unix();
    let mut entries = Vec::new();
    let mut unknown_columns = 0usize;

    loop {
        let (result, consumed, written) = reader.read_field(input, &mut field);
        input = &input[consumed..];
        match result {
            ReadFieldResult::InputEmpty => continue,
            ReadFieldResult::OutputFull => {
                return Err(format!(
                    "KeePassXC CSV field exceeds the {MAX_CSV_FIELD_LEN}-byte limit"
                ));
            }
            ReadFieldResult::Field { record_end } => {
                let value = &field[..written];
                if let Some(columns) = columns.as_ref() {
                    let csv_row = entries.len() + 2;
                    let column = columns.get(column_index).copied().ok_or_else(|| {
                        format!(
                            "KeePassXC CSV row {csv_row} has more than {} columns",
                            columns.len()
                        )
                    })?;
                    row.set(column, value, csv_row)?;
                } else {
                    let header = std::str::from_utf8(value)
                        .map_err(|_| "KeePassXC CSV header contains invalid UTF-8".to_string())?;
                    headers.push(normalize_csv_header(header));
                }
                field[..written].zeroize();
                column_index += 1;

                if record_end {
                    if let Some(columns) = columns.as_ref() {
                        let csv_row = entries.len() + 2;
                        if column_index != columns.len() {
                            return Err(format!(
                                "KeePassXC CSV row {csv_row} has {column_index} columns; expected {}",
                                columns.len()
                            ));
                        }
                        if entries.len() >= MAX_CSV_ROWS {
                            return Err(format!(
                                "KeePassXC CSV exceeds the {MAX_CSV_ROWS}-entry import limit"
                            ));
                        }
                        entries.push(row.finish(csv_row, now)?);
                        row = KeepassRow::default();
                    } else {
                        let parsed = parse_keepass_headers(&headers)?;
                        unknown_columns = parsed
                            .iter()
                            .filter(|c| **c == KeepassColumn::Ignore)
                            .count();
                        columns = Some(parsed);
                    }
                    column_index = 0;
                }
            }
            ReadFieldResult::End => break,
        }
    }

    if columns.is_none() {
        return Err("KeePassXC CSV has no header row".to_string());
    }
    Ok(KeepassCsvImport {
        entries,
        unknown_columns,
    })
}

/// Parse a messy `keys.txt` into entries (use case UC-17).
pub fn parse_raw(text: &str) -> RawImport {
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    let mut unnamed = 0usize;

    for block in split_blocks(text) {
        match block_to_entry(&block, &mut unnamed) {
            Some(e) => entries.push(e),
            None => skipped += 1,
        }
    }
    RawImport {
        entries,
        blocks_skipped: skipped,
    }
}

fn normalize_csv_header(header: &str) -> String {
    header
        .trim_start_matches('\u{feff}')
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn parse_keepass_headers(headers: &[String]) -> Result<Vec<KeepassColumn>, String> {
    let columns: Vec<KeepassColumn> = headers
        .iter()
        .map(|header| KeepassColumn::from_header(header))
        .collect();
    let mut seen = HashSet::new();
    for column in columns
        .iter()
        .copied()
        .filter(|column| *column != KeepassColumn::Ignore)
    {
        if !seen.insert(column.name()) {
            return Err(format!(
                "KeePassXC CSV contains duplicate {} columns",
                column.name()
            ));
        }
    }
    for required in [KeepassColumn::Title, KeepassColumn::Password] {
        if !columns.contains(&required) {
            return Err(format!(
                "KeePassXC CSV is missing required {:?} column",
                required.name().to_ascii_lowercase()
            ));
        }
    }
    Ok(columns)
}

/// Split into blocks on blank lines and `---` rulers; drop `#` comments and over-long lines.
fn split_blocks(text: &str) -> Vec<Vec<String>> {
    let mut blocks = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    for raw in text.lines() {
        if raw.len() > MAX_LINE_LEN {
            continue;
        }
        let t = raw.trim();
        if t.starts_with('#') {
            continue; // comment
        }
        if t.is_empty() || is_divider(t) {
            if !cur.is_empty() {
                blocks.push(std::mem::take(&mut cur));
                if blocks.len() >= MAX_BLOCKS {
                    return blocks;
                }
            }
            continue;
        }
        cur.push(t.to_string());
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    blocks
}

fn is_divider(line: &str) -> bool {
    line.len() >= 3 && line.chars().all(|c| c == '-')
}

/// Build an entry from one block, or `None` if the block has no secret-looking content.
fn block_to_entry(block: &[String], unnamed: &mut usize) -> Option<Entry> {
    let mut secret_kvs: Vec<(String, String)> = Vec::new();
    let mut plain_kvs: Vec<(String, String)> = Vec::new();
    let mut secret_loose: Vec<String> = Vec::new();
    let mut label_loose: Vec<String> = Vec::new();

    for line in block {
        if let Some((k, v)) = parse_kv(line) {
            if looks_like_secret(&v) {
                secret_kvs.push((k, v));
            } else {
                plain_kvs.push((k, v));
            }
        } else if looks_like_secret(line) {
            secret_loose.push(line.clone());
        } else {
            label_loose.push(line.clone());
        }
    }

    // Pick the primary secret and a title; collect any extra secrets as protected custom fields.
    let title;
    let password;
    let mut extra_secrets: Vec<(String, String)> = Vec::new();

    if !secret_kvs.is_empty() {
        let (k, v) = secret_kvs.remove(0);
        title = k;
        password = v;
        for (k, v) in secret_kvs {
            extra_secrets.push((k, v));
        }
    } else if !secret_loose.is_empty() {
        password = secret_loose.remove(0);
        title = if !label_loose.is_empty() {
            label_loose.remove(0)
        } else if let Some(p) = provider_guess(&password) {
            p.to_string()
        } else {
            *unnamed += 1;
            format!("imported-{}", *unnamed)
        };
        for (i, s) in secret_loose.into_iter().enumerate() {
            extra_secrets.push((format!("secret-{}", i + 2), s));
        }
    } else {
        return None; // no secret in this block
    }

    let now = now_unix();
    let mut entry = Entry {
        id: random_id(),
        title,
        username: String::new(),
        password: Protected::new(password.into_bytes()),
        url: String::new(),
        notes: String::new(),
        tags: vec!["imported".to_string()],
        otp_secret: None,
        created_at: now,
        modified_at: now,
        expires_at: None,
        custom_fields: Vec::new(),
    };

    let mut notes: Vec<String> = label_loose; // leftover labels become notes
    for (k, v) in plain_kvs {
        match k.to_lowercase().as_str() {
            "user" | "username" | "login" => entry.username = v,
            "url" | "uri" | "host" | "endpoint" => entry.url = v,
            "note" | "notes" | "comment" | "description" => notes.push(v),
            _ => entry.custom_fields.push(CustomField {
                name: k,
                value: CustomValue::Plain(v),
            }),
        }
    }
    for (name, v) in extra_secrets {
        entry.custom_fields.push(CustomField {
            name,
            value: CustomValue::Protected(Protected::new(v.into_bytes())),
        });
    }
    entry.notes = notes.join("\n");
    Some(entry)
}

/// Parse `KEY=value` or `key: value`. Rejects scheme-like lines (e.g. `postgres://…`) by requiring
/// a `: ` (colon-space) for the colon form and a label-like key.
fn parse_kv(line: &str) -> Option<(String, String)> {
    if let Some(i) = line.find('=') {
        let (k, v) = (line[..i].trim(), line[i + 1..].trim());
        if is_key_like(k) && !v.is_empty() {
            return Some((k.to_string(), v.to_string()));
        }
    }
    if let Some(i) = line.find(": ") {
        let (k, v) = (line[..i].trim(), line[i + 2..].trim());
        if is_key_like(k) && !v.is_empty() {
            return Some((k.to_string(), v.to_string()));
        }
    }
    None
}

fn is_key_like(k: &str) -> bool {
    !k.is_empty() && k.len() <= 64 && k.chars().all(|c| c.is_alphanumeric() || " _.-".contains(c))
}

fn looks_like_secret(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 8 {
        return false;
    }
    if KNOWN_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return true;
    }
    s.len() >= 20 && !s.contains(char::is_whitespace) && shannon_bits_per_char(s) >= 3.0
}

fn provider_guess(secret: &str) -> Option<&'static str> {
    const MAP: &[(&str, &str)] = &[
        ("sk-", "openai"),
        ("ghp_", "github"),
        ("gho_", "github"),
        ("github_pat_", "github"),
        ("glpat-", "gitlab"),
        ("AKIA", "aws"),
        ("AGE-SECRET-KEY-", "age"),
        ("xox", "slack"),
        ("AIza", "google"),
    ];
    MAP.iter()
        .find(|(p, _)| secret.starts_with(p))
        .map(|(_, n)| *n)
}

fn shannon_bits_per_char(s: &str) -> f64 {
    let n = s.chars().count() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let _ = getrandom::getrandom(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(e: &Entry) -> Vec<u8> {
        e.password.expose().to_vec()
    }

    #[test]
    fn label_then_secret() {
        let r = parse_raw("github\nghp_FAKE0mZ9xQ2vL7nR4tW8pY1aB3cD5eF6gH7iJ");
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].title, "github");
        assert_eq!(
            pw(&r.entries[0]).as_slice(),
            b"ghp_FAKE0mZ9xQ2vL7nR4tW8pY1aB3cD5eF6gH7iJ".as_slice()
        );
        assert_eq!(r.entries[0].tags, vec!["imported".to_string()]);
    }

    #[test]
    fn key_value_secret_with_metadata() {
        let r = parse_raw("AWS_SECRET=AKIAEXAMPLE7F4QX9TZ2P\nregion: us-east-1");
        assert_eq!(r.entries.len(), 1);
        let e = &r.entries[0];
        assert_eq!(e.title, "AWS_SECRET");
        assert_eq!(pw(e).as_slice(), b"AKIAEXAMPLE7F4QX9TZ2P".as_slice());
        // non-secret KV becomes a plain custom field
        assert!(e
            .custom_fields
            .iter()
            .any(|f| f.name == "region"
                && matches!(&f.value, CustomValue::Plain(v) if v == "us-east-1")));
    }

    #[test]
    fn bare_secret_guesses_provider() {
        let r = parse_raw("glpat-FAKExZ9y8W7v6U5t4S3r2Q1p");
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].title, "gitlab");
    }

    #[test]
    fn dividers_and_blank_lines_split_blocks() {
        let text = "openai\nsk-proj-FAKEa1B2c3D4e5F6g7H8i9J0kLmNoPq\n\nstripe\nsk_test_FAKE51H8xQ2vL7nR4tW8pY1aB3";
        let r = parse_raw(text);
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0].title, "openai");
        assert_eq!(r.entries[1].title, "stripe");
    }

    #[test]
    fn comments_and_no_secret_blocks_are_handled() {
        let text = "# a comment\n\njust some notes\nnothing secret here\n\n---\n\ntoken\nsk-FAKEa1B2c3D4e5F6g7H8i9J0";
        let r = parse_raw(text);
        assert_eq!(r.entries.len(), 1); // the notes-only block is skipped
        assert_eq!(r.blocks_skipped, 1);
        assert_eq!(r.entries[0].title, "token");
    }

    #[test]
    fn second_secret_in_block_becomes_protected_custom_field() {
        let r =
            parse_raw("AWS_ID=AKIAEXAMPLE7F4QX9TZ2P\nAWS_SECRET=wJalrXUtnFEMIK7MDENGbPxRfiCYfake1");
        let e = &r.entries[0];
        assert_eq!(e.title, "AWS_ID");
        assert!(e
            .custom_fields
            .iter()
            .any(|f| matches!(&f.value, CustomValue::Protected(_))));
    }

    #[test]
    fn connection_string_is_a_secret_not_a_kv() {
        let r = parse_raw("db\npostgres://appuser:s3cr3tP4ssw0rd9f3a@db.internal:5432/appdb");
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].title, "db");
        assert!(pw(&r.entries[0]).starts_with(b"postgres://"));
    }

    #[test]
    fn keepassxc_fixture_preserves_fields_and_opaque_cells() {
        let csv = include_str!("../tests/fixtures/keepassxc.csv");
        let r = parse_keepassxc_csv(csv).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.unknown_columns, 1);

        let e = &r.entries[0];
        assert_eq!(e.title, "GitHub, Inc.");
        assert_eq!(e.username, "=opaque-user");
        assert_eq!(pw(e), b"+opaque-password".to_vec());
        assert_eq!(e.url, "https://github.com");
        assert_eq!(e.notes, "first line\nsecond line");
        assert!(e.tags.iter().any(|tag| tag == "Work"));
        assert_eq!(
            e.otp_secret.as_ref().unwrap().expose().as_slice(),
            b"otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn keepassxc_accepts_bom_crlf_and_reordered_headers() {
        let csv = "\u{feff}Password,Notes,Title,URL,Username\r\nsecret,note,Example,https://e.test,user\r\n";
        let r = parse_keepassxc_csv(csv).unwrap();
        let e = &r.entries[0];
        assert_eq!(e.title, "Example");
        assert_eq!(e.username, "user");
        assert_eq!(pw(e), b"secret".to_vec());
    }

    #[test]
    fn keepassxc_rejects_missing_headers_and_malformed_rows() {
        assert!(parse_keepassxc_csv("Title,Username\nExample,user\n")
            .unwrap_err()
            .contains("password"));
        assert!(
            parse_keepassxc_csv("Title,Password\nExample,secret,extra\n")
                .unwrap_err()
                .contains("row 2")
        );
    }
}
