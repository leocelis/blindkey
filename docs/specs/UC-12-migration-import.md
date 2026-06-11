# UC-12 — Migrate from an Existing Manager

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-12 · **Constraints:** C21 (import), C26; touches C16, C17, C18, C23, C24, C27
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Get a P3 user ("Migrator from `pass`/KeePassXC") from their existing store into Vault in one
command, with strictly stronger post-migration security than they started with. Goals:

1. One-command import: `vault import --format <fmt> <source>`.
2. Every imported field lands inside the AEAD payload (C18) — no intermediate plaintext written
   by Vault, ever.
3. Every imported password is entropy-scanned (C26, zxcvbn) and weak ones reported, nudging
   rotation via `vault gen`.
4. One atomic save at the end (single `vault_version` increment, C16; atomic write per M5).
5. Honest post-import guidance: the *source* files are plaintext or weakly protected and the
   user must destroy them — with platform-accurate caveats.

Out of scope: live sync with the old manager, two-way migration, browser-extension stores.

### Import source matrix

| Source | Format | Mechanism | Milestone |
|---|---|---|---|
| Generic text | `--format txt` | documented line schema (below) | **v1 (M6)** |
| Generic JSON | `--format json` | documented schema (below) | **v1 (M6)** |
| Bitwarden | `--format bitwarden` | unencrypted JSON export | **v1 (M6)** |
| KeePassXC | `--format keepassxc-csv` | CSV export from KeePassXC | **v1 (M6)** |
| KeePassXC / KeePass | `--format kdbx` | direct KDBX4 read via `keepass` crate | M9 |
| pass / gopass | `--format pass` | walk store dir, decrypt each `.gpg` via `gpg` subprocess | M9 |

Rationale for the split: the v1 four are pure parsing (no new crypto surface); the M9 two add
either a third-party format parser with crypto (`keepass`) or an external-binary dependency
(`gpg`) and deserve their own test/fuzz cycle.

## 2. Prior art

### 2.1 Open source

- **pass / gopass** store layout: one GPG-encrypted file per entry in a directory tree;
  `.gpg-id` names the recipient key; first line is the password, subsequent lines are free-form
  key-value metadata ([passwordstore.org](https://www.passwordstore.org/) — already the C21
  baseline citation). The tree itself leaks entry names — the very thing C17/C18 fix — so the
  importer maps *relative path → entry title*.
- **keepass-rs** (`keepass` crate, [github.com/sseemayer/keepass-rs](https://github.com/sseemayer/keepass-rs)):
  ✓ verified June 2026 — parses KDB/KDBX3/KDBX4, read support solid (write experimental),
  v0.13.x, actively maintained (last release ~1 month old). MIT-licensed, fits the C24 allowlist.
- **sequoia-openpgp** ([crates.io/crates/sequoia-openpgp](https://crates.io/crates/sequoia-openpgp)):
  ✓ verified June 2026 — complete Rust OpenPGP (RFC 9580/4880), streaming `Decryptor`, v2.3.0,
  active. **License: LGPL-2.0-or-later** — outside the C24 allowlist and `deny.toml` policy.
- **Bitwarden export** ([bitwarden.com/help/export-your-data](https://bitwarden.com/help/export-your-data/)):
  unencrypted `.json` with `folders[]` and `items[]`; login items carry `login.username`,
  `login.password`, `login.uris[]`, `login.totp` (an `otpauth://totp/...` URI). Bitwarden's own
  docs tell users to delete the export immediately.
- **CVE-2019-20184** (KeePass 2.4.1 CSV injection) — already cited in
  [research/security_coverage_gaps.md](../../research/security_coverage_gaps.md) theme A3: the
  CSV path in password managers has real CVE history. We are *consuming* CSV here, not
  producing it, but the precedent justifies treating CSV cells as hostile bytes (A2/A3
  sanitization applies to anything we later display).

### 2.2 Academic / standards

- RFC 4180 (CSV) for quoting/escaping rules when parsing KeePassXC CSV.
- zxcvbn (Wheeler, USENIX Security 2016) — the estimator behind the C26 entropy floor.
- `shred(1)` documentation: explicitly ineffective on journaled, COW, and wear-leveled (SSD)
  storage — grounds the honest post-import guidance in §3.6.

## 3. Proposed design

### 3.1 gpg subprocess vs sequoia-pgp (decision)

**Decision: invoke `gpg --decrypt` as a subprocess for `--format pass` (M9).** Reasons, in order:

1. **C24 license wall.** sequoia-openpgp is LGPL-2.0-or-later; `deny.toml` and C24 permit only
   MIT/Apache-2.0/ISC/BSD/Unicode licenses. Linking it would fail `cargo deny check licenses`.
2. **C3 trusted-surface.** A full OpenPGP implementation in our dependency tree is a large new
   audited-crypto surface used only at migration time. A subprocess keeps it out of the binary.
3. **Practicality.** Every `pass` user has a working `gpg` + keyring *by definition*; their
   agent/pinentry config already works. We borrow it instead of reimplementing smartcard/agent.

Mechanics: detect `gpg` on `PATH` (error with install guidance if absent); run
`gpg --quiet --batch --decrypt <file>` per entry, reading plaintext from the child's stdout pipe
directly into a `Zeroizing<Vec<u8>>` (C11). Never pass secrets on argv (C31), never
write decrypted output to a temp file. gpg talks only to the local agent — no network (C23).

### 3.2 Input schemas (v1)

- **txt**: one entry per block, blank-line separated; first line `name`, second `password`,
  optional `key: value` lines (`username:`, `url:`, `notes:`). Mirrors the pass file convention
  so a hand-decrypted store imports trivially.
- **json**: documented array-of-objects schema:
  `[{ "name", "username", "password", "url", "notes", "tags": [], "otp": "otpauth://..." }]` —
  also the schema `vault export --format json` emits, so export/import round-trips.
- **bitwarden**: map `items[].name` → title, `login.username/password`, first `login.uris[].uri`
  → url (extra URIs → notes), `login.totp` → otp_secret, folder name → tag. Non-login item
  types (card, identity, secure note) → notes-only entries, flagged in the report.
- **keepassxc-csv**: RFC 4180 parsing; map Group→tag, Title, Username, Password, URL, Notes,
  TOTP columns. Header row is matched by name, not position (column sets vary by KeePassXC
  version — verify against a current export before freezing the mapping).

### 3.3 Import pipeline

```
parse(source) → Vec<RawEntry>            # format-specific, hostile-input rules apply (A4)
  → normalize → Vec<Entry>               # title/username/password/url/notes/tags/otp_secret
  → entropy_scan                          # zxcvbn per password (C26): < 60 bits ⇒ flag
  → dedupe                                # §3.4
  → report (stderr)                       # counts, weak list (names only — never secrets), skips
  → single save                           # ONE atomic write, ONE vault_version increment (C16)
```

All intermediate buffers holding secrets are `Zeroizing` (C11). The report prints entry *names*
and bit estimates only — no secret material on stdout/stderr (C27). Import requires an unlocked
vault session like every mutating command (C21).

### 3.4 Duplicate handling

Key = case-insensitive normalized title. Policy flag `--on-duplicate <skip|rename|overwrite>`:

| Mode | Behavior | Default |
|---|---|---|
| `skip` | keep existing entry, report skip | ✅ default |
| `rename` | import as `title (imported-2)` | opt-in |
| `overwrite` | replace existing entry | opt-in, per-run confirmation |

Never silently overwrite. Duplicates *within* the source (two identical titles) always rename.

### 3.5 Entropy scan & report (C26)

Each imported password runs through zxcvbn; estimate `bits = guesses_log10 × log2(10)` (the C26
formula). Entries below 60 bits are listed in the post-import report with the suggestion to
rotate via `vault gen`. Warn, never block (C26: warn-don't-refuse) — a migration must not strand
the user's data because their old passwords were weak. That's *why* they're migrating.

### 3.6 Post-import guidance (printed after a successful import)

1. **Destroy the source.** `shred -u <file>` on Linux — **with the caveat printed verbatim**:
   shred is not effective on SSDs, COW filesystems (btrfs/ZFS/APFS), or journaled metadata;
   on such storage the realistic options are filesystem-level encryption from day one or a
   secure-erase of free space. We tell the truth (same honesty rule as crypto-shredding,
   coverage-gap C2) rather than implying `shred` is a guarantee.
2. **Remember sync copies.** A KeePassXC CSV or Bitwarden JSON that ever touched a synced
   folder, cloud trash, or Time Machine persists there; the export should be created in a
   non-synced location to begin with (the docs say this *before* the export step).
3. **Rotate flagged passwords** (`vault gen`), starting with the weak list.
4. For `--format pass`: the old store's *git history* still leaks entry names (the C17 problem);
   deleting the working tree is not enough — delete the repo and its remotes.

### 3.7 What is NOT imported (v1)

| Item | Status | Reason |
|---|---|---|
| Attachments / file fields (KDBX, Bitwarden) | not imported, counted in report | no attachment model in v1 entry schema |
| TOTP edge cases (Steam TOTP, non-30s period, non-SHA1, non-6-digit) | raw `otpauth://` URI preserved in `otp_secret`, flagged | Vault v1 stores the secret; it does not generate codes, so exotic params are preserved but unvalidated |
| KDBX key-file / hardware-key credentials | n/a | we read the *decrypted* DB via master password only (M9) |
| Password history (KDBX, Bitwarden) | not imported | one current value per field in v1 |
| pass git history | not imported | history is the leak we're escaping |

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| sequoia-openpgp in-process decrypt | no gpg dependency; pure Rust | LGPL (fails C24/deny.toml); huge crypto dep for one importer (C3) | ❌ rejected |
| gpg subprocess (pass import) | zero new crypto deps; user's keyring already works | requires gpg on PATH; subprocess plumbing | ✅ **chosen (M9)** |
| KDBX direct read (`keepass` crate) | no plaintext CSV ever on disk; richer data | third-party parser of attacker-influenceable input — needs fuzzing before trust | ✅ chosen for M9 |
| KeePassXC CSV only (no kdbx) | trivial parser | forces user to write a plaintext CSV to disk | ✅ v1 stopgap, documented risk, kdbx supersedes it in M9 |
| rpgp (MIT/Apache OpenPGP crate) | license-compatible | still a large in-process crypto surface for one feature; subprocess is smaller | ❌ deferred — revisit only if gpg-subprocess proves unworkable |
| Import via stdin pipe only | no source file path handling | breaks directory-tree sources (pass); worse UX | ❌ (stdin accepted *in addition* for single-file formats) |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C21 (import) | implements `vault import --format txt\|json` plus named-manager formats as a superset |
| C26 | zxcvbn scan of every imported password; < 60 bits ⇒ stderr warning naming `vault gen`; warn-don't-block |
| C18 | imported fields exist only inside the AEAD payload; Vault writes no plaintext intermediate |
| C16 | exactly one save → one `vault_version` increment per import run |
| C17 | report prints names to the *terminal* only; no per-entry files created |
| C27 | no secret bytes on stdout/stderr at any point in the pipeline; report is names + bit counts |
| C11 | decrypted source material held in `Zeroizing` buffers end-to-end |
| C23 | no network: gpg subprocess is local; all parsing is local |
| C24 / C3 | no LGPL dependency; `keepass` crate is MIT and goes through `cargo audit`/`deny` |

## 6. Test plan

- **UNIT (per parser):** golden-file fixtures for each format, including quoting edge cases
  (CSV embedded commas/newlines, JSON escapes, otpauth URIs with exotic params).
- **FUZZ (A4):** `cargo-fuzz` harness per parser (csv, json, bitwarden, kdbx) — no panic, no
  OOM, no over-read on arbitrary bytes; bounded allocation against declared lengths.
- **INTEGRATION (pipeline):** import a 50-entry fixture; assert 1 file write, `vault_version`
  +1, all entries retrievable, `strings vault.vlt` reveals no imported field (C18 test recipe).
- **INTEGRATION (C26):** fixture containing "password1"; assert stderr warning containing
  "vault gen" and successful import.
- **INTEGRATION (dupes):** import the same fixture twice with each `--on-duplicate` mode;
  assert skip/rename/confirm behaviors.
- **INTEGRATION (pass, M9):** fixture GPG store + ephemeral test keyring; assert decrypt via
  subprocess, no secret on any argv (`/proc/<pid>/cmdline` check), no temp files.
- **MANUAL (pre-freeze):** verify KeePassXC CSV column set against a current KeePassXC release.

## 7. Open questions

1. Ship `keepass`-crate KDBX import already in v1 (PRD §9 Q2: P3 acquisition) or hold to M9
   for a dedicated fuzz cycle? This spec assumes M9.
2. Should `--format pass` re-encrypt-then-delete each source file as it goes (`--consume`),
   or is destruction strictly the user's manual step? (Current design: manual, guided.)
3. Chrome/Firefox password-CSV import — same CSV machinery, large audience; v1.x candidate?
4. Should the weak-password report be writable to a file (`--report PATH`)? It contains entry
   names (metadata) — probably stderr-only, consistent with C17's metadata stance.
