# UC-06 — Find and Manage Entries Day-to-Day

> **Tech spec** · Accepted v0.2 · implemented pre-1.0 · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-6 · **Constraints:** C21, C25, C18 via SC2; C11, C13
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

The daily loop: find an entry (`vault ls --search`), change it (`vault edit`), remove it
(`vault rm`), and rely on the session locking itself when you walk away (C25). This spec
covers:

- in-memory search with **no on-disk index** (SC2's resolution: `C18 > C21`),
- the `vault edit` flow and the `$EDITOR` swap-file leak it must not reproduce,
- `vault rm` confirmation semantics,
- the v1 session model: **per-process, no daemon** — what C25's auto-lock means in that world,
- the `~/.vault.toml` configuration schema (validated, loud on error).

## 2. Prior art

### 2.1 Open source

| Source | Relevance |
|---|---|
| `pass` ([passwordstore.org](https://www.passwordstore.org/)) | Search = `ls`/`grep` over plaintext *filenames* — the metadata leak C17/C18 exist to prevent. `pass edit` creates the tempfile in `/dev/shm`; **if `/dev/shm` is unavailable it falls back to `$TMPDIR` with a warning** (verified from the man page) — plaintext on real disk, the known weakness we refuse to inherit (§3.3). Session = gpg-agent's passphrase cache (a daemon). |
| KeePassXC | Long-lived GUI process holding decrypted state; idle auto-lock and lock-on-suspend options; in-memory search over the open database — the UX bar for §3.2's results. Molotnikov 2023 audit flagged in-memory secret handling, which C11/C12 address at the type level. |
| 1Password CLI ([app integration](https://developer.1password.com/docs/cli/app-integration/), verified June 2026) | Desktop-app/biometric unlock; without it, `op signin` issues **session tokens that expire after 30 minutes of inactivity**. A daemon+token architecture — explicitly *not* v1's model (§3.4), cited as the contrast. |
| [gopass](https://github.com/gopasspw/gopass) | `gopass fsck`, fuzzy search over names — still plaintext-filename-based like pass; same structural leak. |

### 2.2 Academic / standards

- Grubbs et al. leakage-abuse line (CCS 2015 / IEEE S&P 2017, cited in the intent): any
  searchable *on-disk* structure over encrypted entries leaks access/frequency patterns —
  the research basis for SC2's "no plaintext index, search in memory only".
- [`memfd_secret(2)`](https://man7.org/man/man2/memfd_secret.2.html) (Linux 5.14+): anonymous
  RAM that is removed from the kernel direct map — evaluated and **not** used for `--editor`
  (§4: editors need a path, not an fd).
- [research/security_coverage_gaps.md](../../research/security_coverage_gaps.md) B3 (ptrace),
  C1 (atomic writes) — adjacent hardening that edit/rm rely on but do not re-specify.

## 3. Proposed design

### 3.1 Session primitive shared by all commands

```rust
/// Lives exactly as long as one CLI invocation (v1: no daemon — §3.4).
pub struct Session {
    data_key: Secret<[u8; 32]>,          // C11: zeroize-on-drop; C12: mlock'd
    entries: Zeroizing<Vec<Entry>>,      // full decrypted payload (SC2)
    dirty: bool,
    last_activity: Instant,              // feeds the C25 idle timer (interactive mode)
}
```

Single-shot commands (`get`, `ls`, `rm …`) create a `Session`, use it, and drop it — zeroize
runs unconditionally on scope exit. Long-lived flows (interactive `edit`, a future REPL) are
where the C25 idle timer actually ticks (§3.4).

### 3.2 `vault ls --search` — in-memory, O(n), no index

Per SC2: search requires unlock, runs over the decrypted entries in mlock'd memory, and
**never** creates an on-disk index, cache, or "recent results" file. O(n) over < 10,000
entries is sub-millisecond — the decrypt+KDF dominates by orders of magnitude.

Matching (proposed: substring + prefix ranking — deliberately boring):

1. Normalize query and fields to lowercase (Unicode simple casefold).
2. Match against `title` and `tags` (not username/notes by default; `--all-fields` opt-in —
   usernames are semi-sensitive and noisy in results).
3. Rank: exact title match → title prefix → title substring → tag exact → tag substring.
   Ties break alphabetically. No fuzzy/edit-distance matching in v1: fuzzy scorers are
   surprising, harder to test, and invite dependency weight for marginal benefit at vault
   scale (§4).

```rust
fn rank(query: &str, e: &Entry) -> Option<u8> {        // lower = better
    let t = e.title.to_lowercase();
    if t == query                    { Some(0) }
    else if t.starts_with(query)     { Some(1) }
    else if t.contains(query)        { Some(2) }
    else if e.tags.iter().any(|g| g.eq_ignore_ascii_case(query)) { Some(3) }
    else if e.tags.iter().any(|g| g.to_lowercase().contains(query)) { Some(4) }
    else { None }
}
```

Output: entry titles (+ tags with `-v`), one per line, **ANSI/control-sanitized** before
printing (gap A2 — a hostile imported title must not own the terminal). Secrets never appear
in `ls` output under any flag. Plain `vault ls` lists all titles, same ordering rules.

### 3.3 `vault edit` — field-by-field by default; `$EDITOR` only into RAM

**The `$EDITOR` problem:** handing a plaintext temp file to an editor leaks via vim swap files
(`.swp`), undo persistence (`~/.viminfo`, undodir), backup-on-write copies, editor LSP/plugin
indexing, and crash artifacts — on disk, outside the vault, invisible to C18's guarantees.
pass mitigates with `/dev/shm` but **falls back to `$TMPDIR` (real disk) with a warning**;
we treat that fallback as a defect, not a feature.

**Default flow — interactive field-by-field prompts (no temp file at all):**

```
$ vault edit github-prod
  title    [github-prod]:            ⏎ keep
  username [leo]:                    ⏎ keep
  password [unchanged]:              (g)enerate / (e)nter / ⏎ keep → g
  Generated: 20 chars … = 131.1 bits (uniform CSPRNG).    ← UC-02 §3.4
  url      [https://github.com/o]:   ⏎ keep
  notes    [1 line]:                 ⏎ keep
Save changes? [Y/n]
```

Secrets are entered no-echo; every buffer is `Zeroizing`; the updated entry is re-encrypted
and saved atomically (gap C1 pattern: temp file in vault dir → fsync → rename). Nothing
touches the filesystem in plaintext.

**`--editor` opt-in (power users editing long notes):**

- Linux: create `0700` dir + `0600` file under `/dev/shm/vault-edit.XXXXXX` (RAM-backed tmpfs),
  launch `$EDITOR`, read back, shred-overwrite + unlink, then best-effort `rmdir`.
  Set `$TMPDIR`/`VIMINIT` hints? No — we cannot control editor side-channels; instead the
  prompt before launch states: *"Your editor may write swap/undo copies; configure it for
  sensitive files (vim: `:set noswapfile noundofile nobackup`)."*
- macOS / platforms without a guaranteed RAM-backed path: **refuse** `--editor` with
  `no RAM-backed temporary filesystem on this platform; use the interactive editor (default)`.
  Refusal-over-fallback is the pass lesson applied (no silent plaintext on disk, ever).
- `memfd_secret`/`O_TMPFILE` were evaluated and rejected for this path: editors require a
  *named path* and re-open it by name (write-rename dance), which breaks fd-backed schemes (§4).
- The notes field only is offered via `--editor`; passwords are never routed through an editor.

### 3.4 Sessions and auto-lock (C25) — v1 is per-process, no daemon

**What v1 ships:** every `vault` invocation derives keys, does its work, zeroizes, exits.
There is no background agent, no socket, no cached unlock between commands. Consequences,
stated plainly (this goes in CLI.md too):

- Each command that needs the payload prompts for the master password (or touches a hardware
  stanza). That is the deliberate UX cost.
- The C25 idle timer (default **300 s**, `auto_lock_seconds`, min 30 / max 3600 / 0 = disabled)
  governs **long-lived states**: the interactive `edit` session, a future REPL/TUI, and any
  command blocked on user input. On expiry: zeroize `Session` (keys + entries + mlock'd pages,
  per C25), then either exit (one-shot command) or demand re-unlock (interactive flow).
- The UC-04 clipboard holder is *not* a session: it holds one delivered field, never keys.

**Why no daemon in v1** (contrast with prior art):

| Tool | Session model | Cost |
|---|---|---|
| pass | gpg-agent daemon caches the GPG passphrase | Unlock state lives in a third-party daemon with its own cache policy and socket |
| KeePassXC | Long-lived GUI process holds decrypted DB; idle/suspend auto-lock | Whole-vault plaintext resident for the app lifetime (audit-flagged memory handling) |
| 1Password CLI | Desktop-app integration (biometric) or `op signin` session tokens, 30-min inactivity expiry (verified) | Daemon + IPC + token surface |
| **vault v1** | **Per-process; nothing survives the command** | More password prompts |

A daemon is the single biggest attack-surface addition a vault can make (live keys, an IPC
endpoint, a token to steal). v1 buys auditability with keystrokes. A post-v1 optional agent
(socket-peer-credential-checked, hardware-tap-to-release) is roadmap material and must arrive
as new constraints, not as a quiet feature.

### 3.5 `vault rm NAME`

1. Resolve entry (exact title; if multiple/ambiguous after C28-sanitized listing → exit 9).
2. TTY: prompt `Delete entry 'github-prod'? This cannot be undone. [y/N]` — default **No**.
   Non-TTY: require `--yes` (UC-05 §3.3 matrix; exit 2 without it).
3. Remove from the in-memory entry set, save atomically, `vault_version += 1` (C16).
4. Deletion is **crypto-shredding semantics** (gaps C2): the entry is absent from the
   re-encrypted payload; we do not promise physical erasure of old blob generations on SSDs or
   in sync history — documented in the user guide, with `vault rotate-data-key` as the future
   stronger answer.

### 3.6 `~/.vault.toml` — configuration schema

```toml
# ~/.vault.toml — all keys optional; absent file = all defaults.
vault_file        = "~/.vault/vault.vlt"   # default vault path (CLI --file overrides)
clipboard_timeout = 30      # seconds; C13: min 5, max 300, default 30
auto_lock_seconds = 300     # seconds; C25: min 30, max 3600, 0 = disabled, default 300
```

```rust
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]            // typos fail loudly, not silently
pub struct Config {
    pub vault_file: Option<PathBuf>,
    #[serde(default = "d30")]  pub clipboard_timeout: u64,   // validated 5..=300   (C13)
    #[serde(default = "d300")] pub auto_lock_seconds: u64,   // 0 or 30..=3600      (C25)
}
```

- **Out-of-range values are errors, not clamps** (exit 2 with the offending key and the legal
  range). Silent clamping would let `clipboard_timeout = 99999` masquerade as configured
  while running at 300 — a misleading security posture.
- The config file holds **no secrets** and is read-only input; the vault never writes it.
  Unknown keys rejected (`deny_unknown_fields`) so `auto_lock_secnds = 0` cannot silently
  disable nothing.
- Permissions: warn (not fail) if the file is group/world-writable — a writable config could
  redirect `vault_file`.

### 3.7 Error paths (shared)

| Condition | Behavior |
|---|---|
| Search with locked vault | Unlock prompt (TTY) or exit 5 (non-TTY, UC-05 matrix) |
| `edit` interrupted (SIGINT) mid-flow | No partial save; in-memory buffers zeroized on unwind; original entry intact |
| `--editor` returns empty file / parse failure | Abort with message; entry unchanged; shm file shredded regardless |
| Config parse error / out-of-range | Exit 2, name the key, show legal range; never half-apply a config |
| `rm` of nonexistent entry | Exit 3, sanitized echo of the queried name |

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| On-disk search index (even encrypted) | O(log n), instant for huge vaults | Leakage-abuse surface (access/frequency patterns); prohibited by SC2; pointless at < 10k entries | **Rejected** |
| Fuzzy matching (Levenshtein / `fzf`-style scoring) | Typo tolerance | Surprising ranking, dependency weight, harder constraint tests; substring+prefix covers the 99% case | **Rejected v1** (revisit with user evidence) |
| `$EDITOR` as the default edit flow (pass model) | Familiar | Swap/undo/backup leaks; pass's own `$TMPDIR` fallback is the documented weakness | **Rejected** — field prompts default, RAM-only `--editor` opt-in |
| `memfd_secret`-backed editor buffer | Strongest RAM guarantee | Editors need named paths and rename-on-write; fd-backed files break them; Linux-only, root-config-dependent | **Rejected** for editor path; noted for internal buffers post-v1 |
| `$TMPDIR` fallback with a warning when no `/dev/shm` | Editor works everywhere | Plaintext on real disk contradicts C18's spirit; warnings get ignored | **Rejected** — refuse instead |
| Daemon/agent with cached unlock in v1 | Fewer prompts | Largest possible new attack surface; needs its own constraint set; against the v1 simplicity principle | **Deferred** post-v1 |
| Config clamping to legal ranges | Forgiving | Misrepresents the running security posture | **Rejected** — loud error |
| `rm` soft-delete / trash | Undo safety | A "deleted but present" plaintext-equivalent inside the payload surprises users; version history via sync backend already exists | **Rejected v1** |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C21** | `ls --search`, `edit`, `rm` (confirmation required), `lock` semantics all specified; round-trip test §6.1 mirrors C21's integration test |
| **SC2 / C18** | Search exclusively in-memory over the decrypted payload (§3.2); no index, cache, or result file ever written; documented O(n) tradeoff |
| **C25** | Auto-lock default 300 s, configurable 30–3600 / 0 via `auto_lock_seconds` (§3.4, §3.6); lock zeroizes all key material and mlock'd pages; constant-time comparison and core-dump rules inherited from C25 unchanged |
| **C11 / C12** | `Session` uses `Secret`/`Zeroizing` types, mlock'd; every edit/search buffer zeroized on drop (§3.1, §3.3) |
| **C13** | `clipboard_timeout` schema bounds (5–300, default 30) match C13 exactly (§3.6) |
| **C16** | `rm`/`edit` saves increment `vault_version` by exactly 1 (§3.5) |
| Gap A2 | All echoed entry-derived strings sanitized before terminal output (§3.2, §3.7) |

## 6. Test plan

1. **INTEGRATION (C21 round-trip):** init → add → get → ls → edit → rm; assert rm prompts and
   `n` aborts with entry intact; `--yes` required when stdin piped.
2. **UNIT (ranking):** fixture entries; assert exact > prefix > substring > tag ordering and
   alphabetical tie-break; case-insensitive matches.
3. **INTEGRATION (SC2):** run `vault ls --search github` under `strace -e trace=openat,write`;
   assert no file created/written besides the state file and TTY; before/after directory
   snapshot identical.
4. **INTEGRATION (edit, no plaintext on disk):** run field-by-field edit changing the password;
   `grep -r` the filesystem temp locations (`$TMPDIR`, `/tmp`, `/var/tmp`) for the new secret →
   zero hits. With `--editor` on Linux: file existed only under `/dev/shm`, gone after.
5. **INTEGRATION (`--editor` refusal):** on macOS CI, `vault edit X --editor` → exit ≠ 0,
   message contains `RAM-backed`.
6. **INTEGRATION (C25):** interactive session with `auto_lock_seconds = 30` (mock clock);
   after 31 s idle, next action demands re-unlock; memory test hook asserts key pages zeroed.
7. **UNIT (config):** `clipboard_timeout = 4` → exit 2 naming the key and `5..=300`;
   `auto_lock_seconds = 0` → accepted, timer disabled; unknown key → exit 2.
8. **UNIT (A2):** entry titled `evil\x1b]52;c;…\x07` lists as escaped/visible text; raw ESC
   byte absent from captured output.

## 7. Open questions

1. **Ambiguous-name UX for `rm`/`edit`/`get`:** error-with-candidates (current proposal) vs
   interactive picker — picker is friendlier but adds TTY-only behavior divergence.
2. **`--all-fields` search scope:** include notes (potentially large, semi-sensitive) or keep
   to title/tags/username? Current: include, opt-in only.
3. **`vault lock` in a per-process world** is near-vacuous v1 (clears the local state file's
   session hints and the clipboard holder, if any) — keep for forward-compat with an agent, or
   document as a no-op? Current: keep, document exactly what it clears.
4. **Unicode casefold:** simple lowercase vs full casefold for search normalization (relates to
   gap E2's NFC decision for the master password — settle both together).
5. **macOS RAM-backed alternative** for `--editor` (`hdiutil` APFS ramdisk is heavy; refusal is
   current policy) — revisit only on user demand.
