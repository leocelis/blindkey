# UC-08 — Recover from a sync conflict

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-8 · **Constraints:** C21 (merge), C16, SC3
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Two machines wrote the same vault concurrently; the sync backend now holds two valid, divergent
`.vlt` files (or the user has `vault.vlt` and `vault.sync-conflict-….vlt`). `vault merge OLD.vlt
NEW.vlt` (C21) produces one merged vault, entry by entry, without ever printing a secret value.

This spec covers: conflict detection, the merge algorithm and UX (masked diffs), the entry
identity model (per-entry UUID — an addition to the entry model), output-file semantics, and why
finer-grained mergeable encryption is prohibited (SC3).

Out of scope: detecting that the backend served an *old* file (UC-07 / C16), automatic merge on
save (KeePassXC-style "synchronize on save" is a v2 candidate), and group/folder hierarchies
(v1 entries are a flat namespace).

## 2. Prior art

### 2.1 Open source

- **KeePassXC database merge** — the model we adopt. Verified against the
  [KeePassXC User Guide](https://keepassxc.org/docs/KeePassXC_UserGuide) (June 2026): entries are
  matched **by UUID** regardless of group; "the most recently modified version will be made the
  current and the previous version will be placed into the entry's history." We adopt UUID
  matching and the modified-time tiebreak; we have no per-entry history in v1, so the losing
  version is surfaced in the diff instead of archived.
- **pass / gopass — the cautionary tale.** One GPG file per entry in Git means conflicts surface
  as binary-file merge conflicts Git cannot resolve textually; the "easy git merge" of per-entry
  stores only works because entry *names and existence* are plaintext — exactly the leakage C17
  prohibits ([passwordstore.org](https://www.passwordstore.org/); gopass docs). We refuse that
  trade: opaque blob + an explicit merge tool, instead of merge-friendliness bought with metadata.
- **Bitwarden** — last-write-wins with server timestamps; randomized per-entry cipher keys
  (never deterministic). Cloud-arbitrated, so not portable to local-first, but it confirms the
  randomized-encryption requirement (`research/vault_spec.md` Q2).

### 2.2 Academic / standards

- **Grubbs, Sekniqi, Bindschaedler, Naveed, Ristenpart (IEEE S&P 2017)** — leakage-abuse attacks
  recover "99 % of first names, 97 % of last names" from deterministically encrypted databases
  ([eprint 2016/895](https://eprint.iacr.org/2016/895)); with **Cash, Grubbs, Perry, Ristenpart
  (CCS 2015)** ([eprint 2016/718](https://eprint.iacr.org/2016/718)), the basis for SC3's
  prohibition (§3.6).
- **RFC 4122 / UUID v4** — random 128-bit entry identity; collision probability is negligible at
  vault scale and requires no coordination between machines (the property a merge needs).

## 3. Proposed design

### 3.1 Conflict detection

A conflict exists when two files both parse and verify (C7–C10) and share the same `vault_id`,
and either:

| Case | Signal | Meaning |
|---|---|---|
| D1 | `vault_version(A) ≠ vault_version(B)`, and neither file's entry set is a superset of the other | Divergent histories (both machines saved past the common ancestor) |
| D2 | `vault_version(A) == vault_version(B)` but header bytes differ (different `master_seed`/HMAC) | Split brain: same counter, different writes |

`vault merge` does not need to prove divergence to run — it is safe on any two same-`vault_id`
files (merging a strict ancestor is a no-op union). Different `vault_id`s → hard error
"these are different vaults" (no flag to override in v1; import is the tool for that).

**Rollback-anchor interaction (C16):** `vault merge` reads both inputs *bypassing* the
regression abort (one input is old by definition) and **never advances the anchor from an
input**. The anchor advances only when the merged output is written, whose version (§3.5) is
`max(old, new) + 1 ≥ last_seen` — so the merge never manufactures a rollback warning.

### 3.2 CLI behavior

```
vault merge OLD.vlt NEW.vlt [--output PATH] [--prefer newest|left|right] [--dry-run]
```

1. Parse + verify both headers (C9 order: hash → KDF → HMAC). Check same `vault_id`.
2. **Unlock both.** Prompt once for the master password and try it on *both* files (same vault
   lineage — usually the same password). If it fails on the second, prompt again for that file.
   Hardware stanzas are tried per the UC-09 ordering before each password prompt.
3. Decrypt both payloads into mlock'd `SecretBuffer`s (C11/C12); compute the entry union (§3.4).
4. Resolve conflicts: interactively per entry (default on a TTY, masked diff §3.4), or by
   `--prefer` non-interactively. Non-TTY without `--prefer` → exit 8 (usage), nothing written.
5. Write the merged vault atomically; print a summary (counts only, no field values).

`--dry-run` prints the summary and per-entry resolution plan (masked) without writing.
Exit codes: 0 merged · 1 error (parse/auth/IO) · 2 reserved (rollback, UC-07) · 3 unresolved
conflicts in non-interactive mode.

**Output path:** `--output PATH` if given; otherwise the configured active vault path
(`--file` / config). Inputs are never modified. If the output path equals one of the inputs,
write via atomic temp + rename and keep the displaced input as `<name>.premerge.bak`.

### 3.3 Entry identity — per-entry UUID (entry-model addition)

The merge keys on identity, not names (renames must not fork an entry). **Addition to the entry
model** (lives inside the encrypted payload, so no format-header change; needs intent sign-off):

```rust
struct Entry {
    uuid: [u8; 16],        // UUID v4 from OsRng, assigned once at creation, never changed
    title: SecretString,   // ... existing C18 fields ...
    created_at: i64,       // UTC seconds — already mandated encrypted by C18
    modified_at: i64,      // bumped on every field change; the merge tiebreak
    // ...
}
```

Rules: `vault add` generates the UUID; `vault edit` never touches it; import generates fresh
UUIDs (two machines importing the same CSV produce distinct entries — documented). `modified_at`
is set from the local clock; clock skew is therefore a tiebreak hazard (§7).

### 3.4 Merge algorithm — union by UUID, two-way (no common ancestor)

There is no stored ancestor, so this is deliberately a **two-way** merge ("three-way-less"):

| Case | Resolution |
|---|---|
| UUID only in one input | Keep it. **Consequence:** an entry deleted on one machine and untouched on the other is resurrected — v1 has no tombstones (§7) |
| UUID in both, all fields byte-equal | Keep one copy |
| UUID in both, fields differ | **Conflict** → prompt (TTY) or `--prefer` |

`--prefer newest` (the non-interactive default semantics, matching KeePassXC): higher
`modified_at` wins, whole-entry. `left`/`right` pick a side wholesale. v1 resolves conflicts
**per entry, not per field** — field-level cherry-picking is a v2 candidate.

**Interactive masked diff.** Secret values never reach the terminal (C27 spirit; also avoids
ANSI-injection surface, constraint C28 — field *names* are ours, field *values* are sanitized
before any display):

```
conflict 3/4 · entry "github-prod" (uuid 5f0c…)
  field        OLD (modified 2026-06-01 14:22)   NEW (modified 2026-06-08 09:10)
  username     leo@example.com                   leo@example.com        (same)
  url          https://github.com/org            https://github.com/o2  (differs)
  password     ••••••••                          ••••••••               (differs)
  notes        (unchanged)                       (edited)
Keep [o]ld / [n]ew / [s]kip entry / newest for [a]ll remaining? [n]
```

- **Protected fields (password, `otp_secret`, C19):** always rendered as exactly eight bullets —
  fixed width so the mask hides length too. Never a prefix, suffix, or checksum of the value
  (a displayed digest would be an offline-crackable oracle). Equality/difference is computed
  in memory (constant-time, C25) and reported only as `(same)` / `(differs)`.
- **Non-protected fields** (title, username, url, tags): shown in full — the user has already
  unlocked both payloads; these are display-sanitized per constraint C28.
- `[s]kip` keeps **both** versions: the loser is duplicated under a fresh UUID with title suffix
  `" (conflict 2026-06-08)"`, so no data is silently dropped.

### 3.5 Output file

The merged vault is a **new** save of the active vault lineage:

- `vault_version = max(vault_version(OLD), vault_version(NEW)) + 1` (monotonic past both heads;
  the C16 anchor advances to it on write).
- Fresh `master_seed` (C8), header re-HMAC'd (C9), payload re-encrypted and re-blocked (C1/C10).
- `data_key`: both inputs wrap the *same* data key (created once, C4) — verified by comparing the
  unwrapped keys in constant time; mismatch (one side ran a future `rotate-data-key`) is a hard
  error in v1 with guidance to re-run merge after rotating the other side.
- **Stanza set:** union by `stanza_type`, the NEW side winning per type; the password stanza must
  be present (C5 hard error otherwise). Rationale: a factor enrolled on either machine survives
  the merge; a factor removed on one machine but not the other survives too (remove again —
  conservative, documented).

## 3.6 Why not CRDTs or per-entry encryption (SC3)

- **Per-entry encrypted files** (the pass model, or encrypted-per-entry blobs): the backend sees
  entry count, per-entry sizes, and which entry changed when — the exact observation channel
  leakage-abuse attacks feed on, and C17 prohibits it outright.
- **Deterministic per-entry encryption** (needed for the backend — or a dumb CRDT store — to
  deduplicate/converge without keys): reveals the plaintext frequency distribution; Grubbs et al.
  reconstruct 99 % of first names from exactly this (§2.2). Prohibited by the intent's
  `prohibitions` list and SC3.
- **CRDTs** require either server-visible operations (each op's existence/timing leaks edit
  patterns) or per-entry convergent ciphertexts (above). Merge convenience is explicitly
  subordinated: SC3 resolution is last-write-wins + this manual merge tool.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Two-way union by UUID + `modified_at` tiebreak (proposed) | Matches KeePassXC precedent; no format change beyond entry UUID; honest about no-ancestor | Deletions resurrect; clock-skew sensitivity | **Adopt** |
| Three-way merge with stored ancestor hash/snapshot | True deletion detection | Requires keeping a second blob locally (availability + leakage surface) and defining ancestor identity across machines | Defer (v2, with tombstones) |
| Tombstone records for deletions | Fixes resurrection | Grows payload forever or needs GC policy; entry-model + intent change | Defer to v2 — pair with three-way |
| Per-field merge resolution | Less all-or-nothing | UX explosion; field-level provenance needed | Defer (v2) |
| CRDT / per-entry encrypted store | Automatic convergence | SC3 / Grubbs et al.; C17 | **Prohibited** |
| Auto-merge on open when split-brain detected | Zero-friction | Surprising writes; merge needs both files unlocked + user judgment | Reject; keep merge explicit |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C21 (merge) | Implements `vault merge OLD.vlt NEW.vlt` exactly; both inputs require valid unlock; confirmation semantics via interactive prompts |
| C16 | Output version = max+1 keeps the counter monotonic past both heads; inputs bypass the regression *abort* but never move the anchor; anchor advances only on the authenticated merged write |
| SC3 | Merge stays whole-blob and offline; no per-entry files, no deterministic encryption, no CRDT — the prohibited approaches are documented with the Grubbs et al. grounding in §3.6 |
| C5/C8/C9/C10 (by construction) | Output is a normal save: password stanza enforced, fresh master_seed, re-HMAC'd header and blocks |
| C25/C27 (touched) | Secret equality checks are constant-time; no secret value is ever printed — masked fixed-width bullets only |

## 6. Test plan

1. **UNIT (union):** A has {x}, B has {x, y} → merged {x, y}; identical entries deduplicate.
2. **UNIT (conflict, newest):** same UUID, different password, `modified_at(B) > modified_at(A)`,
   `--prefer newest` → B's entry wholesale; assert OLD's password absent from merged payload.
3. **UNIT (skip-keeps-both):** interactive `[s]` → two entries, fresh UUID + suffixed title on the loser.
4. **INTEGRATION (masked diff):** drive the prompt over a PTY; assert the secret value never
   appears in terminal output (`strings` over captured PTY stream), bullets are exactly 8 chars
   for both 4-char and 40-char passwords (length hiding).
5. **INTEGRATION (version):** OLD v7, NEW v9 → merged v10; reopen advances anchor to 10, no
   rollback warning; subsequently opening NEW (v9) again *does* warn (regression vs. 10).
6. **INTEGRATION (non-interactive):** stdin from `/dev/null`, conflicts present, no `--prefer` →
   exit 8 (usage), no output file written.
7. **INTEGRATION (identity):** `vault_id` mismatch → error "different vaults", exit 1.
8. **INTEGRATION (stanzas):** OLD has password+fido2, NEW has password only → merged has both;
   attempt to construct a merge dropping the password stanza → hard error (C5).
9. **UNIT (resurrection — documented behavior):** delete x on A, modify y on B, merge → x present;
   asserts the *documented* v1 semantics so a future tombstone change is a deliberate test break.

## 7. Open questions

1. **Tombstones / deletion semantics** — resurrection (§3.4) is the worst v1 wart. Tombstone
   records inside the payload (UUID + deleted_at, GC after N merges?) need an intent amendment;
   decide before M6 freezes the entry model, since retrofitting changes payload schema.
2. **Clock skew** — `modified_at` from unsynchronized clocks can pick the older edit. Prompt
   instead of auto-resolving when `|Δmodified_at| <` some epsilon (60 s?), even under `--prefer newest`?
3. **Entry UUID into the intent** — C18's field list doesn't name `uuid`; promote it (and its
   CSPRNG source / immutability rules) to a constraint or a C18 amendment before implementation.
4. **`--prefer` naming** — `left`/`right` vs `old`/`new`: positional names invite the user to
   believe OLD/NEW ordering matters beyond labels. Does it? (This spec: labels only.)
5. **Same-version split brain (D2)** — should `vault open` itself detect a sibling
   `.sync-conflict` file (Syncthing naming convention) and suggest `vault merge` proactively?
