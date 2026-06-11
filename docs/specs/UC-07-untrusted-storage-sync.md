# UC-07 — Sync the vault over storage you don't trust

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-7 · **Constraints:** C17, C16, C10, C9
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

The vault is a single opaque blob (`vault.vlt`, C17) that the user drops into Git, Dropbox,
Syncthing, or any other backend they do **not** trust. This spec covers:

1. What the backend can and cannot learn (residual metadata leakage, and padding as a mitigation).
2. Rollback detection (C16): local anchor file format, platform paths, TOCTOU handling,
   multi-machine semantics, non-interactive behavior.
3. Practical guidance for Git as the backend.

Out of scope: conflict *merging* (UC-08), the hosted-sync non-goal, and transport security
(the blob is its own envelope; the transport is assumed hostile).

## 2. Prior art

### 2.1 Open source

| Tool | Model | Lesson |
|---|---|---|
| `pass` / gopass | One GPG file per entry in a git repo | Entry names, counts, and edit patterns leak in plaintext paths and git history — the anti-pattern C17 prohibits |
| Syncthing untrusted-device mode | Per-file encryption, AES-SIV filenames | Still leaks file sizes (~1 KiB granularity), counts, directory structure ([Syncthing spec](https://docs.syncthing.net/specs/untrusted.html), `research/vault_spec.md` §6) |
| KeePassXC / age / Bitwarden | Single blob / format only | **None** implements whole-file rollback detection (C16 rationale) — the gap this spec closes |
| gocryptfs | Per-file encrypted FS | Audit: "no security at all against an active adversary who can modify the ciphertexts" — why C9/C10 integrity is mandatory |

### 2.2 Academic / standards

- **PURBs / Padmé** — Nikitin, Barman, Lueks, Underwood, Hubaux, Ford, *"Reducing Metadata
  Leakage from Encrypted Files and Communication with PURBs"*, PoPETS 2019(4) / PETS 2019
  ([petsymposium.org/popets/2019/popets-2019-0056.php](https://petsymposium.org/popets/2019/popets-2019-0056.php),
  [arXiv:1806.03160](https://arxiv.org/abs/1806.03160)). Padmé padding limits length leakage to
  **O(log log M)** bits with overhead **≤ 12 %, decreasing with payload size** (verified against
  the abstract, June 2026). Evaluated in §3.2.
- **TCG TPM 2.0 NV counters** — a 64-bit value that can only increment; "cannot be rolled back by
  deleting it and redefining it" ([tpm2_nvincrement](https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_nvincrement.1/),
  C16 rationale). The upgrade path in §3.5.
- **KDBX 4** header integrity (SHA-256 + keyed HMAC) and HmacBlockStream — already adopted as C9/C10;
  they make *tampering* detectable, leaving *rollback* as the one attack a backend can still mount.

## 3. Proposed design

### 3.1 The single-blob property and what the backend learns

C9 (keyed header HMAC), C10 (per-block encrypt-then-MAC), and C1 (STREAM chunking) make every
splice, truncation, reorder, and KDF-downgrade detectable. C17/C18 put every entry field inside
the AEAD payload. What remains observable to a backend that stores every version it is given:

| Signal | Granularity | What it reveals |
|---|---|---|
| Blob size | exact bytes | Entry count, coarsely. Header ≈ 250–600 B + ~36 B/MiB block overhead + ~16 B/64 KiB chunk tag; a typical entry serializes to ~200–600 B, so size ≈ affine in entry count |
| Size *deltas* across versions | exact bytes | Approximate size of each edit (added a note vs. added an entry) |
| mtime / version timestamps | backend-dependent | The user's editing schedule; correlation with external events |
| Save frequency | per version | How actively the vault is used |

Backends with history (Git, Dropbox version history) retain **every** past blob. Two consequences
to document for users: (a) `vault upgrade-kdf` does not re-protect old copies in backend history —
they remain crackable at the *old* KDF cost; (b) size history is a growth curve of the vault.

### 3.2 Padding (Padmé) — evaluated, verdict: optional / v2

Mitigation for the size signal: pad the **plaintext payload before STREAM encryption** (padding
inside the AEAD, so it is authenticated and invisible) up to a bucket size.

| Scheme | Leakage | Overhead | Notes |
|---|---|---|---|
| None (v1 default) | full length | 0 % | Status quo |
| Fixed 4 KiB buckets | length ÷ 4096 | < 4 KiB | Hides small edits; large vaults still distinguishable |
| Next power of two | O(log M) → very coarse | ≤ 100 % | Too expensive at MiB sizes |
| **Padmé (PURBs)** | **O(log log M) bits** | **≤ 12 %, shrinking with size** | Round length up so only ⌊log₂ log₂ L⌋+1 mantissa bits of the length are significant |

Padmé is the right curve: near-power-of-two privacy at near-fixed-bucket cost. But padding does
not hide save *frequency* or mtime, and a 12 % bound on a 100 KiB vault is noise to a real
adversary only if many users share bucket sizes. **Verdict: ship v1 unpadded; reserve a
`pad = "padme" | "none"` knob (config + payload-level, format-compatible since padding lives
inside the AEAD) for v2.** Promoting this to a constraint requires intent approval.

### 3.3 Rollback anchor — local state file (C16)

One file **per `vault_id`**, as scaffolded by `anchor_path()` in
[`crates/vault-core/src/rollback/mod.rs`](../../crates/vault-core/src/rollback/mod.rs).

**Path (per platform, via the `directories` crate):**

| Platform | Anchor path |
|---|---|
| Linux | `$XDG_DATA_HOME/vault/<vault_id_hex>.state` (default `~/.local/share/vault/…`) |
| macOS | `~/Library/Application Support/vault/<vault_id_hex>.state` |
| Windows | `%LOCALAPPDATA%\vault\<vault_id_hex>.state` — **Local**, not Roaming: Roaming AppData syncs across domain machines, which would silently violate the per-machine anchor semantics of §3.5 |

`<vault_id_hex>` = lowercase hex of the 16-byte `vault_id` (32 chars). The file lives outside the
vault directory and must never be added to a synced dotfiles repo (C17 test asserts this layout).

**Content: exactly 8 bytes — `last_seen` as u64 little-endian.** C16 specifies "a plain u64";
richer formats were considered and rejected (§4). A missing, empty, or short anchor file is
treated as `last_seen = 0` (never a hard error — the anchor is an alarm wire, not a lock).

```rust
/// rollback/mod.rs (extends the existing scaffold)
pub fn read_anchor(path: &Path) -> u64;          // missing/invalid → 0
pub fn advance_anchor(path: &Path, seen: u64) -> Result<()>; // monotonic, atomic
pub fn check(payload_version: u64, last_seen: u64) -> RollbackCheck; // scaffolded
```

### 3.4 Open/save sequencing and TOCTOU

The window between reading the anchor and updating it spans the Argon2id unlock (hundreds of ms),
and a second `vault` process may run concurrently. Rules:

1. **Read order on open:** read anchor → unlock + verify (C9 header HMAC, C10 block HMACs, C1 tags)
   → read `vault_version` from the *authenticated* payload → `check()`. The version is trusted
   only because it sits inside the AEAD; never read it from any cache.
2. **Advance is monotonic and locked:** `advance_anchor` takes an advisory lock (`flock`/
   `LockFileEx`) on the anchor file, re-reads it, writes `max(current, seen)` to a temp file in
   the same directory, `fsync`s, and atomically renames. A concurrent open can therefore never
   lower the anchor (classic check-then-write TOCTOU eliminated by re-read-under-lock + max).
3. **Save order:** write the new vault blob first (atomic temp + rename, coverage-gap C1-atomic),
   **then** advance the anchor to the new version. A crash between the two leaves
   `payload_version ≥ last_seen` — safe. The reverse order would manufacture false alarms.
4. `--allow-rollback` proceeds but does **not** lower the anchor; the anchor only moves forward.

### 3.5 Multi-machine semantics — the documented gap

The anchor is **per machine**. The regression warning fires only relative to what *this machine*
has seen. Concretely: machine A saves v10; machine B (last saw v5) is served v6 by the backend —
**no warning fires on B**, even though v6 is stale. C16 detects *regression below local
knowledge*, not *global staleness*. This is inherent to a local-first design with no shared
trusted state, and is documented user-facing.

Two distinct hardening paths (both from the C16 rationale, both post-v1):

- **TPM NV monotonic counter** (`tpm2_nvincrement`): protects the *anchor itself* against
  same-user malware editing the 8-byte state file backwards. It is still per-machine — it does
  not close the cross-machine staleness gap.
- **Git signed commits** as an append-only log close part of the staleness gap when Git is the
  backend, if the client pins the last-seen commit hash (see §3.7).

### 3.6 Non-interactive behavior (C16, persona P4)

If `check()` returns `Regressed { expected, got }`:

- **TTY:** print to stderr `WARNING: vault version regressed (expected >= <N>, got <M>). The sync
  backend may have served an older copy. Proceed anyway? [y/N]` — default N, abort.
- **Non-TTY stdin:** no prompt; print the warning to stderr; **exit code 2**. Exit 2 is reserved
  exclusively for rollback so scripts can branch on it.
- `vault open --allow-rollback` (and the same flag on any unlocking subcommand) proceeds
  non-interactively, still printing the warning. The anchor is not lowered (§3.4).

### 3.7 Interaction with Git

- **`.gitattributes`:** ship and document `*.vlt binary` (equivalent to `-diff -merge -text`).
  Without it, Git may attempt textual diff/merge on the blob; a textual "merge" of two `.vlt`
  files produces garbage that fails C9/C10 verification loudly (good) after wasting the user's
  time (bad). With `-merge`, conflicting versions are left intact for `vault merge` (UC-08).
- **Diff noise:** every save rewrites the header (`master_seed` and `nonce_prefix` both rotate per body-writing save, C8/C1) and the
  body; commits are whole-blob binary changes. Delta compression across versions is poor by
  design — accept repository growth, recommend a dedicated repo and occasional `git gc`.
- **git-lfs:** **not recommended.** Vaults are KiB–low-MiB; LFS adds a second server dependency,
  weakens the offline-first story, and its pointer files add no privacy (size still visible on
  the LFS server). Revisit only if vaults beyond ~50 MiB become a real use case.
- **Signed commits:** `git commit -S` gives an authenticated append-only history; a client that
  also records the last-seen commit hash locally can detect a remote serving an older signed
  commit. This is an optional belt-and-braces layer on top of C16, not a replacement.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| One anchor file per `vault_id` (proposed) | No cross-vault lock contention; corruption blast radius = one vault; trivial parser; matches `anchor_path()` scaffold | Directory of small files | **Adopt** |
| Single map file `vault_id → last_seen` | One file | One corrupt write kills all anchors; needs serialization format + whole-file lock; contradicts the scaffold | Reject |
| Anchor with magic/version/CRC framing | Self-describing | C16 says "a plain u64"; intent wins; framing adds parse failure modes to an alarm wire | Reject (note for v2 intent revision) |
| Anchor in OS keychain | Harder for same-uid malware to edit | Platform-divergent, breaks headless/CI, adds prompt friction on every open | Reject for v1; TPM NV is the stronger upgrade anyway |
| Padmé padding on by default | Best size privacy | ≤ 12 % overhead, hides little against per-user longitudinal observation, not constraint-backed yet | Optional / v2 (§3.2) |
| git-lfs for the blob | Handles huge files | Server dependency, no privacy gain, breaks offline | Reject |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C17 | One `.vlt` blob; anchor lives in platform data dir, not the vault dir; nothing per-entry ever touches the backend |
| C16 | Per-vault 8-byte u64 LE anchor at XDG/AppData path; warn + default-abort on regression; exit 2 + `--allow-rollback` non-interactively; anchor advanced only after authenticated read, monotonically, under lock |
| C10 | Per-block HMAC (keyed per block index + per-save `master_seed`) defeats block substitution/truncation by the backend; this spec adds no body-format change |
| C9 | Keyed header HMAC defeats KDF-downgrade by the backend; verification order (hash → KDF → HMAC → payload) unchanged |

## 6. Test plan

Beyond the C16/C17 tests already in the intent (which remain authoritative):

1. **UNIT** `read_anchor`: missing file → 0; 8 valid bytes → value; short/garbage file → 0, no panic.
2. **UNIT** `advance_anchor` monotonicity: advance to 5 then 3 → file still 5.
3. **INTEGRATION (concurrency):** two processes open the same vault simultaneously; assert the
   anchor ends at the max version and is never observed torn (read returns 0 or a valid u64).
4. **INTEGRATION (crash order):** kill the process between blob rename and anchor advance;
   reopen; assert no rollback warning (payload ≥ anchor).
5. **INTEGRATION (exit code):** stdin from `/dev/null`, regressed file → exit 2, warning on
   stderr, no prompt; with `--allow-rollback` → exit 0, warning still printed, anchor unchanged.
6. **INTEGRATION (multi-machine gap):** fresh anchor dir (simulating machine B), open v6 after
   "machine A" wrote v10 → no warning; documented-behavior test, not a bug test.
7. **INTEGRATION (git):** commit two versions of a vault to a repo with `*.vlt binary`; assert
   `git diff` reports "Binary files differ" and a forced textual merge never silently succeeds.

## 7. Open questions

1. **Cross-save ciphertext determinism — Resolved.** C1 now derives
   `payload_key = HKDF(ikm=data_key, salt=nonce_prefix, info="vault-payload-v1")` where
   `nonce_prefix` is a 16-byte CSPRNG field in the plaintext header (C8), regenerated on every
   body-writing save. Two successive saves of the same vault produce entirely different ciphertext
   (different `nonce_prefix` → different `payload_key` → different keystream). Unchanged chunks
   are no longer byte-identical across versions; the edit-locality oracle and keystream-reuse
   channels are closed. The size/mtime signals in §3.1 remain. (`nonce_prefix` is covered by
   `header_hash`/`header_hmac` — any tampering with it is detected before decryption. It is not
   regenerated by stanza-only rewrites such as password rotation — see C1, C4, SC6 in
   `vault_intent.yaml`.)
2. Should the rollback warning also fire on *equal* version but different header bytes (same
   `vault_version`, different `master_seed`) — a split-brain signal that belongs to UC-08?
   *Disposition 2026-06-10: deferred to the Part-2 backlog (a header-generation counter in the
   local anchor). G0.3 already closed the KDF-upgrade case by making `upgrade-kdf` a full
   version-bumping save; the residual window is header-only ops (password rotation) served
   stale — and old credentials can decrypt the old blob offline regardless, which rollback
   detection cannot change.*
3. Anchor garbage collection: vaults deleted or re-created leave stale `.state` files; ship
   `vault doctor` cleanup or ignore (8 bytes each)?
   *Disposition 2026-06-10: ignore for v1 (8 bytes each; a re-created vault gets a fresh
   UUIDv4 vault_id, so stale anchors can never collide). `vault doctor` stays a Part-2 idea.*
4. Padmé adoption criteria for v2: what adversary model justifies the 12 % ceiling — and should
   padding also quantize *save times* (batching) to blunt the mtime channel?
