# UC-30 — Volume working copy (checkout / checkin)

> **Tech spec** · **Accepted v0.3** · September 2026 · **Status:** core + CLI + GUI Blindfolder complete (W0–W5); GUI opens a cleartext working folder via `MaterializedMount` (ADR-0010 degraded path); Linux FUSE remains optional `volume-mount`; optional macOS FUSE via user macFUSE + `macos-fuse`  
> **Cross-checked:** 2026-09-07 vs research R1–R17 + live CLI/GUI/core · **Impl↔spec gap close:** 2026-09-07 (§19)  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-30  
> **Constraints:** C99–C102 (G22, **PASS**) · **amends** C73 (live mount of a *sync-path* `.vltd` stays forbidden)  
> **Depends on:** [UC-25](UC-25-local-encrypted-volume.md) (volume format + mount) · [UC-07](UC-07-untrusted-storage-sync.md) · [ADR-0011](../adr/0011-volume-working-copy-checkout.md) · [ADR-0010](../adr/0010-volume-macos-mount-matrix.md) (macOS mount)  
> **Research:** [volume_working_copy_research.md](../../research/volume_working_copy_research.md) (R1–R17 closed)  
> **Sibling (not this UC):** [UC-23](UC-23-sealed-file-storage.md) — one-shot `.vltf` archive for cloud  
> **User-facing name:** Blindfolder (same feature; this spec uses the capability name)  
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the **intent wins**.

This document is the **implementation contract**: checkout/checkin lifecycle, hydration
gates, working-copy layout, outer fingerprint, atomic replace, crate/CLI/GUI surfaces,
tests, and phased delivery. Volume crypto and FUSE mount stay in UC-25; this UC only
moves a **closed** `.vltd` out of and back into an untrusted sync folder.

---

## 1. Scope & goals

A single operator wants a VeraCrypt-class folder: unlock Blindkey → work in a normal
directory → lock → ciphertext only — and wants the **brick** (`.vltd`) to live in a sync
folder so another machine (or tomorrow) can open the same workspace.

| # | Goal |
|---|------|
| 1 | **Checkout** a sync-folder `.vltd` to a local non-sync **data** directory (same root as C70 anchors) |
| 2 | Open **only** that working copy (UC-25 FUSE **or** `MaterializedMount` cleartext folder); never the sync-folder path (C73 / C99) |
| 3 | **Checkin** via sibling temp + `fsync` + `rename` (C100); outer fingerprint guard (C101) |
| 4 | Crash/resume via a sidecar next to the working copy — never in the sync folder |
| 5 | Honest docs: checkin ≠ “every device has it”; no Blindkey-side delta sync (C102) |

**Supported cloud story:** checkout → UC-25 mount of the copy → on eject, atomic replace
back into the sync folder. Sync clients (Dropbox, Drive, iCloud, Syncthing, OneDrive, …)
are **examples of a class**, not product integrations.

**Forbidden (C73, unchanged):** mount the `.vltd` that sits *inside* the sync folder, or
let the sync client upload the brick while it is mounted.

### 1.1 Non-goals

- Live RW mount of the sync-path file (C73).
- Pausing or automating Dropbox / Drive / iCloud / Syncthing.
- Hosted Blindkey sync service.
- Multi-user / team locking beyond E1 (fingerprint fail-closed).
- Putting the working copy in the same sync folder “to be clever.”
- Changing the `.vltd` on-disk format (UC-25 / ADR-0007).
- Replacing UC-23 `seal` (snapshot archive remains the one-shot cloud path).
- Shipping macFUSE / Fuse-T as the only macOS mount (ADR-0010 Phase C packaging). GUI Blindfolder uses `MaterializedMount` (cleartext folder) until that packaging lands.

---

## 2. Architecture fit (Blindkey OSS)

| Layer | Responsibility |
|-------|----------------|
| `blindkey-core` | **Shipped:** hydration helpers, outer fingerprint, clonefile/`fs::copy`, atomic replace, `WorkingCopySession` + sidecar, **one** `is_under_sync_root` |
| `blindkey-fuse` / UC-25 mount | Mount/umount the **working copy only** — unchanged crypto |
| `blindkey-cli` | **Shipped:** `volume checkout` / `checkin` / `work-status` / `work-discard`; C73 refuse on `mount` of sync roots |
| `blindkey-gui` | **Shipped:** Open Blindfolder → checkout → unlock work copy into a cleartext folder (`MaterializedMount`); Eject → import + checkin; E2 resume; E9 refuse |
| Sync client | Uploads the **closed** brick after checkin — outside Blindkey |

**Crypto boundary:** no new AEAD / Merkle / Kcom. Outer fingerprint hashes the **host file**
(logical bytes). Inner Merkle does **not** replace it (research §4.2.1).

### 2.1 Current implementation baseline (2026-09-06 · impl↔spec audit)

**Shipped (core + CLI + GUI Blindfolder + folder mount).** Live facts:

| Fact | Evidence | Spec implication |
|------|----------|------------------|
| `WorkingCopySession` + sidecar | `volume/working_copy.rs` | C99–C101 |
| `MaterializedMount` cleartext folder | `volume/materialize.rs` + GUI | Main scenario steps 7–10 without Fuse |
| CLI `checkout [--mount]` / `checkin` / `work-*` | `blindkey-cli` + `volume_work_cli.rs` | W1–W2 |
| GUI Open Blindfolder + Eject checkin + resume | `volume_gui.rs` | W3 |
| macOS dataless / `mdls` ubiquitous / backup-exclude / coordinated replace | `blindkey-sys` `fs_macos` | W4 |
| Linux FICLONE / SEEK_HOLE | `blindkey-sys` `fs_linux` | hole-preserving |
| Exit codes 10–13 | `main.rs` | E1/E5/E6/E8 |

Markers alone still do **not** answer hydration. UC-30 adds the probe on top of the unified detector.

---

## 3. Actors and main success scenario

| Role | Who |
|------|-----|
| Operator | One human, one session at a time |
| Blindkey | CLI and/or desktop GUI |
| Sync client | Dropbox / Drive / iCloud / Syncthing / OneDrive (or equivalent). Not a Blindkey service. |

**Preconditions**

1. A UC-25 `.vltd` exists (created locally or already in the sync folder).
2. Live mount **or** Blindfolder cleartext folder (`MaterializedMount`) is available for the **working copy** (Linux FUSE optional; macOS uses MaterializedMount until ADR-0010 Fuse packaging).
3. The sync-folder file is fully hydrated before checkout (E5).

### 3.1 Main success scenario

1. Operator chooses a `.vltd` under a detectable sync root (or an explicit “cloud brick” path).
2. Blindkey **refuses** `volume mount` on that path (C73) and offers **checkout** (CLI) / Open Blindfolder (GUI) and Seal.
3. Operator runs **checkout** (CLI: `blindkey volume checkout`; GUI: Open Blindfolder).
4. Blindkey runs **hydration + idle probe** (§7). Fail closed on stub / stale / mid-sync.
5. Blindkey copies the brick to a local working path that is **not** under a sync root
   (platform **data** dir — §5). Prefer hole-preserving copy (`clonefile` / `cp -c` on macOS;
   Linux `FICLONE` → `SEEK_HOLE` → `fs::copy`).
6. Blindkey records a **fingerprint** of the sync-folder brick (§8) and writes sidecar
   `phase=copied`.
7. Operator unlocks the **working copy**. GUI opens a cleartext folder via `MaterializedMount`
   (same residual class as FUSE). CLI may `volume mount` the work path (Linux `volume-mount`)
   or pass `checkout --mount`. Sidecar `phase=mounted`.
8. Operator reads and writes files. All writes hit the working copy / cleartext folder only.
9. Operator ejects / quits Blindkey (or umounts).
10. Blindkey closes the folder (import + sync + shred) or unmounts, zeroizes keys (C72).
    Sidecar `phase=unmounted`.
11. Blindkey **checkin** (GUI Eject chains this; CLI: `volume checkin`). Re-hashes the sync-folder
    brick. If the fingerprint **matches** checkout, atomic replace (write-temp + rename).
12. Blindkey deletes or shreds the working copy (best-effort) and removes the sidecar.
    Sync client now uploads a **closed** brick.

### 3.2 Extensions and exceptions

| ID | Condition | Behavior |
|----|-----------|----------|
| E1 | Sync-folder brick changed since checkout (fingerprint mismatch) | **Fail closed** on checkin. Do not overwrite. Tell the operator both paths; no silent last-write-wins. |
| E2 | Crash after writes, before checkin | Working copy + sidecar remain under data dir. Next launch offers **Resume checkin** or discard. Do not leave a half-written sync-folder file. |
| E3 | Crash during checkin | Temp file on the sync path may exist; the previous brick must remain until rename succeeds. Retry rename if fingerprint still matches; if brick already equals work hash, delete tmp (idempotent). |
| E4 | Two machines checkout the same brick | Last successful checkin that still matches its fingerprint wins; the other hits E1. No multi-writer merge (UC-07 / SC3 class). |
| E5 | Cloud-only / not fully hydrated / stale ubiquitous download | Checkout fails closed with a clear error. |
| E6 | Working-copy path is itself a sync root | Checkout fails closed. |
| E7 | Operator uses `volume mount` on the sync path | Still refused (C73) unless CLI `--force-local` (unsupported escape hatch — warn only). Offer checkout (this UC) and Seal (UC-23). GUI has **no** force override. |
| E8 | Rename / coordinator replace fails | Fail closed; keep work + sidecar; **never** truncate-in-place. Optional fallback: temp outside sync root then replace (KeePassXC-class); if that also fails → stop. |
| E9 | iCloud unresolved `NSFileVersion` conflicts | GUI refuse checkin/checkout of that path until the operator resolves in Finder. Do not auto-`resolved=true`. |
| E10 | Syncthing temp sibling (`.syncthing.*` / `~syncthing~*`) present | Refuse checkout/checkin (mid-sync). |

---

## 4. Prior art (implementation lessons)

Distilled from research; load-bearing sources cited there.

| Source | Lesson for Blindkey |
|--------|---------------------|
| Dropbox conflict help | Move file **out** while editing — UC-30 productizes that; do not pause Dropbox |
| KeePassXC safe saves | Sibling temp + atomic move; no lockfile in sync folder |
| KeePassXC / Qt rename failures | Detected-failure fallback; never default to truncate |
| KeePass 2.x multiuser | Loaded-vs-disk check — UC-30 uses **full outer hash**, not mtime; no entry merge |
| Apple ubiquitous status | `current` eligible; `downloaded` = **stale** → refuse; `notDownloaded` → refuse |
| Apple `NSFileCoordinator` | Coordinated **read** hydrates — never use as a hydration *probe* (R14) |
| Syncthing | Blocks + `sync-conflict` sibling; 10 s watcher delay; temp name prefixes reserved |
| VeraCrypt community | Dismount before sync; one machine at a time |
| Oakley / APFS | Prefer `clonefile` out of sync folder; iCloud eviction can explode sparse bricks (UX honesty) |

---

## 5. Working-copy layout & sidecar

### 5.1 Directory contract

Reuse the **same platform data root** as UC-25 volume anchors / vault rollback
(`rollback::data_dir()` → `…/blindkey/`). Do not invent a second app leaf.

| Platform | Working copy + sidecar home | Avoid |
|----------|-----------------------------|--------|
| macOS | `~/Library/Application Support/blindkey/volumes/work/<id>/` | Documents, Desktop, iCloud Desktop & Documents, `/tmp`, Downloads, Caches |
| Linux | `$XDG_DATA_HOME/blindkey/volumes/work/<id>/` (default `~/.local/share/blindkey/…`) | `$XDG_RUNTIME_DIR`, `$XDG_CACHE_HOME` |
| Windows (when mount exists) | `%LOCALAPPDATA%\blindkey\volumes\work\<id>\` | OneDrive-known folders, `%TEMP%` as sole home |

`<id>` = opaque session id (UUID). Sibling on disk: `…/blindkey/volume-anchors/<hex>/`
(C70). Research preferred `$XDG_STATE_HOME` for “open files”; Blindkey already ships
anchors under **data** dir — one tree beats two. Still **not** cache.

After creating the directory, resolve **realpath** and run the sync-root detector. If the
operator relocated Application Support / data dir into Dropbox → **E6**.

On macOS, set `NSURLIsExcludedFromBackupKey` on work files **each time they are written**
(Apple: common ops reset the flag). Do **not** set this on the operator’s sync-folder brick.

### 5.2 Files inside `<id>/`

```text
volumes/work/<id>/
  brick.vltd          # working copy (ciphertext; UC-25 format)
  state.json          # sidecar — not secret
```

### 5.3 Sidecar schema (`state.json`)

```json
{
  "version": 1,
  "source_path": "/path/to/sync/folder/workspace.vltd",
  "source_fingerprint": {
    "size": 0,
    "sha256": "…",
    "dev": 0,
    "ino": 0,
    "magic_ok": true
  },
  "work_path": "…/brick.vltd",
  "phase": "copied | mounted | unmounted | checkin",
  "pid": 0,
  "created_at": "RFC3339"
}
```

**Rules (research §6):**

- Phase `mounted` + pid dead → crash path: unmount if needed; offer resume checkin or discard.
- Phase `checkin` + tmp present + fingerprint still matches → retry rename.
- Phase `checkin` + fingerprint differs → E1; do not overwrite.
- **Never** write this JSON into the sync folder.
- Pid is advisory after reboot; fingerprint + phase are authoritative.
- Sidecar holds paths + hashes only — not keys. Zeroize volume keys on crash path (C72).

---

## 6. `blindkey-core` API (contract)

Illustrative signatures — **the contract**, not final names. Mount still goes through UC-25
`Volume` + fuse adapter.

```rust
/// Uniform failure string for hostile / stub sources (no format oracle).
pub const WORKING_COPY_ERROR: &str = "volume working copy could not be prepared";

#[derive(Clone, Debug)]
pub struct OuterFingerprint {
    pub size: u64,
    pub sha256: [u8; 32],
    pub dev: u64,
    pub ino: u64,
    pub magic_ok: bool,
}

#[derive(Clone, Debug)]
pub enum WorkPhase {
    Copied,
    Mounted,
    Unmounted,
    Checkin,
}

pub struct CheckoutOpts<'a> {
    pub source: &'a Path,           // sync-folder .vltd
    pub work_root: Option<&'a Path>, // default: platform data dir (…/blindkey/)
    pub cancel: Option<&'a AtomicBool>,
    pub progress: Option<&'a mut dyn FnMut(u64, u64)>,
}

pub struct WorkingCopySession {
    pub id: String,
    pub source_path: PathBuf,
    pub work_path: PathBuf,
    pub fingerprint: OuterFingerprint,
    pub phase: WorkPhase,
}

impl WorkingCopySession {
    /// Hydration + idle probe → hole-preserving copy → fingerprint → sidecar.
    /// Does NOT mount. Does NOT open UC-25 crypto.
    pub fn checkout(opts: CheckoutOpts<'_>) -> Result<Self>;

    /// Load sidecar after crash / relaunch.
    pub fn resume(work_id: &str) -> Result<Self>;

    /// Record phase transitions; write sidecar.
    pub fn set_phase(&mut self, phase: WorkPhase) -> Result<()>;

    /// C101: re-hash source; Err if mismatch.
    pub fn assert_source_unchanged(&self) -> Result<()>;

    /// C100: sibling tmp + fsync + rename onto source_path.
    /// Caller MUST have unmounted and synced the Volume first.
    pub fn checkin(self) -> Result<()>;

    /// Discard work file + sidecar without writing sync path.
    pub fn discard(self) -> Result<()>;
}

/// Shared with CLI/GUI C73 path — **single** implementation in core (W0).
/// Union of today’s CLI + GUI markers; include CloudStorage + Syncthing.
pub fn is_under_sync_root(path: &Path) -> bool;

/// Platform hydration probe — fail closed on stub/stale (E5).
pub fn assert_hydrated_for_checkout(path: &Path) -> Result<()>;

/// Outer logical SHA-256 (holes = zeros). See §8.
pub fn hash_outer_logical(path: &Path) -> Result<OuterFingerprint>;
```

**Rules:**

- `checkout` must call `assert_hydrated_for_checkout` **before** any content `open` that
  could force a download (R1, R14).
- Prefer `clonefile` (same APFS volume, hydrated) → else `FICLONE` / `SEEK_DATA`+`SEEK_HOLE`
  → last resort full logical copy (document blow-up).
- Never `clonefile` a dataless / placeholder file.
- Checkin temp name: `<stem>.<rand>.bk-checkin.tmp` — **must not** use `.syncthing.` or
  `~syncthing~` prefixes.
- On rename failure → E8; no truncate-in-place.

### 6.1 Platform replace split (research §3.5)

| Surface | Replace path |
|---------|----------------|
| GUI / app on macOS | Sibling-tmp + `NSFileCoordinator` writing with `ForReplacing` (`blindkey-sys::coordinated_replace`). POSIX rename is the fallback if the coordinator fails. |
| `blindkey` CLI on macOS | POSIX sibling-tmp + `rename` same directory; `EXDEV`/`EPERM` → E8 fallback |
| Linux CLI / GUI | POSIX `rename` after `fsync` of temp |
| Blindfolder folder open | `MaterializedMount` cleartext folder by default; Linux FUSE with `volume-mount`; optional macOS FUSE with user macFUSE + `macos-fuse`. kill-9 leftover `mnt/` is adopted on unlock (`open_or_adopt`), never wiped. |

Coordinator (when packaged) reduces File Provider races; it is **not** a substitute for C101.

---

## 7. Hydration & idle probe

### 7.1 Order of operations (normative)

1. Resolve path; confirm regular file; magic/`VLTD` only **after** stub checks where open
   would hydrate.
2. Sync-root marker check (unified core list after W0 — §2.1) — UX + C73; not hydration.
3. **Hydration** (platform table below).
4. No Syncthing / vendor temp siblings (E10).
5. **Idle probe:** two `stat` samples **≥ 1 s** apart with same `size`, `mtime`, `ino`.
   If mismatch twice within a finite timeout (CLI default **30 s**) → fail closed
   (“wait until the client finishes”). Do **not** treat 250 ms as synced (R11).
6. Then outer hash (§8).

### 7.2 Platform hydration table

| Platform / client | Eligible | Refuse |
|-------------------|----------|--------|
| macOS iCloud / File Provider | `ubiquitousItemDownloadingStatus == current` | `downloaded` (stale), `notDownloaded`, `SF_DATALESS` without current |
| Google Drive Stream | Hydrated / Available offline | Placeholder / not offline |
| Google Drive Mirror | Local copy present | Missing file |
| Windows CfAPI | Fully present on disk | `RECALL_*` / `PARTIALLY_ON_DISK` as sole state |
| Linux Syncthing / generic | Regular file; not mid-temp; not `st_blocks==0` with large `st_size` | Temp siblings; header-less stub |

**Do not** use “allocated ≪ logical” alone as a stub signal — that is also a hydrated
sparse `.vltd` (R13). **Do not** use coordinated read / content `open` as a hydration probe
on Apple (R14).

---

## 8. Outer fingerprint (C101)

### 8.1 Fields

| Field | Role |
|-------|------|
| `size` | Cheap reject |
| SHA-256 of **logical** file bytes (holes = zeros) | Detect any bit change |
| `dev` + `ino` at checkout | Detect replaced inode / conflicted sibling left beside |
| Header magic OK | Cheap reject of wrong type |

✗ mtime-only. ✗ Inner Merkle alone. ✗ Hash-while-downloading. ✗ Hash only allocated extents.

### 8.2 When to hash

1. After hydration + idle probe.
2. During/after copy: hash what was written to the working copy; re-stat source; if
   size/`ino` changed during copy → abort and delete partial work.
3. **At checkin:** full re-hash of the sync-folder brick; compare to checkout record.
   Mismatch → E1.

Streaming SHA-256 while copying is allowed; **checkin** must still re-read the sync path.

---

## 9. Atomic checkin (C100)

```
assert unmounted + Volume.sync done
assert_source_unchanged()          # C101
phase = checkin
write sibling temp in same dir
fsync temp
rename temp → source_path           # or NSFileCoordinator.forReplacing (GUI macOS)
fsync directory (best-effort)
verify source hash == work hash (optional idempotent)
delete work + sidecar
```

**Forbidden:** truncate-in-place of the sync brick; lockfiles next to the sync brick;
marketing “fully synced to all devices” after rename returns.

**Honesty (C102):** checkin means the **local** sync folder has a closed brick. Provider
upload class (iCloud full object, Dropbox ≤4 MiB blocks, Syncthing blocks, Drive differential
parts) is not a Blindkey feature. iCloud eviction may explode sparse bricks to full logical
size (R17) — document, do not refuse iCloud.

---

## 10. CLI surface (clap)

```
blindkey volume checkout PATH.vltd [--work-dir DIR]
blindkey volume checkin  [PATH.vltd|WORK_ID]     # default: active session
blindkey volume work-status [WORK_ID]            # not `volume status` (that is UC-25 metadata)
blindkey volume work-discard WORK_ID
blindkey volume mount PATH.vltd MOUNTPOINT [--force-local]   # existing; C73
```

**Behavior notes:**

- `checkout` may optionally chain to mount when a TTY unlock is available; or leave mount
  as a separate step. GUI always chains for Blindfolder UX.
- On launch, if any `volumes/work/*/state.json` has `phase` in `{mounted, unmounted, checkin}`
  with dead pid → print resume/discard prompt (non-interactive: exit non-zero with path).
- Passwords: TTY / `--password-fd` / `--password-stdin` / `BLINDKEY_PASSWORD_FILE` only (C31).
- Exit codes: extend UC-04/G0.8 table — distinct codes for E1 fingerprint mismatch, E5
  hydration, E6 sync-root work path, E8 rename failure.
- **C73 refuse copy:** names `volume checkout` / Blindfolder **and** `blindkey seal`.
  Keep `--force-local` as an explicit unsupported override with stderr warning
  (do not add a GUI equivalent).

---

## 11. Desktop GUI (`blindkey-gui`)

Thin shell over core (UC-18). No crypto reimplementation.

| Action | Behavior |
|--------|----------|
| Open Blindfolder on sync-path `.vltd` | Checkout → unlock → mount working copy; residual-risk banner (UC-25) |
| Open / Mount on **non-sync** `.vltd` | Existing UC-25 mount (unchanged) |
| Eject | Umount → checkin → clear work; on E1 show both paths |
| Resume dialog | On launch with orphan sidecar: Resume checkin / Discard / Reveal in Finder |
| Cloud folder + Mount attempted | Refuse (C73); offer **Open Blindfolder** (checkout) and **Seal**. No GUI `--force-local`. |
| iCloud unresolved conflicts | Refuse with Finder-resolution message (E9) |
| Progress | Worker thread + cancel; `request_repaint` (UC-20) |

**Falsifiable claims**

**Allowed:** checkout never mounts the sync-folder path; checkin refuses changed remotes;
atomic replace leaves prior brick until rename succeeds.

**Forbidden marketing:** live synced mounted vault; “stronger than Cryptomator because
single file”; Blindkey delta sync; “pause Dropbox for you”; immune to two-writer races
beyond fail-closed.

---

## 12. Constraint mapping

| ID | Requirement | Implementation hook |
|----|-------------|---------------------|
| C99 | Checkout mounts only local non-sync copy; fail if not hydrated / work is sync root | `WorkingCopySession::checkout`; `assert_hydrated_*`; sync-root on work realpath |
| C100 | Checkin = temp + rename; no truncate-in-place | `checkin`; E8 fallback |
| C101 | Fingerprint at checkout; mismatch → no overwrite | `OuterFingerprint`; `assert_source_unchanged` |
| C102 | Docs/CLI/GUI do not market live sync-path mount; C73 stays green | refuse paths; PRD/THREAT_MODEL wording; `c102_*` |
| C73 | No live mount of sync-path `.vltd` | existing CLI/GUI refuse; W1/W3 checkout CTAs; `--force-local` remains unsupported escape (CLI) |
| C72 | Zeroize on umount / crash path | UC-25 `Volume::close` before checkin |
| C67–C71, C74 | Volume format / hostile parse | UC-25 unchanged |

**Satisfiability (intent SC):** C73 ∧ C99 — different paths: refuse mount of sync path;
checkout copies closed file to non-sync path and mounts **that**.

---

## 13. Test plan

| Suite | Location (planned) | Covers |
|-------|--------------------|--------|
| Outer hash holes = zeros | `blindkey-core` unit | R15 / C101 |
| Hole-preserving copy / clone | `working_copy::tests::hole_preserving_copy_roundtrips_bytes` | C99 / R4 |
| Atomic replace + no truncate | `c100_*` | C100 |
| Fingerprint mismatch refuse | `c101_*` | C101 / E1 |
| Sync-root work path refuse | `c99_*` + CLI exit 12 | C99 / E6 |
| Hydration stubs | `e5_hydration_refuses_*` + CLI exit 11 | E5 / R2 |
| Idle probe ≥1s | `idle_probe_passes_on_stable_file` | §7.1 |
| E8 fallback + fail-closed | `e8_fallback_replace_*` + CLI exit 13 | E8 |
| Sidecar resume / discard | `work_session` tests | E2 / E3 |
| Joint satisfaction | `tests/uc30_joint_satisfaction.rs` | C99–C102 one fixture: mutate remote → checkin refuses |
| CLI | `blindkey-cli/tests/volume_work_cli.rs` | verbs, C73 hint, exits 10–13 |
| GUI | `uc30_constraints.rs` | Blindfolder CTA, resume dialog strings |
| C73 regression | existing refuse tests | C102 |

**Joint (IVD):** checkout fixture → mutate sync-folder bytes → checkin fails; sync path still
equals pre-checkin fingerprint; work retained for discard/resume.

**Provenance note:** C99–C102 tests are `execution_derived` (intent v1.9.8) via
`uc30_constraints.rs` + `uc30_joint_satisfaction.rs`.

---

## 14. Rollout (phased)

| Phase | Deliverables | Gate |
|-------|--------------|------|
| **Spec** | UC **Accepted v0.3** + research closed + ADR-0011 Accepted | ✓ |
| **Accept** | Maintainer accept | ✓ |
| **W0** | Unify `is_under_sync_root` + `WorkingCopySession` + fingerprint + POSIX checkin + sidecar | ✓ |
| **W1** | CLI `checkout` / `checkin` / resume; C73 refuse text names checkout **and** seal | ✓ |
| **W2** | Wire checkout → UC-25 mount (`--mount` / operator mount of work path) | ✓ |
| **W3** | GUI Blindfolder + resume dialog | ✓ |
| **W4** | macOS hydration (SF_DATALESS / ubiquitous probe) + exclude-from-backup + coordinated replace path + E8 fallback | ✓ (portable + macOS helpers in `blindkey-sys`; live Finder FUSE still ADR-0010) |
| **W5** | Docs: CLI.md, CONSTRAINT_INDEX, ROADMAP S-29 | ✓ |

**macOS Blindfolder UX:** ships via `MaterializedMount` (cleartext working folder). Optional
user-installed macFUSE + `--features macos-fuse` is additive (ADR-0010) — **not** a hard
gate for Blindfolder. Linux FUSE remains optional `volume-mount`.

---

## 15. Open questions

| Item | Status |
|------|--------|
| Checkout vs live mount | ✓ closed — ADR-0011 / C73 |
| Pause Dropbox | ✓ closed — do not |
| Outer vs inner hash | ✓ closed — outer logical SHA-256 |
| Google conflict filename grammar | ✓ closed — none official; fingerprint only |
| Google upload class | ✓ closed — desktop differential for large edits; not Blindkey delta |
| Exact allocated/logical stub cutoff | ✓ closed — use status/CfAPI/`SF_DATALESS`, not a ratio |
| macOS mount provider | Deferred to ADR-0010 (build), not this UC |
| Exact CLI flag names | Soft — may move in implementation; copy/never-mount-sync-path may not |
| `--force-local` retention | ✓ keep as CLI unsupported override; never default; never GUI |
| CLI vs GUI sync-marker lists | ✓ closed as debt — unify in core at W0 (union + CloudStorage + Syncthing) |
| Work dir vs XDG_STATE_HOME | ✓ closed — reuse `rollback` data_dir `…/blindkey/` (same as volume-anchors) |
| Windows CfAPI detail matrix | When Windows mount exists — extend §7.2 |

---

## 16. Relationship to UC-23 / UC-25

| | UC-23 Seal | UC-25 Volume | UC-30 Working copy |
|---|------------|--------------|--------------------|
| Artifact | `.vltf` archive | `.vltd` live volume | Same `.vltd`, moved |
| Cloud story | Snapshot upload | Local mount only | Repeatable workspace in sync folder |
| Mount sync path | N/A | Forbidden (C73) | Forbidden; checkout instead |
| Multi-writer | N/A | N/A | Fail-closed (E1) |

---

## 17. Docs updates when shipping

- [x] `docs/CLI.md` — `checkout` / `checkin` / resume
- [x] `docs/THREAT_MODEL.md` — two-writer + sync-client residual; honesty on upload class
- [x] `docs/PRD.md` §5 UC-30 — aligned with this contract
- [x] `ROADMAP.md` S-29 — W0–W4
- [x] UC-25 §6 cloud policy — Seal + checkout CTAs
- [x] Public README Blindfolder blurb — no live-mount-of-sync-path claim

---

## 18. Requirements ↔ tech spec traceability

| Requirement | Spec section |
|-------------|--------------|
| C99 checkout copy + non-sync mount | §1, §5, §6, §7, §12 |
| C100 atomic replace | §6.1, §9, §12 |
| C101 fingerprint refuse | §8, §3.2 E1, §12 |
| C102 / C73 wording | §1.1, §9 honesty, §11, §17 |
| Crash resume | §5.3, §3.2 E2–E3 |
| Hydration | §7 |
| Hole-preserving copy | §5, §6 |
| Research R1–R17 | §4, §7–§9, §15 |

---

## 19. Cross-check log

| Date | Check | Result |
|------|-------|--------|
| 2026-09-06 | Draft v0.1 scenario + C99–C102 stubs | Landed with ADR-0011 / intent v1.9.7 |
| 2026-09-06 | Research R1–R17 + Google blockers closed | Fed into Draft v0.2 |
| 2026-09-06 | Draft v0.2 vs UC-25 depth (API, layout, tests, rollout) | Landed |
| 2026-09-06 | Cross-check vs research + live CLI/GUI/core | Fixed: data_dir work path; marker divergence; `--force-local`; unlock channels; `work-status` |
| 2026-09-06 | Design package Accept | **PASS** — Accepted v0.3 |
| 2026-09-06 | Core + CLI ship (W0–W1) | `WorkingCopySession` + CLI verbs + `uc30_*` tests |
| 2026-09-06 | **Full implement W2–W4** | CLI `--mount`; exit 10–13; orphan warn; GUI Blindfolder+resume+E9; Linux FICLONE/SEEK_HOLE; macOS backup-exclude + dataless + coordinated replace; E8 out-of-tree fallback; cancel/progress opts |
| 2026-09-06 | **Residual complete** | Real `NSFileCoordinator` (objc2); kill-9 `open_or_adopt`; Drive xattr/sibling probes; Linux GUI `volume-mount` FUSE; Blindfolder lifecycle test |
| 2026-09-07 | **Impl↔spec gap close** | Docs drift fixed (§10/§11/§14/§19); `magic_ok` persisted from probe; idle/E5/hole-copy/E8/CLI exit 11–13 tests |

### 19.1 Implementation ↔ contract matrix (2026-09-07 · gap close)

| Contract item | Status | Evidence / note |
|---------------|--------|-----------------|
| C99–C102 | **PASS** | `uc30_*` + joint + `volume_work_cli` |
| Auto mount after checkout | **PASS** | CLI `--mount`; GUI `MaterializedMount` on unlock; quit→eject |
| E2 resume | **PASS** | CLI orphan warn; GUI Resume; includes `Copied` orphans |
| E3 / E8 / E10 | **PASS** | idempotent + out-of-tree fallback + Syncthing temps |
| E5 hydration | **PASS** | portable + macOS dataless/`mdls`; Windows CfAPI recall/offline; Drive placeholder siblings |
| E9 conflicts | **PASS** | `WorkingCopyUnresolvedConflicts` + Finder UX |
| Hole-preserving copy | **PASS** | macOS `cp -c`; Linux FICLONE→SEEK_HOLE→`fs::copy` |
| Exclude from backup | **PASS** (macOS) | on copy + each `set_phase` / checkin sidecar write |
| Coordinated replace | **PASS** | GUI macOS: real `NSFileCoordinator` `ForReplacing` (`fs_macos.rs`); CLI/Linux: POSIX rename; E8 out-of-tree fallback |
| Distinct exit codes | **PASS** | 10=E1, 11=E5, 12=E6, 13=E8 |
| `phase=mounted\|unmounted` | **PASS** | CLI + GUI; checkin refuses `Mounted` / leftover `mnt` |
| C101 `dev`/`ino` | **PASS** | compared in `assert_source_unchanged` |
| Materialize close-fail | **PASS** | returns mount intact; no shred without sync |

**Verdict:** UC-30 Blindfolder **PASS** — docs aligned with live `NSFileCoordinator` + `MaterializedMount`; residual tests for idle/E5/hole-copy/E8/CLI exits 10–13 green. Default macOS UX remains `MaterializedMount`; optional `--features macos-fuse` + user macFUSE.

---

## 20. Acceptance (PASS — core/CLI)

| ID | Must be true | Test |
|----|----------------|------|
| C99 | Checkout copies to a non-sync path; mount is only of that copy | `c99_*` PASS (mount = operator `volume mount` on work path) |
| C100 | Checkin is write-temp + rename; no truncate-in-place of the sync brick | `c100_*` PASS |
| C101 | Fingerprint mismatch → no overwrite | `c101_*` + joint PASS |
| C102 | `volume mount` on a sync root still refused; docs do not market live sync | `c102_*` + CLI refuse PASS |

Joint: one fixture where a mutated remote brick cannot be overwritten by checkin
(`uc30_joint_satisfaction.rs`) — PASS.
