# Volume working copy (checkout / checkin) — Research

> **Task:** Implementation-grade survey — how to copy a single encrypted container out of an
> untrusted sync folder, mount the **copy**, then write it back — without mounting the
> sync-folder path. Scope is **provider-agnostic**: Dropbox, iCloud Drive, Google Drive,
> OneDrive, Syncthing, and equivalents are examples of the same class (desktop sync / File
> Provider), not product integrations.
>
> Feeds [UC-30](../docs/specs/UC-30-volume-working-copy.md) (C99–C102; Draft v0.2 full
> contract) and
> [ADR-0011](../docs/adr/0011-volume-working-copy-checkout.md). Does **not** redo volume
> crypto or live-mount architecture — those live in
> [`encrypted_volume_mount_research.md`](encrypted_volume_mount_research.md) and
> [`encrypted_volume_maximum_security_research.md`](encrypted_volume_maximum_security_research.md).
> Cloud *seal vs overlay* survey:
> [`encrypted_cloud_storage_research.md`](encrypted_cloud_storage_research.md).
>
> Research date: **2026-09-06** (expanded + source-audit + second expansion same
> day). **Final source validation:** 2026-09-06 — Dropbox help/API, Syncthing RST,
> Apple status + coordinator + backup-exclude, CfAPI, Google Drive File Provider,
> KeePassXC `Database.cpp`, Oakley 2024/2025, UC-25 §4. Markers: ✓ verified ·
> ~ inferred · ? unverified (do not treat as load-bearing).
>
> **Public wording:** sync folder, working copy, checkin, brick / container file.
> No operator paths, personal notebooks, or private-repo names.

---

## 0. Executive finding

The **decision** (checkout, do not live-mount the sync path) is already settled (C73,
ADR-0011). The **gap** was how that loop survives real desktop sync clients.

**ONE recommended implementation posture:**

1. **Probe metadata first** — never `open()` / `read()` a candidate until hydration
   checks pass. Opening a File Provider placeholder **downloads** it.
2. **Copy into a local state directory** that is not a sync root. Preserve
   **sparse holes** (`clonefile` / `FICLONE` / `SEEK_HOLE` when the source is
   hydrated). Never clone a placeholder. Never sequential-read a sparse brick
   as if it were dense.
3. **Fingerprint** = size + cryptographic hash of the **closed** file bytes (not mtime
   alone). Re-check immediately before replace.
4. **Checkin** = write a sibling temp file → `fsync` → `rename` onto the brick.
   On Apple File Provider / iCloud paths, wrap the replace in `NSFileCoordinator`
   (`.forReplacing`). If the client cannot rename (KeePassXC / Qt documented this),
   fail closed or use their documented “temp file then move” fallback — never
   truncate-in-place.
5. **Sidecar lives next to the working copy**, never in the sync folder. Lockfiles
   in the sync folder spawn conflict copies and do not serialize two machines.

Dropbox’s own help text for avoiding conflicted copies is the same shape as UC-30:
move the file **out** of the sync folder while working, then move it back.
✓ [help.dropbox.com/organize/conflicted-copy](https://help.dropbox.com/organize/conflicted-copy)
(updated 2025-05-15).

---

## 1. Scope

| In | Out |
|----|-----|
| Hydration / placeholder detection | Volume AEAD / Merkle (already researched) |
| Atomic replace onto a sync-watched path | macOS FUSE provider matrix (ADR-0010) |
| Fingerprint races | Pausing or scripting the sync app |
| Working-copy directory + copy vs clone | Hosted Blindkey sync |
| Crash / resume sidecar | Per-file overlay vaults (Cryptomator class) |
| Two-writer + vendor conflict copies | Team merge of brick contents |

A **brick** here is one opaque container file (Blindkey `.vltd`). The same mechanics
apply to any large single-file ciphertext a sync client will upload as one object.

---

## 2. Hydration — is the file actually on disk?

Sync clients present a Finder/Explorer name and a **logical** size while the bytes
live in the cloud. Copying that stub produces a useless or corrupt working copy
(UC-30 E5).

### 2.1 macOS — iCloud / File Provider

✓ Apple: `URLResourceKey.ubiquitousItemDownloadingStatusKey` reports whether a local
copy exists and whether it is current.
[developer.apple.com — ubiquitousItemDownloadingStatusKey](https://developer.apple.com/documentation/foundation/urlresourcekey/ubiquitousitemdownloadingstatuskey)

Documented status values
([`URLUbiquitousItemDownloadingStatus`](https://developer.apple.com/documentation/foundation/urlubiquitousitemdownloadingstatus)):

| Status | Apple’s meaning (verbatim class) | Checkout |
|--------|----------------------------------|----------|
| `current` | “A local copy of this item exists and is the most up-to-date version known to the device.” | **Eligible** (still re-hash). |
| `downloaded` | “A local copy of this item exists, but it is **stale**. The most recent version will be downloaded as soon as possible.” | **Refuse** (E5 / C101 class). |
| `notDownloaded` | Item has not been downloaded yet. | **Refuse.** |

Cite the enum pages, not a paraphrase: [current](https://developer.apple.com/documentation/foundation/urlubiquitousitemdownloadingstatus/current),
[downloaded](https://developer.apple.com/documentation/foundation/urlubiquitousitemdownloadingstatus/downloaded),
[notDownloaded](https://developer.apple.com/documentation/foundation/urlubiquitousitemdownloadingstatus/notdownloaded).
Apple’s HTML is JS-gated; the `downloaded` = stale wording is also quoted on
Apple Forums (FB17662379) as `NSMetadataUbiquitousItemDownloadingStatusDownloaded`.

✓ Practitioner confirmation (Sonoma+): evicted iCloud files keep the **full logical
size** in Finder/`stat`; the tell is downloading status, not `st_size == 0`.
Howard Oakley, *Dataless files arrive* (2023-10-29),
[eclecticlight.co](https://eclecticlight.co/2023/10/29/last-week-on-my-mac-dataless-files-arrive/)
— uses the same `ubiquitousItemDownloadingStatus` key; notes `SF_DATALESS` on
`stat.st_flags` as a second signal (`stat`/`getattrlist`).

✓ Google Drive for desktop on macOS 12.1+ **streams** via File Provider
(“folder location is controlled by macOS”).
[support.google.com/drive/answer/12178485](https://support.google.com/drive/answer/12178485)

✓ Google Drive for desktop has two My Drive modes
([support.google.com/drive/answer/13401938](https://support.google.com/drive/answer/13401938)):

| Mode | Local bytes | Checkout implication |
|------|-------------|----------------------|
| **Stream** | Cloud-primary; local when opened, marked Available offline, or cached. | Treat like File Provider placeholders until hydrated. Refuse unless status/offline says present. Opening to probe **downloads** (File Provider often requires full download before examine — [answer/12178485](https://support.google.com/drive/answer/12178485)). |
| **Mirror** | Full local + cloud copy of My Drive. Always offline. | Size-on-disk / magic checks still apply. |

✓ Stream vs Mirror overview:
[support.google.com/drive/answer/13401938](https://support.google.com/drive/answer/13401938).
Shared Drives are **stream-only**. Path under `~/Library/CloudStorage/` +
size > 0 ≠ hydrated.

~ File Provider vs legacy streaming (same Google page): **already downloaded**
files under File Provider can remain accessible when Drive for desktop is
**not** running; legacy streaming required the app. Do not hard-code “app must
be running” as the hydration gate — use presence/offline/status signals.

~ Nextcloud’s third-party File Provider diagnostic (`ncstatus`) states the same
operational rule: **never open a file to inspect it** — opening a placeholder
downloads it. Community README, not Apple or Nextcloud product docs.
[github.com/weiaoli2/ncstatus](https://github.com/weiaoli2/ncstatus)

✓ **Do not use `NSFileCoordinator` read as a hydration probe.** Apple:
if the file is not downloaded, `coordinate(readingItemAt:…)` **blocks**
(potentially a long time) while it downloads, or fails.
[coordinate(readingItemAt:…)](https://developer.apple.com/documentation/foundation/nsfilecoordinator/coordinate(readingitemat:options:error:byaccessor:))
Same warning in *Designing for Documents in iCloud*:
“Reading a file that has not been downloaded can take a long time, because
the coordinated read operation blocks until the file finishes downloading.”
[library archive](https://developer.apple.com/library/archive/documentation/General/Conceptual/iCloudDesignGuide/Chapters/DesigningForDocumentsIniCloud.html)
Check status keys first. Coordinated read is for **already-hydrated** fingerprint
at checkin, not for “is this a stub?”

**Checkout rule (macOS):** read resource values / `getattrlist` **before** any
content `open` **and** before any coordinated read. If status is missing (not
an iCloud item) fall through to magic + size-on-disk checks. If
`notDownloaded` or `downloaded` (stale) → fail closed with a “make available
offline / wait for download” message. Do not auto-hydrate in v1 (that is a
network side effect the operator did not ask for).

#### 2.1.1 Do not trust `st_size` — use allocated size + download keys

✓ Oakley (2023): evicted iCloud files keep the **full logical size**. `stat.st_size`
is the cloud object size, not “bytes on this disk.”

✓ Apple `URLResourceValues`:

| Key | Use |
|-----|-----|
| `fileSize` / `totalFileSize` | Logical / display size — **not** hydration. |
| `fileAllocatedSize` / `totalFileAllocatedSize` | Blocks × block size on this volume. Dataless ≈ metadata only. [fileAllocatedSize](https://developer.apple.com/documentation/foundation/urlresourcevalues/fileallocatedsize) |
| `ubiquitousItemIsDownloading` | Download **in flight** — refuse (moving target). |
| `ubiquitousItemPercentDownloaded` | 0–100; treat `< 100` as not ready. [iCloud metadata attrs](https://developer.apple.com/library/archive/documentation/CoreServices/Reference/MetadataAttributesRef/Articles/iCloudAttrs.html) |
| `ubiquitousItemPercentUploaded` | Upload in flight — see §3.4; checkin already happened locally. |
| `ubiquitousItemHasUnresolvedConflicts` | Another version exists — refuse checkout/checkin (E1). [NSFileVersion](https://developer.apple.com/documentation/foundation/nsfileversion) |
| `isUbiquitousItem` | If false, skip ubiquitous keys; still run allocated-size sanity. |

**v1 probe (macOS, no content open):**

1. `isUbiquitousItem` + downloading status + percent downloaded + unresolved conflicts.
2. Compare `fileAllocatedSize` to `fileSize`. A hydrated **sparse** volume can have
   allocated much smaller than logical (§5.2). Use that ratio only together with
   status / percent / `SF_DATALESS` — never as the only signal.
3. `SF_DATALESS` in `st_flags` if present → refuse.

? No numeric allocated/logical cutoff is safe. Stub = `notDownloaded` /
`SF_DATALESS` / percent downloaded `< 100` / recall bits. Sparse + `current` +
percent 100 = real holes. Do **not** refuse a hydrated sparse brick because
allocated is less than size.

### 2.2 Windows — Cloud Files / OneDrive / Drive / Dropbox

✓ Microsoft file attributes
([Win32 File Attribute Constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)):

| Attribute | Meaning |
|-----------|---------|
| `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x00400000) | Not fully present locally; **reading fetches** remote data. |
| `FILE_ATTRIBUTE_RECALL_ON_OPEN` | Virtual; **opening is expensive / fetches**. |
| `FILE_ATTRIBUTE_OFFLINE` | Data not immediately available (legacy HSM / still used). |
| `FILE_ATTRIBUTE_PINNED` / `UNPINNED` | User intent: keep local vs prefer cloud. |
| `FILE_ATTRIBUTE_SPARSE_FILE` | Sparse; **not sufficient alone** (real sparse files exist). |

✓ Official Cloud Files API (preferred when available):
`CfGetPlaceholderStateFromAttributeTag` /
`CfGetPlaceholderStateFromFileInfo` → `CF_PLACEHOLDER_STATE`.
[CF_PLACEHOLDER_STATE](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ne-cfapi-cf_placeholder_state)

| Flag | Checkout |
|------|----------|
| `NO_STATES` | Not a CfAPI placeholder — fall through to magic + size checks. |
| `PLACEHOLDER` + `PARTIALLY_ON_DISK` | Not fully local — **refuse**. |
| `PARTIAL` alone | May be on disk but not ready (e.g. verification pending) — **refuse**. |
| `PLACEHOLDER` + `IN_SYNC` without `PARTIALLY_ON_DISK` / `PARTIAL` | Eligible (still re-hash). |

✓ Kernel guidance: `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` means not fully present;
reading fetches remote data. Minifilters must not issue opportunistic reads on
that bit ([placeholders_guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/placeholders_guidance)).

~ Practitioner heuristic (when CfAPI not linked):
`(OFFLINE | RECALL_ON_DATA_ACCESS) && GetCompressedFileSize == 0` as cloud-only.
[SO 79546133](https://stackoverflow.com/questions/79546133/how-can-i-detect-sparse-download-on-demand-files-on-windows-with-python)
— corroborates constants, not an official sample.

**Checkout rule (Windows):** attributes / CfAPI state **before** `CreateFile` for
data. `RECALL_*` or `PARTIALLY_ON_DISK` / `PARTIAL` → fail closed.

### 2.3 Linux desktop clients

✓ **Dropbox Linux `filestatus` is current**, not historical. Official help
updated **2025-11-26**: `dropbox filestatus [-l] [-a] [FILE]…` (alias `stat`);
`ls` is an alias for `filestatus -l`.
[help.dropbox.com/installs/linux-commands](https://help.dropbox.com/installs/linux-commands)
**Must run from the Dropbox folder root** (`~/Dropbox` or the relocated root).
Invoking the local `dropbox` CLI is process IPC, not a Blindkey network call
(C23). Output is **not** machine-stable — do not parse as a security gate.
Optional UX only (“daemon says unsynced”).

✓ **Windows and macOS Dropbox have no supported programmatic sync-status API.**
Dropbox staff: “There isn’t any way to view the sync status of a file
programmatically” (Windows/Mac).
[community.dropbox.com discussion 201505](https://community.dropbox.com/en/discussion/201505/need-for-dos-command-to-know-if-files-are-already-synched)

~ Syncthing keeps a full local replica; placeholders are not the default model.
Hydration is “file readable + size matches.” Still require a stable fingerprint
(§4) because a peer can be mid-receive.

✓ **Syncthing mid-receive:** never writes the destination in place. Temps are
named `.syncthing.original-filename.ext.tmp` (Windows:
`~syncthing~original-filename.ext.tmp`). If that name would be too long, the
temp is `.syncthing.<sha256-of-original-name>.tmp` (Windows:
`~syncthing~<sha256>.tmp`). Prefixes `.syncthing.` and `~syncthing~` are a
reserved namespace — Syncthing **ignores/excludes** any such name.
Cite the RST, not the HTML scrape:
[docs.syncthing.net/_sources/users/syncing.rst.txt](https://docs.syncthing.net/_sources/users/syncing.rst.txt)
(rendered: [Understanding Synchronization](https://docs.syncthing.net/users/syncing.html),
v2.1). Watcher batches changes **10 s** by default (`fsWatcherDelayS`);
deleted files wait ~1 min.

**Checkout rule (Linux):**

1. Regular file, readable.
2. No sibling whose name starts with `.syncthing.` or `~syncthing~` — mid-sync
   or reserved; refuse.
3. `st_blocks == 0` && `st_size` large → refuse (header-less stub / hole).
   Do **not** treat “allocated ≪ logical” alone as a stub — that is also a
   hydrated sparse `.vltd` (R13). Syncthing replicas are usually dense.
4. After (1–3), Linux has **no** ubiquitous/File Provider API. Reading the
   first 4 KiB for `VLTD` magic is allowed **only** after those stub checks.
   A FUSE/Drive-class mount may still hydrate on `open` — if `RECALL_*`-class
   behavior is suspected, fail closed rather than open.
5. Do not require `dropbox filestatus` or Syncthing’s REST API in v1 (daemon
   may be absent; REST is a local port — still extra coupling).

### 2.4 What Blindkey already has

✓ Path-based sync-root detection for C73 exists in **two places and they disagree**:

| Surface | Matcher | Notable markers |
|---------|---------|-----------------|
| CLI `commands/volume.rs` `SYNC_ROOT_MARKERS` | Case-sensitive **full-path substring** | `Dropbox`, `CloudStorage`, `OneDrive`, `iCloud`, `Mobile Documents`, `com~apple~CloudDocs`, Google Drive variants — **no** Syncthing |
| GUI `volume_gui.rs` `is_under_sync_root` | Case-insensitive **path component** | dropbox, googledrive, onedrive, icloud drive, syncthing, nextcloud, … — **no** `CloudStorage` |

That answers “does this path *look like* a sync folder?” It does **not** answer
“are the bytes here?” It can also false-positive a local directory whose name
contains those tokens. UC-30 must (1) **unify** the detector into `blindkey-core`
(union list; include both `CloudStorage` and Syncthing), and (2) add a hydration
probe **in addition**. Do not treat the marker list as a File Provider / recall API.

✓ CLI mount refuse offers `blindkey seal` and `--force-local` (unsupported override).
GUI refuse offers Seal CTA only — no force. Checkout verbs are **not** implemented yet.

---

## 3. Atomic replace on a sync-watched path

POSIX `rename` on the same filesystem is atomic for local observers. A sync
client is a **second observer** with its own queue. The failure mode is not
“two names in one directory listing” — it is “upload a torn file” or “rename
rejected, so the app truncates.”

### 3.1 What reputable apps actually do

✓ **KeePassXC — Safe saves (default):** write a sibling temporary database,
then atomically move it into place. Documented as the defense against crash /
power loss.
[DatabaseOperations.adoc — Advanced Save Options](https://github.com/keepassxreboot/keepassxc/blob/develop/docs/topics/DatabaseOperations.adoc)

✓ **KeePassXC — why a second mode exists:** `Database::saveAs` comments that
Qt `QSaveFile` rename can fail on Dropbox / Google Drive / OneDrive
([QTBUG-57299](https://bugreports.qt.io/browse/QTBUG-57299)). They offer
“Temporary file saves” (write under the system temp dir, then move over) for
“poorly behaved cloud sync tools,” and they document that move as **not**
atomic. Direct-write is called unsafe and reserved for GVFS-class virtual
drives.

**Lesson:** C100’s “write-temp + rename” is the right default. Implement a
**detected-failure fallback** (temp outside the sync root, then replace) rather
than truncate. If even the fallback cannot replace, **fail closed** and leave
the working copy + sidecar (E2). Never “direct write” the brick as v1 default.

✓ **KeePass 2.x (Dominik Reichl):** on **Save** (not Save As), “KeePass first
checks whether the file on disk has been modified since it was loaded.” If
yes, prompt synchronize vs overwrite.
[keepass.info/help/base/multiuser.html](https://keepass.info/help/base/multiuser.html)
That is a **loaded-vs-disk** check (typically mtime/size), **not** a content
hash. KeePass can **merge entries**. KeePassXC is a **different product**: on
save it compares an **MD5 of the first file block** (`m_fileBlockHash` in
`Database.cpp`) and refuses overwrite if it changed (“unmerged changes”) —
still not a full-file hash, and still not entry merge for a volume brick.
UC-30 maps this to C101 fail-closed (**outer full-file** hash), not KeePass
synchronize and not KeePassXC’s first-block MD5 alone.

✓ **KeePassXC removed lockfiles** because they “create more problems than they
solve” on cloud sync: stale locks, conflicted copies of the `.lock` itself, no
shared PID namespace.
[keepassxc#2511](https://github.com/keepassxreboot/keepassxc/issues/2511),
[keepassxc#1002](https://github.com/keepassxreboot/keepassxc/issues/1002).
**Do not** put a `.lock` next to the sync-folder brick.

✓ **Cryptomator** encrypts a *tree* the sync client can delta-upload. It does
not serialize two machines on a single container file. Community: the sync
client cannot see FUSE-level locks on ciphertext.
[community.cryptomator.org/t/9935](https://community.cryptomator.org/t/locking-encrypted-files-when-files-in-the-vault-are-used/9935)
~ Not a template for `.vltd` checkin; it is why Blindkey stays on **one closed
file** + checkout rather than inventing per-block cloud sync.

### 3.2 Apple — coordinate the replace

✓ `NSFileCoordinator.coordinate(writingItemAt:options:error:byAccessor:)` —
wait for other readers/writers; **always use the URL passed into the accessor**
(it may differ from the input).
[developer.apple.com](https://developer.apple.com/documentation/foundation/nsfilecoordinator/coordinate(writingitemat:options:error:byaccessor:))

✓ `.forReplacing` — the write **replaces** the item; Apple: use this when the
new file should replace whatever is at the location; do **not** use it for
in-place content update.
[NSFileCoordinator.WritingOptions.forReplacing](https://developer.apple.com/documentation/foundation/nsfilecoordinator/writingoptions/forreplacing)

**Checkin rule (macOS sync / File Provider path):**

1. Hydration keys first (§2.1). Then fingerprint the existing brick
   (coordinated **read** only if already `current`). Coordinated read of a
   stub **downloads and blocks** (§2.1).
2. If mismatch → E1, stop.
3. Coordinated **write** `.forReplacing`: write `brick.vltd.<random>.tmp` in the
   **same directory** (same volume → `rename` can be atomic), `fsync`, `rename`
   over the brick (or `renamex_np` / `RENAME_EXCHANGE` only if both names must
   survive — not required here).
4. Do not leave the tmp name if rename succeeded.

~ iCloud / Drive File Provider may still upload the result as a **new
generation**. For iCloud that is a **full object** (§3.4). That is acceptable:
the brick is closed. It is **not** a reason to mount the sync path.

### 3.3 Linux

✓ Same-directory `rename(2)` after `fsync` of the fd (and `fdatasync` on the
directory where durability matters). `RENAME_EXCHANGE` is unnecessary for
replace-with-tmp.

~ Some FUSE/GVFS mounts (older “Drive as a volume”) break `rename` the way
KeePassXC’s GVFS note describes. Detect `EXDEV` / `EPERM` → fail closed +
sidecar; do not fall back to truncate.

### 3.4 What the sync client does after a good replace

~ Dropbox / Drive / iCloud will enqueue an upload of the new inode. During
upload the **remote** side is stale; another machine that checks out **now**
may get the old brick or a partial object depending on the vendor. That is
why hydration + fingerprint exist. There is **no** supported API to wait until
“uploaded” on macOS/Windows Dropbox (§2.3). Linux `dropbox filestatus` is
text-only and optional (§2.3).

✓ **iCloud uploads the whole file after any change** — not changed blocks.
Oakley measured a 1 MB file: a few-byte edit re-chunked ~the entire object
(MMCS). Same article: disk images / containers in iCloud are a bad fit for
that reason.
[eclecticlight.co, 2024-03-07](https://eclecticlight.co/2024/03/07/icloud-drive-in-sonoma-clones-sparse-files-versions-and-more/)

✓ **Dropbox syncs blocks, not whole files.** Official Dropbox engineering:
files are partitioned into aligned chunks of up to **4 MiB**; upload/download
is a block protocol keyed by SHA-256 of each block.
[Broccoli — dropbox.tech](https://dropbox.tech/infrastructure/-broccoli--syncing-faster-by-syncing-less);
[Streaming File Synchronization](https://dropbox.tech/infrastructure/streaming-file-synchronization);
[Inside LAN Sync](https://dropbox.tech/infrastructure/inside-lan-sync).
Public API `content_hash` uses the same block size: docs say “4 MB” but define
`4 * 1024 * 1024` bytes (**4 MiB**) and SHA-256-of-block-hashes
([developers/content-hash](https://www.dropbox.com/developers/reference/content-hash)).
A `.vltd` checkin that changes a few AEAD blocks → at least the touched 4 MiB
chunks (and neighbors if alignment shifts), **not** necessarily the whole
object. Still do **not** promise Blindkey-side delta sync (C102).

✓ **Syncthing is block-level.** Files are sliced into 128 KiB–16 MiB blocks;
only differing SHA-256 blocks are requested or copied.
[docs.syncthing.net/users/syncing.html](https://docs.syncthing.net/users/syncing.html)
§Blocks.

✓ **Google Drive for desktop uploads changed parts of large edited files**
(differential uploads) — not necessarily the whole object. Official:
“when large files are edited, Drive for desktop will now upload only the
parts of the file that changed.” Rollout complete; available to Workspace
and personal accounts.
[Workspace Updates Weekly Recap, 2025-01-10](https://workspaceupdates.googleblog.com/2025/01/release-notes-01-10-2025.html)
No public block-size / content-hash recipe like Dropbox’s 4 MiB API. Do not
promise Blindkey-side delta sync (C102).

~ Drive **API** resumable upload chunks (multiples of 256 KiB) are transport
for a single upload session
([manage-uploads](https://developers.google.com/workspace/drive/api/guides/manage-uploads)) —
not the desktop client’s differential-sync algorithm. Do not equate them.

✓ `ubiquitousItemPercentUploaded` exists on Apple; it is **progress after
checkin**, not a gate for C100. Another machine must still pass hydration.

**Product honesty:** checkin means “local sync folder has the new closed
brick.” It does not mean “every machine has it.” Provider upload may be
full object (iCloud ✓), ≤4 MiB blocks (Dropbox ✓), Syncthing blocks ✓, or
differential parts (Drive for desktop ✓ since 2025-01). Do not market any
of that as a Blindkey feature.

### 3.5 CLI vs GUI on Apple coordination

✓ `NSFileCoordinator` is a Foundation API. The desktop GUI can call it
(ObjC/Swift or `objc` crate). The Rust CLI has no Foundation runtime unless
we add one.

**Split (v1):**

| Surface | Replace path |
|---------|----------------|
| GUI / app bundle on macOS | Coordinated read + `.forReplacing` write (§3.2). |
| `blindkey` CLI on macOS | POSIX sibling-tmp + `rename` in the same directory. If `EXDEV`/`EPERM`, fail closed. |
| Linux CLI | POSIX `rename` after `fsync` (§3.3). |

Do not skip the fingerprint because the CLI skipped the coordinator. Coordinator
reduces File Provider races; it is not a substitute for C101.

**Checkin temp name:** must **not** start with `.syncthing.` or `~syncthing~`
(Syncthing will ignore/exclude those names). Prefer `<stem>.<rand>.bk-checkin.tmp`.

---

## 4. Fingerprint race

C101: if the sync-folder file changed since checkout, do not overwrite.

### 4.1 What to record

| Field | Why |
|-------|-----|
| `size` | Cheap reject; not sufficient alone. |
| Content hash (SHA-256 or BLAKE2b-256 of **all bytes**) | Detect any bit change. |
| `dev` + `ino` at checkout | Detect “same path, different file” (conflicted copy left beside). |
| Header magic + format version | Cheap reject of placeholders / wrong type. |

✗ **mtime / ctime only** — sync clients rewrite timestamps; two different
payloads can share an mtime after a copy.

✗ **Hash while downloading** — a growing file hashes as “new” every poll.

### 4.2 When to hash

1. **After** hydration pass (§2).
2. Open read-only, hash the working-copy **destination** after copy, then
   **re-stat + re-hash the source** (or compare source size + first/last 4 KiB
   + full hash if cheap enough). If source ≠ recorded checkout fingerprint
   **or** source changed during copy → abort, delete partial working copy.
3. **At checkin:** hash the sync-folder brick again. Compare to checkout
   record. Mismatch → E1.

~ For multi-gigabyte bricks, stream the outer hash **while** copying (hash
what you actually wrote to the working copy). Then re-stat the source; if
size/`ino` changed, abort. A second full source hash before mount is the
strict form; dest-hash + source size/`ino` match is the cheap form — use
strict at checkin (must re-read the sync-folder file anyway).

#### 4.2.1 Inner Merkle does **not** replace the outer file hash

✓ UC-25 layout ([spec §4.1](../docs/specs/UC-25-local-encrypted-volume.md)):
plaintext header + HMAC, AEAD volume header (**dual** copies), then a
**sparse** body of fixed-size AEAD blocks. Merkle leaves cover **block
records** (`block_id ‖ version ‖ tag`), not “every byte of the host file.”

Uncovered or differently covered:

| Region | Why an outer hash still matters |
|--------|----------------------------------|
| Host-file slack / Padmé tail | Logical file length is a size bucket (`--no-pad` opt-out). Spare bytes past the last live extent are not necessarily a Merkle leaf. |
| Sparse holes | `lseek` holes are zeros logically; a naive inner walk may skip them; a sync client may materialize them. |
| Dual header unused gap | Backup header is authenticated as a header, not as “bytes 0..EOF.” |
| Local freshness anchor | C70 lives **beside** the file (`volume-anchors/`), not inside it. Useless as a cloud-brick fingerprint. |

C101 asks “did this **path’s bytes** change?” — that is an **outer** SHA-256 /
BLAKE2b of the host file (or of the packed sparse representation you will
write back). Unlocking the volume to verify Merkle is slower, needs the
passphrase, and still misses host-file slack. **Keep the outer hash.**

#### 4.2.2 Outer hash must match **logical** file contents (holes = zeros)

C101 compares two closed host files. A sparse `.vltd`’s logical bytes include
holes that read as zeros. The outer hash must be over that logical stream
(size = `st_size`), not over allocated extents alone.

| Implementation | Notes |
|----------------|-------|
| Dense `read()` loop | Correct; slow on Padmé holes (reads synthesized zeros). |
| `SEEK_DATA` / `SEEK_HOLE` + feed zero digests for hole ranges | Correct and fast; same digest as dense. |
| Hash only allocated extents / skip holes | **Wrong** — mismatches a dense peer or a post-explosion copy. |

`clonefile` / hole-preserving copy keeps holes. After checkin into iCloud,
eviction/materialization may **explode** sparsity (§5.4) — then a later
checkout hashes a dense file of the same logical size. Digests still match
if both hash logical zeros. If a peer somehow stored a different hole map
with different logical size → size reject first.

### 4.3 Stability window

? No vendor “file is idle” API on Mac/Windows Dropbox.

**Do not treat 250 ms as “sync finished.”** That number was a debounce, not
evidence. ✓ Syncthing’s own watcher **delays 10 s** (`fsWatcherDelayS`) before
it even rehashes; deleted files wait ~1 min.
[Syncthing — Scanning](https://docs.syncthing.net/users/syncing.html)

**v1 idle rule (fail closed, short timeout):**

1. Hydration probe pass (§2).
2. No Syncthing/vendor temp sibling (§2.3, §3.5).
3. Two `stat` samples, **≥ 1 s** apart (not 250 ms): same `size`, `mtime`, `ino`.
4. Ubiquitous: not downloading; percent downloaded = 100 if the key exists.
5. Then hash. If (3) fails twice, error out (“wait until the client finishes”)
   with a **finite** timeout (e.g. 30 s CLI). Do not background-spin.

A file can still change after this window (another device). That is C101’s
job at checkin, not the idle probe’s.

---

## 5. Working-copy location and copy vs clone

### 5.1 Where the copy lives

Requirements: **not** a sync root (C99 / E6); survives process crash (E2);
must not be Time Machine / iCloud-backup of **cleartext-capable** leftovers
as if they were user documents (the working file is still ciphertext, but
sidecars and failed copies should not roam).

| Platform | Put working copy + sidecar here | Avoid |
|----------|----------------------------------|--------|
| macOS | `~/Library/Application Support/blindkey/volumes/work/<id>/` (same data root as C70 `volume-anchors/`) | `~/Documents`, Desktop, iCloud Desktop & Documents, `/tmp`, Downloads |
| Linux | `$XDG_DATA_HOME/blindkey/volumes/work/<id>/` (default `~/.local/share/blindkey/…`) — **reuse** shipped `rollback::data_dir()`, not a second `$XDG_STATE_HOME` tree | `$XDG_RUNTIME_DIR` (dies on reboot), `$XDG_CACHE_HOME` (evictable) |
| Windows (when mount exists) | `%LOCALAPPDATA%\blindkey\volumes\work\<id>\` | OneDrive-known folders, `%TEMP%` as sole home |

✓ XDG: `$XDG_STATE_HOME` is the textbook home for “open files” state
([basedir](https://specifications.freedesktop.org/basedir/latest/)). Blindkey
**already** stores vault rollback + volume anchors under **`$XDG_DATA_HOME` /
Application Support / LocalAppData** (`…/blindkey/`). UC-30 follows that tree so
checkout/resume and C70 share one root. Still never cache/runtime.

✓ Apple: `isExcludedFromBackup` / `NSURLIsExcludedFromBackupKey` for cache and
app-support files. Apple: “Set this property each time you save a file because
some common file operations cause this property to reset to false.” Do not use
this flag on the operator’s sync-folder brick (that is their document).
[isExcludedFromBackupKey](https://developer.apple.com/documentation/foundation/urlresourcekey/isexcludedfrombackupkey)

~ `~/Library/Caches` is purged under disk pressure — bad for an unsaved
checkin. Application Support / data dir + exclude-from-backup is the fit.

After creating the directory, run the **same** sync-root detector on the
resolved realpath. If the operator relocated Application Support into
Dropbox, fail closed (E6).

### 5.2 `clonefile` / `FICLONE` — use for hydrated sparse copies; never for stubs

✓ `clonefile(2)`: new inode, **shared extents**, later writes are
copy-on-write and private to the file being modified. Prefer the XNU man,
not a third-party HTML mirror:
[apple-oss-distributions/xnu `bsd/man/man2/clonefile.2`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/clonefile.2)
(Darwin `man 2 clonefile`). `dst` must not exist. Cloning a **dataless**
file can require materialization or fail depending on I/O policy (man:
dataless + materialization disallowed).

✓ FileProvider **itself** clone-copies into
`~/Library/Application Support/FileProvider/…` when a file is moved *into*
iCloud (staging). The user’s iCloud path keeps the **same inode** on that Mac;
another Mac gets a new inode on download.
[Oakley, 2024-03-07](https://eclecticlight.co/2024/03/07/icloud-drive-in-sonoma-clones-sparse-files-versions-and-more/)
That is the provider cloning **into its own tree**, not an app cloning *out*.

✓ iCloud **preserves APFS sparse** files (same article). A 1 GB logical / 20 KB
physical test file stayed sparse in the cloud. UC-25 volumes are **sparse
growable** (spec §4.1). A naive `read()`/`write()` of the logical size
**explodes holes** and turns checkin into a multi-gigabyte upload of zeros.

✓ Dropbox “clone files” filling Group Containers are the **client’s own
staging**, not a spec that `clonefile` to Application Support rewrites the
source brick.
[community.dropbox.com/826022](https://community.dropbox.com/en/discussion/826022/dropbox-is-filling-my-macs-hard-drive-with-clone-files)

**Copy rule**

| Condition | Action |
|-----------|--------|
| Source not hydrated / dataless | Refuse (E5). Never clone. |
| Dest would be under a sync root | Refuse (E6). |
| Source hydrated, dest state-dir, **same APFS volume** | **Prefer `clonefile`** — keeps sparse holes, cheap, new inode **outside** the sync folder. Source inode unchanged. |
| Different volume / Linux without reflink | Hole-preserving copy (`SEEK_DATA`/`SEEK_HOLE`, `copy_file_range`, or `FICLONE`). |
| No hole API | Last resort: full logical copy (document the size blow-up). |

Still refuse clone as a **substitute for hydration**. After clone: dest
`st_ino` ≠ source; dest realpath not a sync root.

✓ Oakley (2025-04-07): APFS clones share extents **only on the local volume**.
iCloud’s **remote** store treats clones as separate full objects (two 5 GB
clones → 10 GB iCloud quota). Eviction/materialization breaks local clone
sharing. A Blindkey checkout that `clonefile`s **out** of the sync folder into
Application Support creates a second local inode sharing extents until COW;
the sync client still sees one brick path. That is the intended sparse-safe
path — not a live mount of the sync path. No public File Provider doc requires
waiting on “extent refcount watches” for clone-out.
[How robust are APFS clone and sparse files?](https://eclecticlight.co/2025/04/07/how-robust-are-apfs-clone-and-sparse-files/)

**Product default:** prefer hydrated `clonefile` out. If clone fails (`ENOTSUP`
/ dataless policy) → hole-preserving copy, never dense sequential-read of Padmé.

Directory `clonefile` remains discouraged (Apple) — we clone **one file**.
`ENOSPC` on first COW write (man) is a mount-time disk-full error, not a
reason to explode sparse files.

### 5.3 Copy cost

ADR-0011 already accepts a copy on open and close. With hole-preserving
clone, cost tracks **allocated** bytes, not Padmé logical size. A dense
brick still copies in full — that is the price of not live-syncing a mounted
container (Amjad–Kamara–Moataz). After checkin, provider cost is per §3.4
(iCloud full object; Dropbox/Syncthing blocks).

### 5.4 iCloud eviction explodes sparse bricks (operator honesty)

✓ Same Oakley 2025 article: sparse files in iCloud stay sparse **while
downloaded**. Eviction → materialization **explodes** them to full logical
size and clears the sparse flag. iCloud allocation already charges full
logical size even when local was sparse.

Implication for a `.vltd` that **lives** in iCloud Drive:

1. Checkout while hydrated + sparse → cheap `clonefile`.
2. After sync + eviction on another Mac (or this one), the brick may return
   as a **dense** multi-gigabyte file.
3. Blindkey did not “bloat” it — the provider did. Document in C102 / UX:
   prefer Dropbox/Syncthing for large sparse volumes if upload/storage cost
   matters; iCloud is still allowed for a closed brick, with this cost.

Working-copy clones in Application Support are **not** in iCloud — eviction
of the sync-folder brick does not delete the working copy (separate inode).

### 5.5 VeraCrypt / TrueCrypt prior art (same shape as UC-30)

~ World Bank DIME VeraCrypt guidelines and long community practice: store the
container in Dropbox/Drive; **dismount before sync**; do not mount the same
container on two machines at once.
[dime-standards veracrypt-guidelines](https://github.com/worldbank/dime-standards/blob/master/dime-research-standards/pillar-4-data-security/data-security-resources/veracrypt-guidelines.md)

Known friction (community + VeraCrypt issue threads, Dropbox forum): if
“Preserve modification timestamp of file containers” is on, sync clients may
not notice content changes. UC-30 checkin writes a **new** closed file via
temp+rename → mtime/size change is natural. Do not add a “preserve mtime”
option for the sync-folder brick.

Dropbox forum traffic (VeraCrypt `.hc` / `.tc`) confirms operators expect
**block-level** sync of containers when the client detects change — consistent
with §3.4 Dropbox blocks, not with “always full re-upload.”
[Dropbox forum 372717](https://www.dropboxforum.com/t5/Create-upload-and-share/Block-level-sync-for-VeraCrypt-not-working-post-83-4-152-update/td-p/372717)
(~ operator reports; useful as corroboration of expected behavior, not a
protocol spec).

**Lesson:** UC-30 is the productized form of “dismount, then let the client
sync the closed file” — without requiring the operator to pause Dropbox or
manually move files (Dropbox’s own conflict help still recommends that move).

---

## 6. Crash sidecar (not a lockfile)

### 6.1 Why a sidecar

E2/E3: crash after writes, before checkin; or crash during rename. The
operator must be able to **resume checkin** or **discard** the working copy
without a half-written sync-folder file.

### 6.2 What OSS learned

✓ KeePassXC: **no** lockfile in the shared directory (§3.1). Guard **writes**
with a content/hash comparison instead.

~ Editor swap files (`*.swp`) in the **document** directory become conflicted
copies on Dropbox (widely reported; same mechanism as Dropbox’s “file left
open / autosave” trigger). Sidecar in the sync folder inherits that fate.

### 6.3 Recommended record

Store `state.json` (or equivalent) **only** under the working-copy parent
(§5.1):

```text
source_path          # last known sync-folder path (display + reopen)
source_fingerprint   # size + hash (+ dev/ino)
work_path            # container copy
phase                # copied | mounted | unmounted | checkin
pid                  # of the Blindkey process that owns the mount
created_at
```

Rules:

- Phase `mounted` + pid dead → treat as crash: unmount if needed, offer
  resume checkin (if work file looks closed/consistent) or discard.
- Phase `checkin` + tmp still present + brick fingerprint still matches →
  retry rename; if brick already equals work hash, delete tmp (idempotent).
- Phase `checkin` + brick fingerprint **differs** → E1; do not retry overwrite.
- **Never** write this JSON into the sync folder.
- Pid is advisory (stale after reboot). Fingerprint + phase are authoritative.

Zeroize keys on the crash path the same as a normal umount (C72). The sidecar
is not secret material (paths + hashes).

---

## 7. Two writers and vendor conflict copies

UC-30 E4: no merge. Last successful checkin whose fingerprint still matches
wins; the other hits E1.

**Security control is always fingerprint + path, never a filename regex.**
Vendor strings are UX hints only. They change, localize, and false-match.

### 7.1 What each vendor actually does

| Vendor | Mechanism | Primary source | Parse name? |
|--------|-----------|----------------|-------------|
| **Dropbox** | Sibling whose name includes `conflicted copy`, username, save date. Official: “The last version **saved** will always appear as the conflicted copy.” (Not “last finished upload.”) Workaround: move the file **out** while editing. | ✓ [help.dropbox.com/organize/conflicted-copy](https://help.dropbox.com/organize/conflicted-copy) (updated 2025-05-15) | UX only |
| **Syncthing** | Older mtime renamed; name contains `sync-conflict` (raw RST Sphinx macros render as placeholders; treat the token as stable, not a full regex grammar). Tie-break: larger first 63 bits of device ID. **Mod vs delete:** if deletion wins, the modified file is still renamed to a conflict copy. Conflict files **propagate**. | ✓ [syncing.rst](https://docs.syncthing.net/_sources/users/syncing.rst.txt) | UX only (`sync-conflict` to *list*, not to auto-pick) |
| **OneDrive / SharePoint** | Second file with **computer name** (or `-copy`) appended when the client cannot merge. Office “sync conflicts” setting is for Office docs, not a `.vltd`. | ~ Microsoft Q&A (support staff): [learn.microsoft.com answers 5170157](https://learn.microsoft.com/en-us/answers/questions/5170157/sharepoint-online-duplicate-files-with-pc-name) — not a protocol spec | No |
| **iCloud Drive** | Two layers: (1) **`NSFileVersion` conflict versions** — current winner + `unresolvedConflictVersionsOfItem(at:)`. Apps must resolve; versions occupy iCloud until marked resolved. (2) Finder sometimes shows a **sibling** (` (conflicted copy)` or ` 2` suffix). The ` 2` suffix is a known iCloud Desktop/Documents artifact (e.g. git repos under Documents). | ✓ [NSFileVersion](https://developer.apple.com/documentation/foundation/nsfileversion); ✓ [iCloud file management](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/iCloud/iCloud.html); ~ ` 2` suffix: community (SO 62385234), not an API | **API, not regex.** If `ubiquitousItemHasUnresolvedConflicts` → refuse. Do not auto-`replaceItem`. |
| **Google Drive for desktop** | Official docs do **not** publish a Dropbox-style conflict filename grammar. Documented behaviors: (1) stream→mirror switch: “If the content in a file differs from what’s in the cloud, Drive for desktop **keeps both**” — no name pattern. (2) Sync failure: “a copy of the file with your edits” under the parent folder, else My Drive root, else **Lost & Found** (`…/Google/DriveFS/lost_and_found/<account_token>`). Docs/Sheets co-author — **irrelevant** to a `.vltd`. Community names (`[Conflict]`, `(1)`) are **not** load-bearing. | ✓ [answer/13401938](https://support.google.com/drive/answer/13401938) “keeps both”; ✓ [answer/2565956](https://support.google.com/drive/answer/2565956) edit-copy / Lost & Found | **No.** Fingerprint + path only. |

### 7.2 Product rule

Checkin targets the **path the operator opened**. If that path’s hash/`ino`
changed → E1. Optionally **list** siblings whose names contain
`conflicted copy` / `sync-conflict` as a hint. Never overwrite a sibling.
Never “merge” two bricks.

iCloud GUI: if `unresolvedConflictVersionsOfItem` is non-empty, stop and tell
the operator both versions exist. Blindkey does not call `resolved = true`
for them (that deletes cloud versions).

Dropbox’s recommended workaround (move the file out while editing) is
checkout. Do not implement “pause Dropbox.”

---

## 8. Distilled rules for UC-30 implementation

| ID | Rule |
|----|------|
| R1 | Metadata / attributes before any content open. |
| R2 | Fail closed on placeholder, stale ubiquitous download, or recall-on-access. |
| R3 | Working copy + sidecar under platform **data** dir shared with C70 (`…/blindkey/volumes/work/`); re-test sync-root on realpath. (XDG_STATE_HOME is textbook; Blindkey reuses data_dir.) |
| R4 | Copy must **preserve sparse holes**. Hydrated + same volume + dest outside sync → `clonefile`/`FICLONE`. Never clone a placeholder. Never sequential-read a sparse brick as dense. |
| R5 | Fingerprint = outer size + file hash (not inner Merkle). Refresh at end of copy and before replace. |
| R6 | Checkin = sibling tmp + fsync + rename; GUI on Apple → `NSFileCoordinator.forReplacing`. CLI may POSIX-rename. Temp name must not use Syncthing prefixes. |
| R7 | Rename failure → fail closed, keep work + sidecar; no truncate-in-place. |
| R8 | No lockfile / sidecar in the sync folder. |
| R9 | Two-machine = E1, not merge. iCloud: refuse if unresolved `NSFileVersion` conflicts. Filename regex is UX only. |
| R10 | Checkin ≠ “uploaded to all devices.” Do not promise Blindkey delta sync (C102). iCloud recopies the **whole object** (Oakley). Dropbox syncs **≤4 MiB blocks** (dropbox.tech + content_hash). Syncthing syncs **changed blocks**. Drive for desktop uploads **changed parts** of large edits (Workspace Updates 2025-01-10). |
| R11 | Idle probe: hydration + no vendor tmp + two matching `stat`s ≥ 1 s apart. 250 ms is not “synced.” |
| R12 | `st_size` / logical size is not hydration. Use allocated size + ubiquitous / recall / CfAPI bits. |
| R13 | Distinguish dataless stub from hydrated sparse using status / percent / `SF_DATALESS` / `RECALL_*` / `PARTIALLY_ON_DISK` — not “allocated much smaller than size” alone. |
| R14 | Never use coordinated read / content `open` as a hydration probe. Apple’s coordinator **blocks and downloads** an undownloaded file. |
| R15 | Outer fingerprint hashes **logical** contents (holes = zeros). Hole-skipping hashes are wrong. |
| R16 | Google Drive **Stream**: refuse unless hydrated / Available offline. **Mirror**: expect local copy. Do not use “Drive app running” alone as the gate (File Provider keeps downloaded files after quit). |
| R17 | iCloud eviction can explode sparse `.vltd` to full logical size (Oakley 2025). UX honesty, not a code refuse. |

---

## 9. Bibliography

**Apple**

- [URLUbiquitousItemDownloadingStatus](https://developer.apple.com/documentation/foundation/urlubiquitousitemdownloadingstatus) — `current` / `downloaded` (stale) / `notDownloaded`
- [ubiquitousItemDownloadingStatusKey](https://developer.apple.com/documentation/foundation/urlresourcekey/ubiquitousitemdownloadingstatuskey)
- [NSFileCoordinator.coordinate(readingItemAt:…)](https://developer.apple.com/documentation/foundation/nsfilecoordinator/coordinate(readingitemat:options:error:byaccessor:)) — blocks until download
- [NSFileCoordinator.coordinate(writingItemAt:…)](https://developer.apple.com/documentation/foundation/nsfilecoordinator/coordinate(writingitemat:options:error:byaccessor:))
- [WritingOptions.forReplacing](https://developer.apple.com/documentation/foundation/nsfilecoordinator/writingoptions/forreplacing)
- [Designing for Documents in iCloud](https://developer.apple.com/library/archive/documentation/General/Conceptual/iCloudDesignGuide/Chapters/DesigningForDocumentsIniCloud.html) — coordinated read of undownloaded file blocks
- [isExcludedFromBackupKey](https://developer.apple.com/documentation/foundation/urlresourcekey/isexcludedfrombackupkey) — re-set each save (Apple wording)
- [fileAllocatedSize](https://developer.apple.com/documentation/foundation/urlresourcevalues/fileallocatedsize)
- [NSFileVersion](https://developer.apple.com/documentation/foundation/nsfileversion) — `unresolvedConflictVersionsOfItem`
- [iCloud file management](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/iCloud/iCloud.html)
- [iCloud metadata attributes](https://developer.apple.com/library/archive/documentation/CoreServices/Reference/MetadataAttributesRef/Articles/iCloudAttrs.html) — percent downloaded/uploaded
- [clonefile(2) — XNU man](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/clonefile.2)
- Oakley, *Dataless files arrive*, 2023-10-29 — [eclecticlight.co](https://eclecticlight.co/2023/10/29/last-week-on-my-mac-dataless-files-arrive/)
- Oakley, *iCloud Drive in Sonoma: clones, sparse files, versions*, 2024-03-07 — [eclecticlight.co](https://eclecticlight.co/2024/03/07/icloud-drive-in-sonoma-clones-sparse-files-versions-and-more/)
- Oakley, *How robust are APFS clone and sparse files?*, 2025-04-07 — [eclecticlight.co](https://eclecticlight.co/2025/04/07/how-robust-are-apfs-clone-and-sparse-files/) — eviction explodes sparse; clones not shared in iCloud remote

**Microsoft**

- [File Attribute Constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants) — `RECALL_ON_DATA_ACCESS`, `RECALL_ON_OPEN`, `OFFLINE`, `PINNED`
- [CF_PLACEHOLDER_STATE](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ne-cfapi-cf_placeholder_state) — `PARTIALLY_ON_DISK`, `PARTIAL`, `IN_SYNC`
- [CfGetPlaceholderStateFromAttributeTag](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfgetplaceholderstatefromattributetag)
- [Handling placeholders (IFS)](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/placeholders_guidance) — do not opportunistic-read `RECALL_ON_DATA_ACCESS`

**Google**

- [Stream & mirror files](https://support.google.com/drive/answer/13401938) — Stream vs Mirror; stream→mirror “keeps both” on content mismatch
- [Fix problems in Drive for desktop](https://support.google.com/drive/answer/2565956) — edit-copy under parent / Lost & Found (no filename grammar)
- [Workspace Updates Weekly Recap, 2025-01-10](https://workspaceupdates.googleblog.com/2025/01/release-notes-01-10-2025.html) — differential uploads for large edited files
- [Drive API manage uploads](https://developers.google.com/workspace/drive/api/guides/manage-uploads) — resumable 256 KiB transport chunks (not desktop differential recipe)

**Sync vendors**

- [Dropbox — conflicted copy](https://help.dropbox.com/organize/conflicted-copy) (also: move file out while working)
- [Dropbox Linux CLI — filestatus](https://help.dropbox.com/installs/linux-commands)
- Dropbox Community — no programmatic sync status on Mac/Windows
  ([201505](https://community.dropbox.com/en/discussion/201505/need-for-dos-command-to-know-if-files-are-already-synched))
- Dropbox engineering — **4 MiB blocks**: [Broccoli](https://dropbox.tech/infrastructure/-broccoli--syncing-faster-by-syncing-less), [Streaming File Synchronization](https://dropbox.tech/infrastructure/streaming-file-synchronization), [Inside LAN Sync](https://dropbox.tech/infrastructure/inside-lan-sync)
- [Dropbox content_hash API](https://www.dropbox.com/developers/reference/content-hash) — same 4 MiB SHA-256 recipe (public)
- [Syncthing — Understanding synchronization](https://docs.syncthing.net/users/syncing.html) ([RST source](https://docs.syncthing.net/_sources/users/syncing.rst.txt)) — **blocks**, conflicts (`sync-conflict`), `.syncthing.*.tmp` / `~syncthing~*.tmp`, 10 s watcher delay, mod-vs-delete
- OneDrive computer-name duplicates — [Microsoft Q&A 5170157](https://learn.microsoft.com/en-us/answers/questions/5170157/sharepoint-online-duplicate-files-with-pc-name) (support, not a spec)

**OSS apps / prior art**

- KeePassXC [DatabaseOperations.adoc (`develop`)](https://github.com/keepassxreboot/keepassxc/blob/develop/docs/topics/DatabaseOperations.adoc) — Safe saves / Temporary file saves (move **not** atomic) / Direct-write (unsafe; GVFS)
- KeePassXC [`src/core/Database.cpp` (`develop`)](https://github.com/keepassxreboot/keepassxc/blob/develop/src/core/Database.cpp) — `QSaveFile` / QTBUG-57299; first-block **MD5** change guard (`m_fileBlockHash`)
- KeePassXC [#1002](https://github.com/keepassxreboot/keepassxc/issues/1002), [#2511](https://github.com/keepassxreboot/keepassxc/issues/2511) — lockfiles vs cloud
- KeePass [Multiple Users](https://keepass.info/help/base/multiuser.html) — Save checks “modified since loaded” (not a content hash); merge is KeePass-only
- Cryptomator community [t/9935](https://community.cryptomator.org/t/locking-encrypted-files-when-files-in-the-vault-are-used/9935) — FUSE lock ≠ ciphertext lock
- World Bank DIME [VeraCrypt guidelines](https://github.com/worldbank/dime-standards/blob/master/dime-research-standards/pillar-4-data-security/data-security-resources/veracrypt-guidelines.md) — dismount before sync; no dual mount
- Dropbox forum [VeraCrypt block sync](https://www.dropboxforum.com/t5/Create-upload-and-share/Block-level-sync-for-VeraCrypt-not-working-post-83-4-152-update/td-p/372717) — ~ operators expect block sync of containers

**Standards / prior Blindkey research**

- XDG Base Directory — [latest](https://specifications.freedesktop.org/basedir/latest/)
- Amjad–Kamara–Moataz, ePrint 2018/195 — snapshot ≈ persistent adversary (why live+sync stays forbidden)
- [`encrypted_cloud_storage_research.md`](encrypted_cloud_storage_research.md)
- [`encrypted_volume_mount_research.md`](encrypted_volume_mount_research.md)

**Community (not load-bearing alone)**

- [SO 79546133](https://stackoverflow.com/questions/79546133/how-can-i-detect-sparse-download-on-demand-files-on-windows-with-python) — Windows placeholder heuristic
- [ncstatus](https://github.com/weiaoli2/ncstatus) — never open placeholders (third-party README; ~)

---

## 10. Still open (do not fake)

| Item | Status |
|------|--------|
| Google Drive conflict **filename** grammar | ✓ **closed** — official Help has no stable name pattern; documents “keeps both” / edit-copy / Lost & Found. Fingerprint + path only (R9). |
| Google Drive opaque-file upload class | ✓ **closed** — Drive for desktop **differential uploads** for large edited files (Workspace Updates 2025-01-10). No public block-size recipe; do not market as Blindkey delta. |
| Exact allocated/logical cutoff stub vs sparse | ✓ closed as unresolvable — use status/CfAPI/`SF_DATALESS`, not a ratio |
| File Provider watches extent refcounts on clone-out | ✓ closed for product — Oakley 2025: clone-out is local COW; remote does not share extents; prefer `clonefile` when hydrated |
| Dropbox opaque-file checkin = full re-upload? | ✓ **no** — official 4 MiB block sync (Broccoli / content_hash) |
| Wait-until-uploaded API on Mac/Win Dropbox | ✓ does not exist; iCloud has percent-uploaded (progress only) |
| Inner Merkle covers host-file EOF / Padmé slack | ✓ it does not — outer logical hash required (UC-25 §4) |
| Fuse-T / macFUSE still required to **use** the working copy on macOS | Build (ADR-0010), not this paper |

### Final validation checklist (2026-09-06)

| Claim | Source check | Result |
|-------|--------------|--------|
| Dropbox conflict + move-out | help.dropbox.com 2025-05-15 | ✓ “last version **saved**”; move out while working |
| Dropbox 4 MiB blocks | Broccoli + content_hash (4×1024×1024) | ✓ |
| Syncthing temps / blocks / 10 s | syncing.rst | ✓; conflict full template RST-garbled → token only |
| Apple `downloaded` = stale | sosumi / enum docs | ✓ |
| Coordinator blocks on undownloaded | Apple readingItemAt + iCloud Design Guide | ✓ |
| Backup exclude re-set each save | isExcludedFromBackupKey | ✓ Apple wording |
| KeePassXC first-block MD5 | Database.cpp `m_fileBlockHash` | ✓ |
| Google Stream/Mirror + File Provider | answer/13401938 + 12178485 | ✓ |
| Google Drive conflict naming | answer/13401938 + 2565956 | ✓ closed — no official grammar; keeps both / Lost & Found |
| Google Drive upload class | Workspace Updates 2025-01-10 | ✓ differential uploads for large edits |
| iCloud sparse eviction | Oakley 2025-04-07 | ✓ |
| UC-25 outer hash needed | UC-25 §4 Merkle leaves | ✓ |
| Public leaks | OSS tree grep for private vault paths / home usernames | ✓ none |

**No open research blockers** for UC-30 draft implementation. Remaining work is build (ADR-0010 macOS mount, then S-29).

---

## 11. Mapping to constraints

| Constraint | This note |
|------------|-----------|
| C99 | §2 hydration + §5 state dir + **hole-preserving** copy (`clonefile` / `FICLONE` / `SEEK_HOLE`); never mount the sync path |
| C100 | §3 sibling tmp + rename; coordinator on Apple; no truncate |
| C101 | §4 fingerprint; §7 E1 vs conflict copies |
| C102 | §0 / §3.4 / R10 — do not market live sync-path mount or “fully synced” |
