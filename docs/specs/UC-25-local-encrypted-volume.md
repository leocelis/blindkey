# UC-25 — Local Encrypted Workspace Volume (Live Mount)

> **Tech spec** · **Implemented v1.0** · July 2026 · **Status:** implemented — core + CLI + Linux FUSE + GUI shipped  
> (`blindkey-core::volume` create/open/read/write/sync + Merkle/Kcom/anchor; `blindkey volume` CLI
> verbs + `peek` dispatch; Linux `blindkey-fuse` adapter; GUI Create/Mount/Eject thin shell; fuzz +
> joint-satisfaction green. **Remaining lane:** macOS FUSE provider (macFUSE/Fuse-T) packaging +
> harnessed benches — see §12.)  
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-25 · **Constraints:** C67–C74 (G17, FORWARD until ship);  
> reuses C1–C3, C5, C7, C11, C16 posture, C23, C27 (documented residual / SC10), C30–C32, C64 culture  
> **Requirements sources:** PRD §5 UC-25 · intent G17 (C67–C74) · operator patterns MNT-* / MSV-*  
> (encoded herein — public docs must not embed private operator-tree paths, MNT-04d)  
> **Research:** [encrypted_volume_mount_research.md](../../research/encrypted_volume_mount_research.md),  
> [encrypted_volume_maximum_security_research.md](../../research/encrypted_volume_maximum_security_research.md)  
> **Sibling:** [UC-23](UC-23-sealed-file-storage.md) — seal/open/peek for untrusted cloud (**not** this UC)  
> **Architecture:** [ARCHITECTURE.md](../ARCHITECTURE.md) · [FILE_FORMAT.md](../FILE_FORMAT.md) · [CRYPTO.md](../CRYPTO.md)  
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the **intent wins**.  
> C67–C74 (G17, intent **v1.9.1**) are now **active** — verified by `volume_constraints.rs`,
> `uc25_joint_satisfaction.rs`, `fuzz/volume_block_parse`, and `blindkey-gui uc25_constraints.rs`.
> Design sources and tests are bound in `blindkey_intent.yaml` G17; this spec is the
> implementation contract. **Accepted 2026-07-21** (Gate-0 checklist: spec accept).

This document is the **implementation contract**: on-disk layout, crate boundaries, public APIs,
CLI/GUI surfaces, mount lifecycle, tests, and phased delivery — aligned with Blindkey’s OSS
workspace (library/CLI split, thin shells, audited crypto only).

---

## 1. Scope & goals

PGP Disk / VeraCrypt-class UX: create a **local encrypted volume** (`.vltd`), **mount** it as a
normal folder, edit files, **umount** → ciphertext only. Local-workstation complement to UC-23
`.vltf` archives.

**Framing:** “Local encrypted workspace.” Adversary v1 = stolen laptop / USB / offline `.vltd`
copy. **Not** a malicious sync backend (that remains UC-23).

| # | Goal |
|---|------|
| 1 | CLI `blindkey volume …` + `peek`; GUI Create / Mount / Eject over `blindkey-core` (UC-18) |
| 2 | MSV crypto: fixed-size AEAD blocks, Merkle/MAC tree, local freshness, Padmé, Argon2id + **explicit key commitment (Kcom)** + stanzas — GCM-SIV alone is **not** commitment |
| 3 | Userspace mount: Linux `fuser`; macOS macFUSE-FSKit / Fuse-T (no kext hard-req) |
| 4 | Honest residual: mounted = OS cleartext (FileVault-unlocked class); C27 does not cover Finder reads |
| 5 | Same unlock story as vault/`.vltf` (UC-09/UC-21); header-only password change |

**Architecture (MNT-05 / MNT-05b):** Family **B+** only — CryFS-class AEAD fixed blocks + virtual
POSIX tree in Blindkey. **Do not** decrypt a block device + `mkfs` (Family A / XTS world).
Family C (`hdiutil` sparsebundle) is Mac-only **stopgap UX**, never the crypto core.

**Non-goals (v1):** UC-23 FUSE expansion (MNT-01 / C67); live RW+cloud sync (MNT-02 / C73);
VeraCrypt compat (MSV-09d); whole-disk/boot; Windows mount (WinFsp later — MNT-09: **Dokany
forbidden** as primary); PD/hidden volumes (MSV-06); ORAM (MSV-07); GPL cryptsetup in core
(MNT-07 / MSV-20); `hdiutil` as crypto core; cipher cascades (MSV-04); inventing primitives
(MSV-05 / C3); PQ bulk data-plane (MSV-08); EncFS/eCryptfs (MNT-08 / MSV-09c); naked XTS/XCB
(MSV-02 / MSV-03 / C68); GCM-SIV alone as commitment (MSV-09b / C69); compression-before-AEAD
default-on (MSV-09). Threat ladder **L0–L4** only; document L5–L6 residual (MSV-01).

If forced into XTS interop **later** (not v1): add integrity (dm-integrity-class or **iXTS**,
ToSC 2025(4)) and document expansion — never naked XTS as MSV (MNT-05c).

---

## 2. Architecture fit (Blindkey OSS)

### 2.1 Workspace placement

Extend the existing trust boundary — **do not** invent a parallel crypto stack.

```
┌──────────────────────────────────────────────────────────────┐
│  blindkey-cli   Command::Volume { … } · Peek on .vltd        │  C20–C22, C31, C67–C74
│  blindkey-gui   Volume wizard / Mount / Eject (thin shell)   │  UC-18/20/21
│  blindkey-tui   Optional parity gauges for create            │
└────────────────────────────┬─────────────────────────────────┘
                             │ uses (no crypto in shells)
┌────────────────────────────▼─────────────────────────────────┐
│  blindkey-core                                               │
│    volume/          NEW — UC-25 MSV format + virtual FS API  │  C67–C74
│    format/header    extend ContainerKind + magic VLTD        │  C7, C67
│    envelope/        reuse stanza unwrap (password/keyfile/YK)│  C4–C6, C5
│    crypto/          XChaCha STREAM primitives + HKDF/Argon2  │  C1–C3
│    pad/             Padmé (default-on for volumes)           │  C71
│    rollback/        patterns reused for volume local anchor  │  C70
│    memory/          Secret / zeroize / mlock                 │  C11
│    sealed/          UNCHANGED — UC-23 remains seal/open/peek │  C61–C66
└────────────────────────────┬─────────────────────────────────┘
                             │ optional feature
┌────────────────────────────▼─────────────────────────────────┐
│  blindkey-fuse  (NEW crate OR feature `volume-mount` in CLI) │
│    fuser::Filesystem adapter over VolumeSession              │
│    macOS: link Fuse-T / macFUSE provider at packaging time   │
└──────────────────────────────────────────────────────────────┘
```

**Decision (normative):**

| Piece | Location | Rationale |
|-------|----------|-----------|
| Format + AEAD blocks + tree + Kcom + virtual FS | `blindkey-core::volume` | Same as `sealed` — auditable security boundary |
| FUSE adapter | New crate `blindkey-fuse` **or** `blindkey-cli` feature `volume-mount` | Keeps `fuser` / macOS provider deps out of default `blindkey-core` builds (C20 small core) |
| GUI | `blindkey-gui` only calls core + spawn mount helper | UC-18: never reimplement crypto |

**Recommendation:** `blindkey-fuse` as a thin crate depending on `blindkey-core`, invoked by
`blindkey volume mount` (subprocess or in-process). Prefer **in-process** on Linux; macOS may
need a helper for FSKit extension packaging — decide in Phase C ADR.

### 2.2 ContainerKind extension

Today (`lib.rs`): `Vault` (`VLT\0`) · `SealedFile` (`VLTF`) · `Volume` (`VLTD`).

```rust
// Normative — ADR-0007
pub const MAGIC_VLTD: [u8; 4] = *b"VLTD";

pub enum ContainerKind {
    Vault,
    SealedFile,
    Volume, // UC-25
}
```

Wrong-kind open → clear kind-mismatch error (not parse oracle). ADR-0005 hygiene: `.vlt` /
`.vltf` bytes unchanged. Extension **`.vltd`** (ADR-0007).

### 2.3 Invariants (must uphold — same culture as ARCHITECTURE.md)

- No secret `Debug`/`Display`; no plain `Vec<u8>` for keys. **C11**
- Constant-time compares on tags / Kcom. **C25**
- No plaintext block released before AEAD tag verifies. **C68 / C1 culture**
- No network / telemetry on mount path. **C23 / C72**
- No secrets on argv. **C31**
- Atomic header updates (temp → fsync → rename); dual header. **C32 / MSV-15**
- Uniform errors on unlock/auth failure. **C74 / C64 culture**

---

## 3. Prior art (implementation lessons)

| Source | Take into Blindkey code |
|--------|-------------------------|
| `sealed.rs` (UC-23) | Header reuse, `SealedUnlock`, progress/cancel opts, Padmé, stanza parity — **mirror API shape** |
| CryFS | Fixed-size blocks + local version tree |
| LUKS2 | Dual headers; header-only rewrap |
| VeraCrypt | UX; unlocked = cleartext to OS |
| gocryptfs audit (Hornby) | Active adversary → AEAD + tree required (MNT-14); passive-only integrity insufficient |
| age / rage-mount | RO tar/zip FUSE only — **not** RW PGP-Disk UX (MNT-15); do not market as equivalent |
| Albertini / Len | Explicit key commitment on password wraps (MSV-13 / C69) |
| Fuse-T / macFUSE / FSKit | Mount providers; Fuse-T commercial license if embedding |

**KDF note (MNT-13 / MSV kdf):** CryFS config KDF = **scrypt** is prior art only. Blindkey MSV
**requires Argon2id** (C2); scrypt/PBKDF2 rejected as sole volume KDF.

Craft patterns (MNT-*, MSV-*) are encoded below and traced in §18. Public docs must not
embed private operator-tree paths (MNT-04d).

---

## 4. On-disk format (`.vltd` / magic `VLTD`)

All multi-byte integers **little-endian** (FILE_FORMAT.md house style).

### 4.1 Top-level layout

```
┌────────────── plaintext Blindkey header (shared machinery) ──────────────┐
│ magic            [4]   b"VLTD"                              │  C67 / C7
│ format_version   u16   = 1 (volume format v1; independent of vault freeze)
│ volume_id        [16]  UUIDv4, fixed at create              │  HKDF domain
│ kdf_algorithm    u8    1 = Argon2id                         │  C2 / C8
│ argon2id_m/t/p + salt[32]                                   │  C2 floor/ceiling
│ master_seed      [32]  CSPRNG (YubiKey challenge domain)    │  UC-09 parity
│ nonce_prefix     [16]  unused for body STREAM; reserved / 0 │  keep header layout
│ stanza_count     u8    1..=8                                │  C5
│ stanzas          […]   same stanza_record as vault/vltf     │  C5
│ header_hash      [32]  SHA-256(above)                       │  C9
│ header_hmac      [32]  HMAC(data-key-derived)               │  C9
└─────────────────────────────────────────────────────────────┘
┌────────────── authenticated volume header (AEAD-wrapped) ───┐
│ Primary copy + backup copy (MSV-15 / LUKS2)                 │
│   volume_params: block_size_kib, aead_id, max_bytes, …      │
│   merkle_root[32], max_block_id, format flags               │
│   kcom[32]   (or Albertini padding-fix marker)             │  C69
│   pad_mode   default Padmé                                  │  C71
└─────────────────────────────────────────────────────────────┘
┌────────────── sparse body (Padmé-padded file length) ───────┐
│ Block table / extent index (ciphertext)                     │
│ Fixed-size AEAD blocks (CryFS-class graph)                  │  C68
│   plaintext capacity: 32 KiB default (tunable 16–32)        │
│   ciphertext = nonce(24) ‖ ciphertext ‖ tag(16)  (XChaCha)  │
└─────────────────────────────────────────────────────────────┘
```

**Sparse growable** with explicit `max_bytes` at create (MNT-17). Physical file length follows
Padmé buckets by default (`--no-pad` opt-out only).

### 4.2 Block record (normative)

| Field | Size | Notes |
|-------|------|-------|
| `block_id` | u64 | Stable ID in graph |
| `version` | u64 | Monotonic per block (freshness) |
| `kind` | u8 | dir / file-data / free / meta — **ciphertext-indistinguishable sizes** |
| plaintext | `block_size` | Zero-padded to fixed size |
| AAD | — | `volume_id ‖ block_id ‖ version ‖ kind` |
| nonce | 24 | `PRF(nonce_key, block_id ‖ version)[0:24]` — **not** random log |
| AEAD | — | XChaCha20-Poly1305 (default) or AEGIS-256 (optional profile) |

### 4.3 Key hierarchy

```
password ──Argon2id(C2)──▶ KEK
                            │
              HKDF domain-separated
                            ├─▶ Kenc     ──AEAD-wrap──▶ volume_master_key (32)
                            └─▶ Kcom     ──store + verify on unlock──▶  (C69)

volume_master_key ──HKDF──▶ volume_key, mac_key, nonce_key, (kcom_material if needed)

Per block:
  nonce = PRF(nonce_key, block_id ‖ version)
  C = AEAD_Seal(volume_key, nonce, AAD, plaintext_block)
  leaf = H(mac_key, block_id ‖ version ‖ tag)   # or BLAKE3 keyed
  merkle_root = Merkle(leaves)
```

Password change / `upgrade-kdf`: **header-only rewrap** (MSV-16 / MNT-10). Master volume keys
immutable for volume lifetime. Multi-factor unlock = Blindkey stanzas only — **not** a parallel
enrollment story (MNT-18).

Key wrap MAY use XChaCha20-Poly1305 or AES-GCM-SIV for NMR hygiene — **always** with explicit
Kcom or Albertini padding fix (MSV key_wrap / MSV-09b). AES-GCM / ChaChaPoly / AEGIS / GCM-SIV
**alone** do not satisfy C69.

### 4.4 Local freshness anchor (C70)

Not stored inside the synced/stolen `.vltd` alone:

```
~/.local/share/blindkey/volume-anchors/<volume_id hex>/
  anchor.json   # or binary: max_root_version, merkle_root snapshot, device_label
```

(Exact path via existing Blindkey config dir helpers — `BLINDKEY_CONFIG_DIR` / UC-22.) On unlock:
compare header merkle/version to local anchor; mismatch → **fail closed** by default.
**MSV-19:** new device must explicit-trust baseline (document + CLI flag
`volume trust-anchor` or first-mount prompt).

---

## 5. `blindkey-core::volume` — public API (contract)

Illustrative signatures — **the contract**, not final names. Mirror `sealed.rs` style.

```rust
/// Uniform unlock/mount failure (C74 — no format oracle).
pub const VOLUME_OPEN_ERROR: &str = "volume could not be opened";

pub struct VolumeUnlock<'a> {
    pub password: &'a [u8],
    pub keyfile: Option<&'a [u8]>,
    // YubiKey respond hook — same type as sealed::YubiKeyRespond
}

pub struct VolumeCreateOpts {
    pub size_bytes: u64,
    pub max_bytes: u64,
    pub block_size_kib: u16,       // default 32
    pub pad_mode: PadMode,         // default Padme
    pub aead_profile: AeadProfile, // XChaCha (default) | Aegis256
}

pub struct VolumeIoOpts<'a> {
    pub cancel: Option<&'a AtomicBool>,
    pub progress: Option<&'a mut dyn FnMut(u64, u64)>, // create/format progress
}

pub struct Volume; // handle after unlock (keys in Secret/Zeroizing)

impl Volume {
    pub fn create(path: &Path, unlock: VolumeUnlock<'_>, opts: VolumeCreateOpts,
                  io: VolumeIoOpts<'_>) -> Result<Self>;

    pub fn open(path: &Path, unlock: VolumeUnlock<'_>) -> Result<Self>;

    /// Header-only KDF / password rewrap (MSV-16).
    pub fn upgrade_kdf(&mut self, …) -> Result<()>;

    /// List virtual tree (peek) — metadata only.
    pub fn list(&self, path: &str) -> Result<Vec<DirEntryMeta>>;

    /// Virtual FS ops used by FUSE adapter (path-normalized, traversal-safe).
    pub fn getattr(&self, path: &str) -> Result<FileAttr>;
    pub fn readdir(&self, path: &str) -> Result<Vec<DirEntryMeta>>;
    pub fn read(&self, ino_or_path: …, offset: u64, buf: &mut [u8]) -> Result<usize>;
    pub fn write(&mut self, …) -> Result<usize>;
    pub fn create_file / mkdir / unlink / rename / truncate / …;

    /// Persist dirty blocks + dual header; update local anchor.
    /// Verify merkle on metadata path; schedule/perform periodic data-path tag checks (MSV-11).
    pub fn sync(&mut self) -> Result<()>;

    /// Grow sparse container up to max_bytes (MNT-17 / CLI resize).
    pub fn resize(&mut self, new_size: u64) -> Result<()>;

    /// Zeroize keys (C11 / C72 / MSV-18). Caller must have unmounted first.
    pub fn close(self) -> Result<()>;
}

pub struct DirEntryMeta { /* name, kind, size — no content */ }
```

**Rules:**

- Path normalization rejects `..`, absolute paths, NUL — same spirit as UC-23 C65 (virtual tree).
- `write` updates block versions + merkle; `sync` writes dual header atomically (MNT-11).
- **Secure free (MSV-24):** unlink/truncate re-encrypts freed blocks with fresh random **or**
  hole-punch + overwrite policy — never leave stale plaintext-capacity ciphertext reusable as oracle.
- Drop/`close` zeroizes; wipe mount-process cleartext where feasible (MNT-21); debug builds may
  assert keys wiped (C72 test).
- Compression before AEAD: **off by default** (MSV-09); if ever enabled, pad **after** compress.

### 5.1 FUSE adapter API

```rust
// blindkey-fuse (or cli feature)
pub fn mount(volume: Volume, mountpoint: &Path, opts: MountOpts) -> Result<MountGuard>;
// MountGuard: Drop → umount + volume.close()
```

Map `fuser::Filesystem` methods → `Volume::{getattr,readdir,read,write,…}`. No crypto outside
`Volume`.

### 5.2 Mount providers (MNT mount_planes)

| Platform | Preferred | Notes |
|----------|-----------|-------|
| Linux | FUSE via `fuser`; fusermount user mount | Prefer userspace; **document when admin is required** |
| macOS | macFUSE 5 `-o backend=fskit` (**15.4+**); Fuse-T NFS/SMB (older); Fuse-T native FSKit **macOS 26+ only** | Avoid kext as hard v1 requirement; budget Fuse-T **commercial embed license**; notarize GUI |
| macOS degraded | WebDAV localhost | Cryptomator-class — weaker semantics/perf (**fallback only**, MNT-12) |
| macOS stopgap | `hdiutil` encrypted sparsebundle | Opaque Apple crypto — **not** Blindkey core |
| Windows (future) | **WinFsp** | **Dokany forbidden** as primary (MNT-09) |

**FUSE hygiene (MSV-23 / MSV-25):** handle TOCTOU races; no plaintext spill to log paths; on
umount clear page-cache cleartext where the platform allows.

---

## 6. Mount lifecycle

```
create ──▶ .vltd on disk (locked)
open/unlock ──▶ Volume in memory (keys mlock'd)
mount ──▶ FUSE session (OS sees cleartext tree)
  │         sleep/lock policy may auto-umount (MNT-04b)
  ▼
umount ──▶ end FUSE; Volume.sync?; Volume.close (zeroize)
```

| Event | Behavior |
|-------|----------|
| Auth failure | Uniform `VOLUME_OPEN_ERROR`; no partial mount |
| Bit-flip / bad tag | Fail closed; no cleartext spill |
| Rollback vs local anchor | Fail closed (unless `trust-anchor` after explicit confirm) |
| App lock-on-blur (GUI) | No **new** mount while locked; in-flight create may finish/cancel |
| Process crash | Keys in mlock; core dumps disabled (`RLIMIT_CORE=0` / MSV-21); document swap residual (MSV-22) |
| Sleep / screen-lock | UX policy may auto-umount (MNT-04b); not crypto theater |

**Cloud policy (C73 / MNT-02):** Live RW mount + Dropbox/Drive/iCloud/Syncthing on the **same**
`.vltd` is **UNSUPPORTED**. If path under known sync root → warn/refuse; always point to
`blindkey seal`. Do not market live sync.

---

## 7. CLI surface (clap)

```
blindkey volume create PATH.vltd --size SIZE [--max-size SIZE] [--block-size-kib 32]
blindkey volume mount  PATH.vltd [MOUNTPOINT]
blindkey volume umount PATH.vltd|MOUNTPOINT
blindkey volume resize PATH.vltd --size SIZE
blindkey volume status PATH.vltd|MOUNTPOINT
blindkey volume trust-anchor PATH.vltd     # MSV-19 explicit trust on new device
blindkey peek PATH.vltd                    # kind-dispatch: .vltf archive | .vltd tree
blindkey --vault PATH.vltd upgrade-kdf …
blindkey stanzas … PATH.vltd
blindkey --vault PATH.vltd enroll …
```

**Implementation notes (`blindkey-cli`):**

- Add `Command::Volume` alongside `Seal`/`Open`/`Peek` in `commands/mod.rs`.
- Extend `peek` magic dispatch: `MAGIC_VLTF` → sealed peek; `MAGIC_VLTD` → volume list.
- Passwords: TTY / `--password-fd` / `BLINDKEY_PASSWORD_FILE` only (C31).
- Exit codes: extend UC-04/G0.8 table; reuse existing codes where semantics match.
- New module: `commands/volume.rs` (mirror `commands/sealed.rs`).

---

## 8. Desktop GUI (`blindkey-gui`) & TUI

Follow UC-18/20/21: thin egui shell; all crypto in core.

| Screen / action | Behavior |
|-----------------|----------|
| Create Volume wizard | Path, size, max, passphrase×2, stanza pickers (UC-21), Padmé shown default-on |
| Mount | Unlock flow → pick mountpoint → spawn mount → residual-risk banner (once/session) (MNT-04 / MNT-C27) |
| Eject | Umount + Finder parity (MNT-06b) |
| Progress | Worker thread + cancel (`VolumeIoOpts`); `request_repaint` (UC-20); ~0% CPU idle |
| Sleep auto-lock | App lifecycle / launchd policy (MNT-04b / MNT-06b) |
| Cloud folder picked | CTA → Seal dialog (UC-23); do not mount as “synced vault” (C73) |
| TUI | Optional create progress gauge; mount still CLI-primary on headless |

**Banner copy (normative intent):** mounted files are readable by the OS and by any agent with
filesystem access — same class as unlocked FileVault. Not a daily nag after acknowledge.
GUI calls the **same** `blindkey-core` APIs as CLI — Create / Mount / Eject only; never
reimplement crypto (MNT-06 / UC-18 / C45).

### 8.1 Falsifiable claims (PRD / MSV claims_*)

**Allowed:** offline IND-CPA under stated AEAD; detects block modification (INT-CTXT + tree);
detects rollback when local anchor intact; no plaintext names/sizes/tree when locked (Padmé
bucket only); password wrap resists partitioning-oracle speedups via key commitment; no network /
telemetry in mount path.

**Forbidden marketing:** immune to evil maid/DMA; hides access patterns; plausibly deniable;
“stronger than AES because three ciphers”; VeraCrypt-compatible; “stronger bulk cipher than CryFS”
(win = Kcom + Padmé + stanzas + IVD).

---

## 9. Libraries & Cargo features

| Dep | Where | Role |
|-----|-------|------|
| Existing: `chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`, `zeroize`, `subtle` | core | Required |
| `blake3` | core (optional feature `volume`) | Merkle (or HMAC-SHA-256 first to avoid new dep — prefer HMAC v1, blake3 later) |
| `aes-gcm-siv` | core feature | NMR wrap **only with Kcom** |
| `fuser` | `blindkey-fuse` / cli feature | Linux mount |
| Fuse-T / macFUSE | packaging | macOS; commercial license if embedding Fuse-T |
| `libaegis` | optional later | AEGIS-256 profile |
| `luks-core` | never linked | Reference only |

**v1 recommendation:** Merkle via **HMAC-SHA-256** (already in tree) to minimize Gate-0 deps;
document blake3 as optional speed upgrade ADR.

---

## 10. Constraint mapping

| ID | Requirement | Implementation hook |
|----|-------------|---------------------|
| C67 | Distinct magic/UC; Gate-0 | `MAGIC_VLTD`, `ContainerKind::Volume`; no UC-23 API creep |
| C68 | Fixed AEAD blocks; no XTS-only/XCB/cascades | `volume::block`; deny XTS paths in review |
| C69 | Explicit Kcom | wrap recipe + verify before accept master key |
| C70 | Merkle + local freshness | header root + `volume-anchors/` |
| C71 | Locked metadata + Padmé | opaque blocks; `PadMode::Padme` default |
| C72 | Mount hygiene | `fuser`/FSKit; zeroize on close; banner/docs; no network |
| C73 | No live cloud sync | docs + CLI warn + GUI Seal CTA |
| C74 | Hostile parse | fuzz target; uniform errors; fail-closed |
| C1–C3, C5, C7, C11, C23, C30–C32 | reused | existing modules |
| C61 tension | new payload kind | sealed STREAM path untouched; volume = STREAM-per-block class |
| SC10 | C27 vs mounted cleartext | banner + docs; no “model-blind Finder” claim |

---

## 11. Test plan

| Suite | Location (planned) | Covers |
|-------|--------------------|--------|
| Unit block AEAD / Kcom / merkle | `crates/blindkey-core/src/volume/` | C68–C70 |
| Format parse bounds | `volume` + `fuzz/volume_block_parse` | C74, C30 |
| Create/open round-trip | `tests/volume_roundtrip.rs` | C67, C71 |
| Joint satisfaction | `tests/uc25_joint_satisfaction.rs` | C67–C74 one artifact |
| Constraint tags | `tests/volume_constraints.rs` (`c67_*`…) | index like UC-23 |
| CLI | `blindkey-cli/tests/volume_cli.rs` | verbs, peek dispatch, cloud warn |
| GUI | `blindkey-gui/tests/uc25_constraints.rs` | worker/cancel, banner |
| Mount (Linux CI) | `blindkey-fuse` integration if FUSE available | mount/umount smoke |
| macOS mount | manual / HITL Phase C | FSKit / Fuse-T |

**Joint test (IVD):** create → write tree → umount → bit-flip block → open fails uniformly;
rewind body vs anchor fails; Padmé bucket equality; Kcom mismatch fails; strace no network.

---

## 12. Rollout (phased — file-level)

| Phase | Deliverables | Gate |
|-------|--------------|------|
| **Gate-0** | Intent G17 C67–C74 (**v1.9.1+**) + this spec **Accepted** + ADR for magic/`VLTD` | Spec **Accepted 2026-07-21**; magic **ADR-0007 Accepted**; remaining ADRs (merkle / mount / macOS) before A2+ |
| **A1** | `MAGIC_VLTD`, `ContainerKind::Volume`, header branch | Lane A |
| **A2** | `volume/` create/open, Kcom wrap, dual header, Padmé | Lane A |
| **A3** | Block store + virtual FS ops + merkle + local anchor | Lane A |
| **A4** | Fuzz target + `uc25_joint_satisfaction` | Lane A |
| **B1** | CLI `volume` + `peek` dispatch | Lane B |
| **B2** | Linux `fuser` mount (`blindkey-fuse` or feature) | Lane B |
| **C1** | macOS provider + license check | Lane B + packaging |
| **C2** | GUI wizard / Mount / Eject / banner | Lane B; design review by A |
| **D** | Docs (`FILE_FORMAT` pointer, THREAT_MODEL residual, CLI.md); benches: random **4K** R/W + sequential — honest “FUSE loses to dm-crypt” (MNT-22); compaction lessons (MNT-23) | Release |

**ADRs required before payload freeze:** mount crate vs feature; merkle HMAC vs blake3;
macOS provider choice. Magic/extension: **ADR-0007** (done); merkle **ADR-0008** (HMAC-SHA-256);
mount crate **ADR-0009** (`blindkey-fuse`); macOS matrix **ADR-0010** (all Accepted).

### 12.1 Benchmarks (honest — MNT-22)

Target microbenchmarks for the volume data plane: **random 4 KiB read/write** and **sequential
read/write** against the AEAD block store (`blindkey-core::volume`), plus mount-path overhead once
FUSE lands. **Honest expectation:** a userspace-FUSE volume **loses to kernel dm-crypt** on both
latency and throughput — the context-switch per FUSE op and per-block AEAD dominate. Blindkey's win
is **not** raw speed; it is the composed metadata posture (Kcom + Padmé + stanzas + local freshness
+ IVD), portability (no kext), and the same audited crypto path as `.vlt`/`.vltf`. Do **not** market
volume throughput as competitive with block-layer FDE. Bench harness is a Phase-B deliverable; until
then this section is the recorded expectation. Compaction lessons (MNT-23): fixed-block rewrite cost
grows with volume size — document, do not hide.

### 12.2 macOS provider — decided

Per [ADR-0010](../adr/0010-volume-macos-mount-matrix.md) (Accepted, **decided 2026-07-21**):
**do not embed/redistribute Fuse-T commercially** in Blindkey.app without a cleared license; prefer
**macFUSE FSKit on macOS 15.4+**; **no kext is a v1 hard requirement**. Until legal clears Fuse-T,
depend on the user's own macFUSE/Fuse-T install rather than bundling a Fuse-T binary.

---

## 13. Open questions

**Closed (2026-07-21 full cross-check audit):**
1. ~~Hard-forbid vs warn when `.vltd` under Dropbox/Drive~~ → **warn/refuse** when sync root
   detectable; always document unsupported + Seal CTA (C73 / §6). Hard-delete of user files ≠ product.
2. ~~Accept XTS for marketing?~~ → **No** (research/patterns / C68).
3. ~~Extension bikeshed (`.vltd` vs `.vltv`)~~ → **`.vltd`** + magic **`VLTD`** frozen in
   [ADR-0007](../adr/0007-volume-magic-vltd.md).

**Still open (Gate-0 / Phase B packaging — not crypto blockers):**
1. Folder mount vs `/Volumes` disk UX (folder = Family B+ default; `/Volumes` via provider caps)
2. macOS minimum packaging (FSKit ≈15.4+ vs Fuse-T NFS/SMB for older — both allowed; pick ship matrix)
3. Default max size / compaction product defaults
4. Ship AEGIS profile at v1 vs XChaCha-only first (intent: XChaCha default; AEGIS optional)
5. `trust-anchor` UX polish on second machine

---

## 14. Relationship to UC-23

| | UC-23 `.vltf` | UC-25 `.vltd` |
|--|---------------|---------------|
| Module | `blindkey-core::sealed` | `blindkey-core::volume` |
| Cloud | Primary | Unsupported while RW-mounted |
| Access | seal → open whole archive | mount ↔ virtual FS |
| Shared | Header/stanzas, Argon2id, Padmé, fail-closed, thin GUI |

Workflow: edit in volume locally → `blindkey seal` snapshot for cloud. Never Dropbox a live mount.

---

## 15. Beyond v1

1. CryFS IND-aCCFA proof adaptation  
2. Standardized committing AEAD crate  
3. HCTR2++ only if length-preserving needed  
4. woORAM / Shufflecake = separate product  
5. Formal verify AEAD glue  
6. MSV-26 paranoid: HCTR2/Adiantum inside block before AEAD  

---

## 16. Docs updates when shipping

| Doc | Change |
|-----|--------|
| [ARCHITECTURE.md](../ARCHITECTURE.md) | Add `volume/` + optional fuse crate to diagram |
| [FILE_FORMAT.md](../FILE_FORMAT.md) | Link “Volume format → UC-25 §4” (or sibling `FILE_FORMAT_VOLUME.md`) |
| [CRYPTO.md](../CRYPTO.md) | MSV block AEAD + Kcom note |
| [CLI.md](../CLI.md) | `volume` / `peek` on `.vltd` |
| [THREAT_MODEL.md](../THREAT_MODEL.md) | Mounted cleartext residual + L5–L6 |
| [CONSTRAINT_INDEX.md](../CONSTRAINT_INDEX.md) | C67–C74 PASS when tests land |

---

## 17. Cross-check log

| Date | Against | Result |
|------|---------|--------|
| 2026-07-21 | Research + patterns | Gaps closed in v0.2 |
| 2026-07-21 | Patterns ↔ PRD | Gaps closed in v0.2 |
| 2026-07-21 | Blindkey OSS architecture (`sealed`, ARCHITECTURE, FILE_FORMAT) | **v0.3** — full implementation contract |
| 2026-07-21 | **Full requirements ↔ tech spec** (PRD §5 + C67–C74 + MNT/MSV patterns) | **v0.4** — see §18; closed mount-provider, hygiene, claims, resize API, iXTS/Dokany/WebDAV/scrypt/rage, merkle verify, benches |
| 2026-07-21 | **Full audit** research ↔ patterns ↔ PRD ↔ tech spec ↔ intent | **v0.5** — closed AAD `kind` (was research `tree_level`), block-size class, CryFS comparison wording, PRD CLI `trust-anchor` + constraint counts, cloud warn/refuse + `.vltd` extension decisions, CONSTRAINT_INDEX § pointer, mount binary naming |
| 2026-07-21 | **Gate-0 — Accept** | Spec status **Draft → Accepted v0.5**; remaining Gate-0 = magic/`VLTD` ADR (+ merkle / mount / macOS ADRs) |
| 2026-07-21 | **Gate-0 — ADR-0007** | Magic `VLTD` + extension `.vltd` frozen; A1 consts ratified |

---

## 18. Requirements ↔ tech spec traceability (v0.5)

### 18.1 PRD §5 UC-25

| PRD requirement | Spec location |
|-----------------|---------------|
| Local-only; L0–L4; not Dropbox live-sync; warn/refuse + Seal CTA | §1 framing, non-goals, §6 cloud policy, §13 closed |
| MSV: AEAD blocks, Merkle, freshness, Padmé, Argon2id, **explicit key commitment**, stanzas | §1 goals, §4, §8.1 |
| Composition win vs CryFS = Kcom+Padmé+stanzas+IVD (not stronger bulk cipher) | §1 goals, §8.1 claims_forbidden |
| XChaCha default; optional AEGIS-256 | §4.2, §5 `AeadProfile`, §9 |
| Never naked XTS/XCB; no cascade theater | §1 non-goals, §10 C68 |
| GCM-SIV alone ≠ commitment | §1 goals, §4.3 wrap note, C69 |
| CLI `volume create\|mount\|umount\|resize\|status\|trust-anchor` + `peek` | §7 |
| Extension `.vltd` + magic `VLTD` ([ADR-0007](../adr/0007-volume-magic-vltd.md)) | §2.2, §4, §13 closed |
| GUI Create/Mount/Eject; residual-risk banner; UC-18 thin shell | §8 |
| FUSE / macFUSE-FSKit / Fuse-T; no kext hard-req; Fuse-T commercial license | §5.2, §9 |

### 18.2 Intent C67–C74

| ID | Spec hooks |
|----|------------|
| C67 | §2.2 magic/`ContainerKind`; §1 MNT-01; Gate-0 §12 |
| C68 | §4 blocks; §1 forbids XTS/XCB/cascades; §10 |
| C69 | §4.3 Kcom; wrap recipe; §8.1 claims |
| C70 | §4.4 anchor; merkle; fail closed; MSV-19 trust-anchor |
| C71 | opaque blocks; Padmé default; `--no-pad` |
| C72 | §5.2 userspace; §6 zeroize; banner; no telemetry |
| C73 | §6 cloud policy; GUI Seal CTA |
| C74 | fuzz; `VOLUME_OPEN_ERROR`; fail-closed |
| SC10 | §8 banner; no model-blind Finder claim |

### 18.3 Pattern IDs → sections

| IDs | Where encoded |
|-----|----------------|
| MNT-01…04d | §1, §6, §8 banner, MNT-04d header |
| MNT-05…05c | §1 Family B+ / no mkfs / iXTS later |
| MNT-06 / 06b | §8 capability matrix + sleep policy |
| MNT-07…09 | §1 non-goals; §5.2 Dokany; §9 luks-core |
| MNT-10…15 | §3 prior art; §4.3 rewrap; rage/gocryptfs/CryFS notes |
| MNT-16…23 | §4 container; §5 resize; §7 CLI; §12 Phase D benches/compaction |
| MNT-C1…C61 | §1 AEAD; §3 scrypt note; §10 C61 tension; §8 C27 residual |
| MSV-01…09d | §1 ladder + non-goals |
| MSV-10…19 | §4–§6 techniques; trust-anchor |
| MSV-20…26 | §5.2 TOCTOU/page-cache; §5 rules secure free; §9 license; §15 MSV-26 |
| MSV claims_* / beats | §8.1 |

**v0.4 gap closures (were missing or only implied in v0.3):** mount provider version matrix +
WebDAV/Dokany/WinFsp; FUSE TOCTOU + page-cache + secure free; compression default-off; merkle
verify on metadata + periodic data path; `Volume::resize`; Family B+/no-mkfs; iXTS later;
scrypt-not-KDF; rage-mount non-equivalence; falsifiable claims; 4K bench honesty; MNT/MSV ID
traceability table.

**v0.5 gap closures (full-surface audit):** AAD field `kind` (research had stale `tree_level`);
block plaintext class 16–32 KiB; CryFS comparison wording; PRD CLI `trust-anchor` +
66+8 constraint arithmetic; cloud = warn/refuse + Seal CTA; extension `.vltd`; CONSTRAINT_INDEX
section pointer; mount = `blindkey volume` + `blindkey-fuse` (not `blindkey-volume` binary).
