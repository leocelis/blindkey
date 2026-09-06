# Live encrypted volumes (PGP Disk / VeraCrypt class) — Research

> **Task:** Full technical survey — architectures, best practices, open-source libraries,
> official documentation, and academic literature — for adding a **live mountable encrypted
> volume** to Blindkey (CLI + macOS app): create a container, mount it, add/edit files, unmount
> → ciphertext only. Distinct from shipped UC-23 sealed archives (`seal`/`open`/`peek`).
>
> Research date: **2026-07-21**. Sources: VeraCrypt / LUKS2 / Cryptomator / CryFS / gocryptfs /
> age / Apple Disk Utility & FSKit / NIST / IEEE / IACR ePrint / QuarksLab–OSTIF audit /
> Blindkey intent + UC-23 (prior non-goal) + **UC-25** (this feature's requirements). Markers: ✓ verified against primary source ·
> ~ inferred/corroborated · ? unverified (do not treat as load-bearing without re-check).
>
> **Companion docs:** [`encrypted_cloud_storage_research.md`](encrypted_cloud_storage_research.md)
> (seal-vs-live cloud survey),
> [`volume_working_copy_research.md`](volume_working_copy_research.md)
> (checkout / checkin on a sync-folder brick — UC-30),
> [`encrypted_volume_maximum_security_research.md`](encrypted_volume_maximum_security_research.md)
> (**security-maximal crypto / algorithm study — read that for “most secure ever”**),
> [`docs/specs/UC-23-sealed-file-storage.md`](../docs/specs/UC-23-sealed-file-storage.md)
> (explicit non-goal: FUSE / live mount),
> [`docs/specs/UC-25-local-encrypted-volume.md`](../docs/specs/UC-25-local-encrypted-volume.md)
> (**requirements / PRD use case for this feature**), Blindkey intent C1–C74.
>
> **Patterns:** distilled privately as `encrypted_volume_mount_patterns.yaml` +
> `encrypted_volume_maximum_security_patterns.yaml` (operator patterns tree — not in this
> public repo).

---

## 0. Executive finding (read this first)

The PGP Disk / VeraCrypt UX is a **different product surface** from Blindkey’s shipped
`.vltf` seal/open pipeline. It requires a **mount layer** (block device or userspace FS) plus
a **random-access crypto layer**. UC-23 deliberately rejected live mount for cloud sync and
metadata reasons; that rejection still holds for **synced** volumes. A **local-only** live
volume is architecturally feasible and well-supported by OSS + standards — but it forces hard
choices that conflict with Blindkey’s current crypto posture (AEAD STREAM, zero plaintext
metadata, no custom primitives, C3 audited-libs-only).

**ONE recommended architecture for Blindkey** (if this feature is scoped later):

> **Maximum Security Volume (MSV)** — see
> [`encrypted_volume_maximum_security_research.md`](encrypted_volume_maximum_security_research.md):
> CryFS-class **fixed-size AEAD blocks** (XChaCha20-Poly1305 or AEGIS-256; **never** naked
> AES-XTS / **never** XCB — broken 2024) + Merkle/MAC tree + local freshness anchor + Padmé +
> Argon2id with **explicit key commitment** (not GCM-SIV alone) + Blindkey stanzas. Mount via
> **macFUSE-FSKit / Fuse-T** (macOS; Fuse-T native FSKit = macOS 26+) and **FUSE/`fuser`**
> (Linux). Keep **UC-23** for cloud upload. “Better than VeraCrypt” means **composition**
> (integrity + metadata + rollback + Kcom), not a new cipher.

Rationale and alternatives are in §8–§10; algorithm proofs and threat ladder are in the
maximum-security companion.

---

## 1. Problem statement — what “PGP Disk / VeraCrypt-like” means

### 1.1 User-visible capability

| Step | Expectation |
|------|-------------|
| Create | Allocate a container (file or growable sparse image) with passphrase / key factors |
| Mount / unlock | Appears as a normal volume or folder in Finder / shell |
| Use | Copy, edit, create files with ordinary apps; OS filesystem semantics |
| Unmount / lock | Container is opaque ciphertext again; no plaintext residue on disk |

✓ This matches **PGP Virtual Disk** (Symantec Encryption Desktop / PGP Encryption Desktop):
a single file (historically `.pgd`) that mounts as a virtual hard disk; lock anytime without
affecting the rest of the machine. Source: Broadcom KB [153500](https://knowledge.broadcom.com/external/article/153500)
and Encryption Desktop user guides (AES-256 default among CAST5 / Twofish options).

✓ This matches **VeraCrypt file containers**: encrypted volume-as-file, mount → OS filesystem
inside (exFAT/FAT/NTFS/…), XTS sector encryption after header unlock. Official:
[Encryption Scheme](https://veracrypt.io/en/Encryption%20Scheme.html),
[Header Key Derivation](https://veracrypt.io/en/Header%20Key%20Derivation.html).

### 1.2 What it is *not*

| Pattern | Shipped in Blindkey? | Relation |
|---------|----------------------|----------|
| Seal folder → one `.vltf` → extract later | ✓ UC-23 | Archive / one-shot; **no live mount** |
| Credential vault `.vlt` | ✓ core product | Secrets entries, not a filesystem |
| Whole-disk / OS boot encryption | ✗ | VeraCrypt system encryption / BitLocker / FileVault — out of scope |
| Cloud live-sync of a mounted volume | ✗ (and should stay ✗) | Sync + live write = corruption / metadata leak class |

### 1.3 Capability axes (must decide independently)

1. **Container shape:** monolithic sparse file vs directory of ciphertext objects.
2. **Crypto mode:** length-preserving sector cipher (XTS) vs AEAD with expansion.
3. **Mount plane:** kernel block map (dm-crypt / loop) vs userspace FS (FUSE / FSKit / WebDAV).
4. **Host FS inside:** reuse OS FS (format after decrypt) vs custom encrypted FS layout.
5. **Threat:** offline thief of the container file vs active adversary who can mutate ciphertext
   while “synced” or while mounted.

Live local use mainly needs (1)–(4) for offline thieves. Cloud sync of a live volume needs (5)
and usually loses; UC-23 already documented that.

---

## 2. Architecture taxonomy

Three families dominate the industry. Blindkey must pick **one primary family**.

```
                    ┌─────────────────────────────────────────┐
                    │         User sees a volume/folder         │
                    └───────────────────┬─────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              ▼                         ▼                         ▼
     A. Block device              B. Encrypted overlay         C. OS-native
        encryption                   filesystem                  disk image
     (VeraCrypt/LUKS/             (Cryptomator/gocryptfs/      (hdiutil sparsebundle,
      dm-crypt)                    CryFS/rclone crypt)          APFS encrypted)
              │                         │                         │
     Decrypt sectors →             Decrypt files/blocks →      Apple/Windows owns
     host formats FS               present virtual tree         crypto + mount
```

### 2.1 Family A — Block-device encryption (VeraCrypt / LUKS / PGP Disk)

**Shape:** One container file (or partition). Header holds KDF + wrapped master keys. Payload
is a sequence of fixed-size sectors encrypted with a **tweak** = sector number.

**Unlock path (VeraCrypt, official):**

1. Read volume header (64 KiB region; effective header 512 B + salt).
2. Derive header keys from password (+ keyfiles / PIM) via PBKDF2-HMAC or **Argon2id**
   (non-system volumes). ✓ Official: Argon2id derives a **fixed 192 bytes** of header key
   material then takes a prefix (AES-XTS uses first 64 B); default Argon2id ≈ PIM 12
   (**416 MiB**, **6** iterations, parallelism **1**).
3. Decrypt header in XTS; validate; extract **master keys** (immutable for life of volume;
   password change = re-encrypt header only).
4. Map decrypted sector stream as a block device; OS mounts a normal filesystem.

✓ Sources: [veracrypt.io Encryption Scheme](https://veracrypt.io/en/Encryption%20Scheme.html),
[Header Key Derivation](https://veracrypt.io/en/Header%20Key%20Derivation.html).

**LUKS2 (Linux standard):** Binary header + JSON metadata + keyslot area (primary + secondary
headers). Default cipher `aes-xts-plain64`, key size 512 bits (= AES-256-XTS). Keyslots:
Argon2id / Argon2i / PBKDF2. Implementation: `cryptsetup` + kernel `dm-crypt`. Spec:
[LUKS2 on-disk format](https://gitlab.com/cryptsetup/LUKS2-docs) (v1.1.4, 2025-06-16 cited
in cryptsetup docs). Academic root: Clemens Fruhwirth, *New Methods in Hard Disk Encryption*
(LUKS design).

**Pros:** Random access, OS-native FS features, mature tooling, familiar UX.
**Cons:** Classic XTS = **confidentiality only, no authenticity** (see §4). Monolithic file
hurts cloud sync. Kernel/driver or privileged loop setup on some platforms.

### 2.2 Family B — Encrypted overlay filesystem (Cryptomator / gocryptfs / CryFS)

**Shape:** Directory of ciphertext objects (or flat block pool). A FUSE/WinFsp/WebDAV layer
presents a cleartext tree.

| Tool | Content crypto | Name/metadata | Integrity vs active adversary |
|------|----------------|---------------|-------------------------------|
| **Cryptomator** | AES-GCM chunks (vault format ≥1.7) | AES-SIV names; flattened dir IDs | Chunk tags; sizes/counts still leak |
| **gocryptfs** | AES-256-GCM 4 KiB | AES-EME names | ✓ Hornby 2017: strong vs *passive*; **no** security vs active ciphertext modifier |
| **CryFS** | Fixed-size blocks, AEAD (**XChaCha20-Poly1305** default — ✓ cryfs.org) | Structure hidden in block graph; scrypt for config KDF | Peer-reviewed model ([eprint 2017/773](https://eprint.iacr.org/2017/773)) |
| **securefs** | Content+names; optional size padding | — | Thinner ecosystem |

✓ Cryptomator architecture: [docs.cryptomator.org/security/architecture](https://docs.cryptomator.org/security/architecture/),
[vault cryptography](https://docs.cryptomator.org/security/vault/). Mount backends: WinFsp /
macFUSE / FUSE; WebDAV fallback; Dokany deprecated (1.7.0 blog).

✓ CryFS: fixed-size encrypted blocks with random IDs → hides sizes + tree; trade-off large-file
performance. Formal framework + construction: Messmer et al., DBSec 2017 / ePrint 2017/773.

**Pros:** Incremental sync friendlier; can use AEAD naturally; no kernel block driver.
**Cons:** Metadata leakage (Cryptomator/gocryptfs) unless CryFS-class; FUSE dependency hell on
macOS; performance below raw block crypto.

### 2.3 Family C — OS-native encrypted disk images (macOS sparsebundle)

**Shape:** `.sparsebundle` / `.sparseimage` created by Disk Utility / `hdiutil`, APFS
(Encrypted) or older HFS+, AES-128/AES-256 options.

```bash
hdiutil create -size 5g -type SPARSEBUNDLE -fs APFS \
  -encryption AES-256 -volname SecureDocs ~/SecureDocs.sparsebundle
hdiutil attach ~/SecureDocs.sparsebundle   # password prompt
hdiutil detach /Volumes/SecureDocs
```

✓ Apple Support: [Create a disk image using Disk Utility](https://support.apple.com/guide/disk-utility/create-a-disk-image-dskutl11888/mac).
Practitioner detail: Eclectic Light (sparsebundle quirks, `hdiutil compact` / `resize`).

**Pros:** Best Finder UX; no third-party kext; Apple maintains crypto/mount.
**Cons:** Opaque crypto (not Blindkey-constrained); not portable to Linux/Windows as Blindkey
ciphertext; hard to attach Blindkey stanzas (YubiKey / age-style envelope) without wrapping;
App Store / notarization still needed for a GUI that shells out to `hdiutil`.

---

## 3. Prior art deep dive

### 3.1 PGP Virtual Disk (historical product definition)

- Container file; mounts as drive letter / volume; AES-256 default.
- Multi-user unlock (passphrase or key) documented in Encryption Desktop guides.
- Explicit limits (Broadcom KB): not whole-disk; not multi-writer network share (remote =
  read-only).
- Closed source; useful as **UX reference**, not as an implementation to clone.

### 3.2 VeraCrypt

| Topic | Fact | Marker |
|-------|------|--------|
| Mode | XTS for data + header (new volumes); LRW/CBC legacy decrypt only | ✓ official docs |
| Ciphers | AES, Serpent, Twofish, Camellia, Kuznyechik + cascades | ✓ |
| KDF | PBKDF2-HMAC (several PRFs); Argon2id for non-system volumes (recent) | ✓ |
| Hidden volumes | Plausible deniability feature; historically fragile (e.g. GHSA on quick-format) | ✓ |
| Audit | QuarksLab / OSTIF 2016 (v1.18): 8 critical / 3 medium / 15 low; mostly fixed in 1.19 | ✓ [OSTIF PDF](https://ostif.org/wp-content/uploads/2016/10/VeraCrypt-Audit-Final-for-Public-Release.pdf) |
| macOS | User-space / FUSE-era packaging historically painful; not a “pure App Store” story | ~ |
| Cloud sync | Monolithic container + live write = full re-upload / corruption reports | ✓ prior Blindkey survey |

### 3.3 LUKS2 + dm-crypt

- Industry default on Linux; JSON metadata; multi-keyslot; tokens (FIDO2, TPM, keyring).
- Optional **authenticated** path: `cryptsetup luksFormat --integrity …` (dm-integrity /
  HMAC) — length expansion, detects sector tampering. ✓ cryptsetup man pages.
- Cross-platform *format* is generic; *mount* needs dm-crypt (Linux) or userspace decryptors
  (`luks-core` Rust crate can unlock and read sectors without root — see §6).

### 3.4 Cryptomator / gocryptfs / CryFS (already surveyed for UC-23)

Reuse [`encrypted_cloud_storage_research.md`](encrypted_cloud_storage_research.md) §2.1.
For **local** PGP-Disk UX, Cryptomator is the closest “open vault folder in Finder” experience;
CryFS is the closest **metadata-private** design with a proof; gocryptfs is fastest Linux
throughput but admits active-adversary weakness in its audit narrative.

### 3.5 age / rage

- Not a volume; streaming file encryption.
- ✓ **`rage-mount`** (optional Cargo feature `mount`): FUSE-mounts an **age-encrypted TAR or
  ZIP** as a **read-only** directory — Unix/`libfuse` only
  ([rage-mount(1)](https://man.archlinux.org/man/rage-mount.1.en),
  [str4d/rage](https://github.com/str4d/rage)). Useful pattern: decrypt-on-read archive mount,
  **not** RW PGP Disk.

---

## 4. Cryptographic layer — standards, limits, Blindkey tension

### 4.1 XTS-AES (IEEE 1619 / NIST SP 800-38E)

- ✓ **NIST SP 800-38E**: approves XTS-AES for storage device confidentiality; **explicitly
  does not provide authentication**. Not for data in transit.
- ✓ Built on Rogaway’s XEX tweakable construction (Asiacrypt 2004).
- ✓ IEEE 1619-2007 / **IEEE 1619-2025**: XTS for block storage; **2025 adds mandatory key-scope
  limits** (max ~2³⁶–2⁴⁴ × 128-bit blocks per key — public discussion:
  Brož–Forgáč–Sedláček, arXiv:2502.18631). Most legacy XTS deployments are non-compliant with
  the new scopes without rekeying strategy.
- Properties: length-preserving, sector-addressable, parallelizable, hardware-friendly
  (AES-NI). Protects against naive cut-and-paste of sectors under some models; **does not**
  detect malicious modification (ciphertext can be rearranged / bit-flipped with controlled
  plaintext effects depending on attack).

**Implication for Blindkey:** adopting naked XTS as the volume data plane contradicts the
project’s “AEAD everywhere / fail-closed on auth failure” story (C1, C9/C10, C64 culture).

### 4.2 Authenticated storage encryption

| Approach | Mechanism | Expansion | Notes |
|----------|-----------|-----------|-------|
| IEEE 1619.1 | CCM, GCM, CBC-HMAC, XTS-HMAC | Yes | Tape / length-expansion devices |
| dm-integrity + dm-crypt | Per-sector checksum / HMAC | Yes | Linux production pattern |
| iXTS (ToSC 2025) | Black-box conversion of XTS engine → randomized AE | Small | Inoue–Minematsu–Ueno–Homma, *How to Implement Authenticated Encryption on XTS-Enabled Devices*, IACR ToSC **2025**(4) — ~n/2-bit AE; useful if forced onto XTS hardware |
| Per-block AEAD (CryFS / Blindkey STREAM) | XChaCha20-Poly1305 / AES-GCM per fixed block | Tag + nonce | Aligns with Blindkey C1 |

### 4.3 What Blindkey already ships (must reuse if possible)

From workspace `Cargo.toml` / intent:

- ✓ XChaCha20-Poly1305 STREAM (C1), Argon2id floor (C2), audited RustCrypto only (C3),
  age-style multi-stanza envelope (C4–C6), HMAC header/blocks (C9/C10), zeroize+mlock (C11),
  model-blind delivery (C27), Padmé (C66 / UC-23).
- ✗ No AES-XTS, no `aes` crate in workspace deps today, no FUSE crate.

**Best practice for Blindkey:** invent **one new payload type** behind the **existing envelope**
(same pattern as `.vlt` vs `.vltf` magic branch), not a second KDF/cipher zoo.

---

## 5. Mount / presentation layers (CLI + macOS)

### 5.1 Linux CLI

| Mechanism | Privilege | Fit |
|-----------|-----------|-----|
| `losetup` + `dm-crypt` / `cryptsetup open` | Often root / CAP_SYS_ADMIN | Family A native |
| FUSE (`libfuse3` + `fuser` crate) | User mount (`fusermount`) | Family B native |
| NBD (network block device) userspace server | Varies | Userspace block backend without writing a kext |
| `udisks` / D-Bus | Desktop integration | Packaging concern |

### 5.2 macOS — critical path for Blindkey GUI

| Mechanism | Status (2026) | Notes |
|-----------|---------------|-------|
| **Apple FSKit** | ✓ Official API; user-space FS modules as app extensions; Mac App Store compatible; **FSUnaryFileSystem** only in current docs | [developer.apple.com/documentation/fskit](https://developer.apple.com/documentation/fskit). macOS **15.4+** for practical use (release notes / community). |
| **macFUSE 5** | ✓ VFS kext (best perf) **or** `-o backend=fskit` | FSKit backend: mounts under `/Volumes` only; some FUSE features missing; slower than kext. Wiki: [FUSE Backends](https://github.com/macfuse/macfuse/wiki/FUSE-Backends). Kext needs Recovery approval — install friction; Homebrew pulled some FUSE dependents over licensing historically. |
| **Fuse-T** | ✓ Kext-less; NFS/SMB backends; **native FSKit on macOS 26+** only (project site) | [fuse-t.org](https://www.fuse-t.org/) — embeddable; App Store–oriented packaging. **Commercial license required to embed/ship in a product** (personal use free). |
| **WebDAV localhost** | Cryptomator fallback | Works everywhere; weaker semantics / perf. |
| **`hdiutil` encrypted sparsebundle** | ✓ Native | Family C; Blindkey as thin UX wrapper only. |
| **DiskArbitration / DiskImages framework** | System | Used by Disk Utility; programmatic attach/detach. |

**Practical macOS recommendation:** Prefer **macFUSE FSKit backend** (15.4+) or
**Fuse-T NFS/SMB** for older macOS; Fuse-T native FSKit only on **macOS 26+**. Avoid
requiring a kext for v1. Budget for Fuse-T **commercial license** if embedding. Treat
`hdiutil` as a **stopgap / macOS-only SKU**, not the cross-platform crypto core.

### 5.3 Windows (out of Blindkey v1 GUI scope, but architecture-relevant)

WinFsp (Cryptomator’s preferred path) / Dokany (deprecated by Cryptomator) / VeraCrypt driver.
If Blindkey ever ships Windows live volumes, **WinFsp** is the industry lesson.

### 5.4 CLI surface sketch (illustrative — not a spec)

```
blindkey volume create PATH.vltd --size 10G
blindkey volume mount  PATH.vltd [/mountpoint]
blindkey volume umount PATH.vltd | /mountpoint
blindkey volume resize PATH.vltd --size 20G   # if sparse
blindkey peek / stanzas / enroll …            # reuse envelope tools with --vault PATH.vltd
```

GUI: “Create Volume” / “Mount” / “Eject” calling the same `blindkey-core` APIs (UC-18 pattern:
UI never reimplements crypto).

---

## 6. Open-source libraries & crates (usable building blocks)

### 6.1 Cryptographic primitives (Rust — Blindkey-aligned)

| Crate / lib | Role | Notes |
|-------------|------|-------|
| `chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`, `zeroize` | Already in Blindkey | Prefer reuse |
| `aes` + `xts-mode` | AES-XTS | Needed only if Family A / LUKS interop |
| `aes-gcm` | AEAD alternative to XChaCha | Hardware AES on Apple Silicon / AES-NI |
| `blake3` / `blake2` | Optional integrity trees | Not in Blindkey core today |

C3 rule: **no hand-rolled ciphers**; stick to RustCrypto / audited crates.

### 6.2 Volume format / unlock

| Project | Language | Use |
|---------|----------|-----|
| **cryptsetup / libcryptsetup** | C | Gold standard LUKS2; GPL — linking into MIT/Apache Blindkey needs license review |
| **`luks-core`** (crates.io) | Rust | Pure-Rust LUKS1/2 unlock + AES-XTS sector I/O; validated vs cryptsetup; **no mount** |
| VeraCrypt source | C++ | Reference only; license/complexity; do not fork into Blindkey |
| Cryptomator cryptofs / siv-mode | Java | Reference for name encryption / chunk AEAD |

### 6.3 Filesystem / mount

| Project | Role |
|---------|------|
| **`fuser`** (Rust) | FUSE server rewrite; implement `Filesystem` trait |
| **polyfuse** / older `fuse` crate | Alternatives; `fuser` is the maintained choice ~ |
| **macFUSE** / **Fuse-T** | macOS providers under FUSE ABI |
| **Apple FSKit** | First-party module API (Swift/ObjC extension) |
| **WinFsp** | Windows analog |
| **nbdkit** / Rust NBD servers | Userspace block device without dm-crypt |

### 6.4 OS image helpers (Family C)

| Tool | Role |
|------|------|
| `hdiutil`, Disk Utility | Create/attach encrypted sparsebundles |
| `diskutil apfs` | APFS volume ops |
| Linux: `mkfs.exfat` / `mkfs.ext4` after loop decrypt | Format inner FS for Family A |

### 6.5 What **not** to use

| Item | Why |
|------|-----|
| EncFS / eCryptfs | Broken / unmaintained under multi-version adversaries |
| Custom XTS “from a blog” | C3 + audit risk |
| Dokany as primary | Cryptomator deprecated it for WinFsp |
| Embedding GPL cryptsetup into Blindkey binary | License conflict unless carefully isolated as optional external CLI |

---

## 7. Academic & standards bibliography (load-bearing)

### 7.1 Disk / storage encryption

| Ref | Contribution |
|-----|----------------|
| Rogaway, *Efficient Instantiations of Tweakable Blockciphers…*, Asiacrypt 2004 | XEX foundation of XTS |
| IEEE Std 1619 (2007 → **2025**) | XTS for block-oriented storage; key scopes in 2025 |
| NIST SP 800-38E (2009) | Approves XTS-AES; **no authentication** |
| IEEE 1619.1-2018 | Authenticated encryption with length expansion (CCM/GCM/CBC-HMAC/XTS-HMAC) |
| Homma / Inoue et al., iXTS, IACR ToSC **2025**(4) | Black-box XTS → AE conversions |
| Fruhwirth, *New Methods in Hard Disk Encryption* | LUKS design basis |
| Brož–Forgáč–Sedláček, arXiv:2502.18631 | Public analysis of IEEE 1619-2025 XTS key scopes |

### 7.2 Encrypted filesystems / cloud adversaries

| Ref | Contribution |
|-----|----------------|
| Messmer, Rill, Achenbach, Müller-Quade, ePrint **2017/773** / DBSec 2017 | CryFS + formal cloud FS security model (metadata + integrity) |
| Amjad–Kamara–Moataz, ePrint 2018/195 | Snapshot adversaries ≈ persistent adversaries (few snapshots) — frames why live+sync is hard |
| Grubbs et al. (CCS / S&P leakage-abuse) | Deterministic encryption / metadata attacks — Blindkey C17 lineage |
| Hornby, gocryptfs audit (2017) | Passive OK / active adversary not — https://defuse.ca/audits/gocryptfs.htm |

### 7.3 Product audits / AEAD commitment (implementation lessons)

| Ref | Lessons for Blindkey |
|-----|----------------------|
| QuarksLab–OSTIF VeraCrypt 2016 | Header/keyfile mistakes, cipher suite footguns, need continuous audit |
| Cure53 Cryptomator 2017 | Scope limits (mobile libs out of scope); AEAD migrations matter |
| Radically Open Security Picocrypt 2024 | Validates XChaCha20-Poly1305 + Argon2id for file containers (aligns with Blindkey) |
| Len–Grubbs et al., USENIX Sec 2021 / ePrint 2020/1491 | Partitioning oracles; AES-GCM / ChaChaPoly **not** key-committing |
| Albertini et al., USENIX Sec 2022 / ePrint 2020/1456 | AES-GCM-SIV also **not** key-committing; padding / explicit Kcom fixes |

---

## 8. Best practices (distilled)

### 8.1 Product / threat

1. **Separate local-live from cloud-sync.** Live RW mounts + Dropbox/Drive on the same
   container file is a known failure mode (VeraCrypt community + FPF guidance for “encrypt
   then upload”). Keep UC-23 for cloud; live volumes = local or USB.
2. **Prefer AEAD data plane** for a greenfield Blindkey volume. If you must speak XTS
   (interop), add integrity (dm-integrity-class tags or iXTS-style expansion) and document
   the expansion.
3. **One master data key; passphrase only wraps.** Same as VeraCrypt/LUKS/Blindkey vault —
   password change must not re-encrypt all sectors if avoidable (header re-wrap).
4. **Multi-factor unlock via Blindkey stanzas** (password + keyfile + YubiKey), not a parallel
   enrollment story.
5. **Fail closed on auth failure**; uniform errors (UC-10 / C64 culture).
6. **Lock on sleep / screen lock** is UX policy (PGP Disk lesson: unlocked volume = cleartext
   to the OS). Document residual risk like FileVault-unlocked state.
7. **No telemetry**; no network in the mount path (C23).
8. **Do not promise plausible deniability** unless willing to own VeraCrypt-class complexity
   and audit surface.

### 8.2 Implementation

1. **Sparse growable containers** with explicit max size (PGP Disk / sparsebundle pattern).
2. **Atomic header updates** (dual headers like LUKS2 / VeraCrypt backup header).
3. **Key zeroization** on umount (already Blindkey C11).
4. **Fuzz** the header + block parsers from day one (C30).
5. **Benchmarks:** random 4K read/write and sequential; FUSE will lose to dm-crypt — set honest
   expectations in docs.
6. **Privilege:** prefer userspace mount; document when admin is required.
7. **macOS packaging:** FSKit / Fuse-T path to avoid kext; notarize GUI; never ship private
   Limitless paths in public docs.

### 8.3 What UC-23 already decided (do not quietly reverse)

From UC-23 §1 non-goals (✓):

> live-synced/mounted folders (FUSE, watch daemons) — sealed-archive model is deliberate…

A new live-volume UC must be an **explicit new use case** with its own constraints, not a
silent expansion of UC-23. Suggested framing: **“local workstation volume”**, adversary =
stolen laptop / stolen USB / offline copy of `.vltd`, **not** malicious sync backend.

---

## 9. Blindkey fit analysis

### 9.1 Constraint tensions

| Blindkey rule | Live volume impact |
|---------------|--------------------|
| C1 XChaCha20-Poly1305 STREAM | Sector XTS would be a **second** data-plane cipher unless volume uses AEAD blocks |
| C3 audited libs only | OK if RustCrypto; not OK if vendoring unverified XTS |
| C17 / C62 zero plaintext metadata | Family A+host FS: **inner** names hidden when locked; Family B Cryptomator-style: **outer** tree leaks; CryFS-style: outer ≈ opaque blocks |
| C27 model-blind | Mounted volume is OS-visible cleartext while unlocked — agents can read files unless brokered separately; document |
| C61 “reuse STREAM for sealed files” | Live volume needs either STREAM-per-block or a justified new mode |
| UC-23 non-goal FUSE | Must be a **new UC**, not UC-23 scope creep |

### 9.2 Architecture options scored for Blindkey

| Option | UX match | Crypto fit | macOS path | Cross-platform | Effort |
|--------|----------|------------|------------|----------------|--------|
| **B+ AEAD blocks (CryFS-class) + FUSE** ★ | High (folder mount) | Best (reuse C1/C2/envelope) | Fuse-T / FSKit | Good | High |
| A+ AES-XTS container (VeraCrypt-like) | Highest (drive letter) | Poor (no AEAD) | Harder (loop/FUSE-block) | Good on Linux | Very high |
| A+ XTS + integrity tags | Highest | Acceptable | Harder | Good | Very high |
| C `hdiutil` wrapper | Highest on Mac only | Opaque | Trivial | Bad | Low |
| Extend `.vltf` with watch daemon | Medium | Good | Medium | Medium | High — still sync-hostile |

★ = recommended (§0).

### 9.3 Capability matrix — CLI vs macOS app

| Capability | CLI | macOS app (`blindkey-gui`) |
|------------|-----|----------------------------|
| Create sparse volume | ✓ primary | Wizard over same API |
| Mount / unmount | ✓ | Menu + Finder eject parity |
| Passphrase / keyfile / YubiKey | ✓ existing stanza UX | GUI prompts (C27: no secret echo) |
| Progress / cancel for format | Optional | Required for large creates |
| Auto-lock on sleep | Policy / launchd helper | App lifecycle + notifications |
| Drag files into volume | OS | OS (once mounted) |
| Cloud upload of **mounted** volume | Document as unsupported | Same |
| Seal instead (`seal`) | Point users to UC-23 | Same |

---

## 10. Recommended design sketch (for a future intent / UC)

Not an implementation plan — a research-backed target shape:

1. **On-disk:** new magic (e.g. `VLTD`, 4-byte peer of `VLTF` — freeze in Gate-0 ADR) sharing Blindkey header/stanza layout with `.vlt` /
   `.vltf`; payload = fixed-size AEAD blocks (CryFS-like graph or simpler extent tree).
2. **KDF / unlock:** identical Argon2id floor + multi-stanza OR model.
3. **Mount:** `blindkey volume mount` (CLI) + optional `blindkey-fuse` crate / `volume-mount`
   feature (`fuser`) decrypting blocks into a virtual POSIX tree; macOS via Fuse-T or FSKit
   wrapping the same `blindkey-core::volume` APIs (no separate `blindkey-volume` product binary).
4. **Non-goals for v1 of the feature:** VeraCrypt format compat, hidden volumes, Windows,
   live cloud sync, boot encryption, GPL cryptsetup linkage.
5. **Docs:** “Local encrypted workspace”; link UC-23 for “upload to Drive”.
6. **IVD:** new constraint group (integrity of blocks, mount-state key lifetime, umount
   zeroize, path traversal on virtual FS, fuzz targets) — Gate-0 before code.

---

## 11. Open questions (need Leo / design decisions before coding)

**Closed (product/intent/UC-25 Draft v0.5 — 2026-07-21 audit):**
1. ~~Local-only vs Dropbox~~ → **unsupported** live RW on sync backends; **warn/refuse** when
   sync root detectable + Seal CTA (C73). Not hard-delete of user files.
2. ~~Accept XTS for marketing?~~ → **No** (C68).
3. ~~Inner filesystem~~ → **virtual POSIX tree** in `blindkey-core` (Family B+); not mkfs+XTS.
4. ~~Mount binary naming~~ → `blindkey volume` + optional `blindkey-fuse` / feature flag.

**Still open (packaging / UX — not crypto blockers):**
1. **Drive letter / `/Volumes` disk UX vs folder mount** — disk UX pushes Family A; folder
   mount fits Family B+ (default).
2. **macOS minimum version** — FSKit reality ≈ 15.4+; older Macs need Fuse-T NFS/SMB backend
   or kext (ship matrix).
3. **Size limits / sparse growth / compaction** — sparsebundle lessons (`hdiutil compact`).

---

## 12. Source index (URLs)

### Official / primary

- VeraCrypt Encryption Scheme — https://veracrypt.io/en/Encryption%20Scheme.html
- VeraCrypt Header Key Derivation — https://veracrypt.io/en/Header%20Key%20Derivation.html
- LUKS2 format docs — https://gitlab.com/cryptsetup/LUKS2-docs
- cryptsetup man — https://man7.org/linux/man-pages/man8/cryptsetup.8.html
- Cryptomator Security Architecture — https://docs.cryptomator.org/security/architecture/
- Cryptomator Vault Cryptography — https://docs.cryptomator.org/security/vault/
- CryFS how it works — https://www.cryfs.org/howitworks
- Apple FSKit — https://developer.apple.com/documentation/fskit
- Apple Disk Utility disk images — https://support.apple.com/guide/disk-utility/create-a-disk-image-dskutl11888/mac
- macFUSE FUSE Backends — https://github.com/macfuse/macfuse/wiki/FUSE-Backends
- Fuse-T — https://www.fuse-t.org/ (FSKit backend: macOS 26+; commercial embed license)
- NIST SP 800-38E — https://csrc.nist.gov/publications/detail/sp/800-38e/final
- IEEE 1619-2025 — https://standards.ieee.org/ieee/1619/11552/
- Broadcom PGP Virtual Disk KB — https://knowledge.broadcom.com/external/article/153500
- rage-mount(1) — https://man.archlinux.org/man/rage-mount.1.en

### Academic / audits

- CryFS ePrint 2017/773 — https://eprint.iacr.org/2017/773
- iXTS ToSC 2025(4) — https://tosc.iacr.org/index.php/ToSC/article/view/12614
- QuarksLab VeraCrypt assessment (OSTIF) — https://ostif.org/wp-content/uploads/2016/10/VeraCrypt-Audit-Final-for-Public-Release.pdf
- Rogaway XEX (Asiacrypt 2004) — http://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf
- gocryptfs audit (Hornby) — https://defuse.ca/audits/gocryptfs.htm
- Partitioning oracles — https://eprint.iacr.org/2020/1491
- Albertini key commitment — https://eprint.iacr.org/2020/1456
- XTS key scopes discussion — https://arxiv.org/abs/2502.18631
- Snapshot adversaries — https://eprint.iacr.org/2018/195

### In-repo

- [`encrypted_cloud_storage_research.md`](encrypted_cloud_storage_research.md)
- [`encrypted_volume_maximum_security_research.md`](encrypted_volume_maximum_security_research.md)
- [`docs/specs/UC-23-sealed-file-storage.md`](../docs/specs/UC-23-sealed-file-storage.md)
- [`blindkey_intent.yaml`](../blindkey_intent.yaml)

---

## 13. Source cross-check log (2026-07-21)

| Claim | Verdict | Fix |
|-------|---------|-----|
| VeraCrypt Argon2id 192 B prefix | ✓ official Header Key Derivation | Added PIM=12 / 416 MiB defaults |
| CryFS default XChaCha20-Poly1305 | ✓ cryfs.org | Clarified; added scrypt KDF |
| rage-mount RO tar/zip | ✓ man page + rage README | Upgraded ~ → ✓ |
| Fuse-T FSKit on “newer macOS” | ✗ imprecise | Corrected: **macOS 26+** native FSKit; commercial embed license |
| macFUSE FSKit | ✓ wiki | Kept 15.4+ |
| iXTS “Homma 2024” | ✗ | Corrected: Inoue–Minematsu–Ueno–Homma, ToSC **2025**(4) |
| IEEE 1619-2025 key scopes | ✓ | Cited Brož et al. arXiv:2502.18631 for public numbers |
| AES-GCM-SIV as key-committing (MSV doc) | ✗ **false** | Fixed in companion (Albertini / Len) |

---

## 14. Changelog

| Date | Note |
|------|------|
| 2026-07-21 | Initial full survey for Blindkey live-volume (PGP Disk / VeraCrypt class) research. |
| 2026-07-21 | Source cross-check: Fuse-T versions/license, VeraCrypt Argon2id defaults, CryFS scrypt, rage-mount ✓, iXTS citation, IEEE key scopes, bib gaps. |
