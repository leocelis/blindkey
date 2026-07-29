# Maximum-security live encrypted volume — Cryptographic deep research

> **Task:** Security-first expansion of
> [`encrypted_volume_mount_research.md`](encrypted_volume_mount_research.md). Goal: define what
> “most secure folder/disk encryption” means **scientifically**, study the **latest algorithms
> and constructions** (official standards + academic papers), and specify a Blindkey design that
> can **beat VeraCrypt / Cryptomator / LUKS-default / gocryptfs** on real threat properties —
> without inventing unaudited primitives (Blindkey C3).
>
> Research date: **2026-07-21**. Markers: ✓ primary source · ~ corroborated · ? unverified.
>
> **Hard rule:** “Something better” = **better composition + stronger threat model coverage**,
> not a hand-rolled cipher. Novel modes fail audits; Blindkey’s edge is constraint-verified
> assembly of **already-proven** building blocks.
>
> **Patterns:** distilled to the private operator patterns tree as
> `encrypted_volume_maximum_security_patterns.yaml` (not shipped in this public repo).
> **Requirements:** [`docs/specs/UC-25-local-encrypted-volume.md`](../docs/specs/UC-25-local-encrypted-volume.md)
> (PRD use case + proposed C67–C74).

---

## 0. Executive security verdict

### What “most secure ever” actually means

Marketing lists of ciphers (AES-Twofish-Serpent cascades) do **not** maximize security.
Security is a **vector of properties** against a stated adversary. The strongest practical
greenfield design today is:

| Property | VeraCrypt default | Cryptomator | CryFS | **Blindkey MSV (proposed)** |
|----------|-------------------|-------------|-------|------------------------------|
| Confidentiality (offline) | ✓ XTS | ✓ AEAD | ✓ AEAD | ✓ AEAD (same class as CryFS) |
| Integrity (active mod) | ✗ | ✓ chunk tags | ✓ | ✓ + tree |
| Freshness / rollback | ✗ | weak | ✓ local versions | ✓ Blindkey-style anchor |
| Metadata (names/sizes/tree) | hidden when locked* | leaks | ✓ fixed blocks | ✓ fixed blocks + Padmé |
| Wide-block diffusion | ✗ (16 B) | N/A | N/A | optional HCTR2 under AEAD |
| Key-commitment (password) | weak / N/A | scrypt + AES-KW (non-committing AE class) | scrypt config | ✓ **explicit** key commitment (not GCM-SIV alone) |
| Cascade theater | optional | — | — | ✗ forbidden |
| Formal FS model | none | none | ✓ IND-aCCFA | target CryFS-class proofs |

\*Inner FS metadata exists after mount; container looks like random when locked.

**ONE recommendation (security-maximal for Blindkey):**

> Build a **Maximum Security Volume (MSV)**: CryFS-class **fixed-size AEAD blocks**
> (XChaCha20-Poly1305 **or** AEGIS-256 as data AEAD; **never** naked AES-XTS / XCB),
> **Merkle / MAC tree** over block tags, **local monotonic freshness anchor** (reuse C16
> posture), **Padmé** on the container, **Argon2id** unlock with **explicit key commitment**
> (Albertini-style `Kcom` or padding fix — **AES-GCM-SIV alone is not enough**), Blindkey
> multi-stanza envelope. Mount via FUSE. Document residual leaks (access patterns, total size)
> honestly. Do **not** invent a new cipher; do **not** clone VeraCrypt XTS.

That composition is strictly stronger than VeraCrypt on integrity + metadata + key-commitment,
and stronger than Cryptomator/gocryptfs on metadata + rollback. Vs CryFS: **same AEAD+blocks
class**; Blindkey wins are **explicit Kcom + Padmé + stanzas + IVD falsifiability** — not a
stronger bulk cipher — while targeting CryFS-class FS proofs.

---

## 1. Threat model ladder (decide how high to climb)

Each rung costs performance, complexity, or UX. “Most secure” must name the rung.

| Rung | Adversary | Required crypto | Practical? |
|------|-----------|-----------------|------------|
| **L0** | Stolen locked container (offline) | Strong KDF + IND-CPA sector/file crypto | ✓ baseline |
| **L1** | Active bit-flip / cut-paste of ciphertext | AEAD or MAC tree (INT-CTXT) | ✓ **must** |
| **L2** | Rollback / fork (serve old blocks) | Local freshness state (CryFS versions / Blindkey C16) | ✓ |
| **L3** | Snapshot cloud adversary (few snapshots ≈ persistent) | Randomize ciphertext; hide structure (Amjad–Kamara–Moataz ePrint 2018/195) | ✓ for sync; MSV local-only skips sync |
| **L4** | Metadata / size / tree leakage | Fixed-size blocks + padding (CryFS, Padmé/PURBs) | ✓ |
| **L5** | Access-pattern leakage (which blocks touched) | ORAM / woORAM | ✗ for interactive desktop (Ω(log n) bandwidth; Shufflecake ePrint 2023/1529) |
| **L6** | Runtime compromised OS / DMA | Beyond software vault | ✗ accept residual |

**MSV target: L0–L4.** L5–L6 documented as out of scope (same honesty as Blindkey threat model).

---

## 2. Attack surface taxonomy (what products fail at)

### 2.1 Confidentiality-only disk crypto (VeraCrypt / classic LUKS / BitLocker-XTS)

- ✓ NIST SP 800-38E: XTS-AES = **confidentiality**, **no authentication**.
- Sector tweak = address → cut-and-paste / bit-flip attacks with predictable effects.
- Cascades (AES-Twofish-Serpent) add **almost no** security against a computational adversary
  if AES is unbroken; they add complexity and audit surface (QuarksLab VeraCrypt 2016 taught
  this with GOST footguns).

### 2.2 Narrow-block vs wide-block

| Mode | Granularity of change | Auth | Status 2026 |
|------|----------------------|------|-------------|
| AES-XTS | 16-byte block | ✗ | Ubiquitous; weak vs active adversary |
| Adiantum / HCTR2 | whole sector (e.g. 4 KiB) SPRP | ✗ | ✓ modern length-preserving |
| EME2-AES (IEEE 1619.2-2025) | wide-block | ✗ | Survives; XCB **removed** |
| XCB-AES | wide-block | ✗ | **BROKEN** (ePrint 2024/1554 shared-difference; ePrint 2024/1527 full recovery — CRYPTO’25 lineage for Wang et al.) |
| AEAD (GCM / ChaChaPoly / AEGIS) | message + tag | ✓ | Needs length expansion |

**Lesson:** Wide-block **without** auth still loses to an active adversary. Wide-block **plus**
auth (or AEAD-only with expansion) is the modern path.

### 2.3 Nonce / keystream misuse

- STREAM / GCM / ChaChaPoly: nonce reuse = catastrophic.
- Disk-friendly synthetic nonce: `nonce = PRF(key_nonce, block_id ‖ version)` or
  AES-GCM-SIV / misuse-resistant modes for wraps.
- Blindkey C1 already regenerates `nonce_prefix` on body writes — MSV must bind block ID +
  version into every AEAD nonce/AAD.

### 2.4 Partitioning oracles / key commitment (password volumes)

✓ Len, Grubbs, et al., USENIX Security 2021 / ePrint 2020/1491: AES-GCM, ChaCha20-Poly1305,
XSalsa20-Poly1305 are **not key-committing**. A decryption oracle can speed password search
via multi-colliding ciphertexts.

✓ Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, USENIX Security 2022 / ePrint 2020/1456:
**AES-GCM-SIV and OCB3 also fail key commitment** — nonce-misuse resistance ≠ key commitment.
They demonstrate practical multi-key ciphertexts and give two fix families: (1) **explicit key
commitment** string derived via collision-resistant PRF alongside the encryption key; (2)
**padding fix** (prepend fixed zero block(s) to plaintext, verify after decrypt) for GCM /
ChaChaPoly-class schemes (ideal-cipher assumptions; analyze per scheme).

**Implication for Blindkey volumes:** passphrase → Argon2id → wrap of volume key **must**
add an **explicit commitment check**. Do **not** treat AES-GCM-SIV as sufficient for
commitment. Recommended stack: AEAD wrap (XChaCha20-Poly1305 or AES-GCM-SIV for *nonce*
hygiene) **plus** Albertini-style `Kcom` stored in the header (or padding fix on the wrapped
key blob). AEGIS is *claimed* stronger on receiver-binding in libsodium/CFRG prose (~) — still
requires an explicit commitment design; FROB caveats apply if AD is adversarial.

### 2.5 Metadata & padding oracles

- Cryptomator / gocryptfs: leak tree shape, sizes, counts.
- CryFS: fixed blocks → only total volume size; config KDF = **scrypt** (✓ cryfs.org); default
  block cipher **XChaCha20-Poly1305**; historical default block size **16 KiB**, docs also say
  “typically 32KB” — treat as tunable (CryFS changelog + howitworks).
- Padmé / PURBs (PoPETs 2019): size channel → O(log log M) bits — Blindkey already ships Padmé
  for `.vltf` (C66).

### 2.6 Plausible deniability

TrueCrypt/VeraCrypt hidden volumes; Shufflecake (ePrint 2023/1529). Multi-snapshot PD ≈ woORAM
cost. **MSV: do not claim PD** unless willing to own that research program.

---

## 3. Algorithm study — candidates for each layer

Study goal: pick **primitives with proofs or standards**, then compose.

### 3.1 Layer A — Password → volume key (KDF)

| Algorithm | Status | Fit |
|-----------|--------|-----|
| **Argon2id** (RFC 9106) | ✓ OWASP / Blindkey C2 | **Required** — memory-hard, hybrid |
| scrypt | Legacy (Cryptomator) | Inferior to Argon2id for new design |
| PBKDF2 | VeraCrypt legacy / LUKS option | ✗ as sole KDF for MSV |
| Balloon, Balloon-SHA256 | Academic | No need if Argon2id |

**Params:** keep Blindkey floor (m ≥ OWASP 19 MiB; Blindkey defaults higher). Tune for
≥100 ms on target hardware without going below floor. Parallelism = cores carefully (C2 ceiling).

### 3.2 Layer B — Key wrap / header encryption (must be committing)

| Algorithm | Auth | Misuse resistance | Key commitment | Fit |
|-----------|------|-------------------|----------------|-----|
| XChaCha20-Poly1305 | ✓ | nonce-respecting | ✗ (partitioning) | OK **with** explicit Kcom |
| AES-256-GCM | ✓ | fragile nonces | ✗ | Avoid for password wraps |
| **AES-GCM-SIV** (RFC 8452) | ✓ | ✓ nonce-misuse resistant | ✗ **not** committing (Albertini’22) | Good for NMR wrap **only with** Kcom |
| **AEGIS-256** (CFRG draft / libsodium) | ✓ | large-nonce friendly | ~ claimed / unstandardized | Optional data plane; still add Kcom for wraps |
| Ascon-AEAD128 (NIST SP 800-232, Aug 2025) | ✓ | lightweight | — | Prefer for IoT, not desktop volume bulk |

**MSV header wrap recommendation (corrected):**

```
KEK = Argon2id(password, …)           // C2 floor
(Kenc, Kcom) = HKDF-Expand(KEK, …)    // domain-separated
C = AEAD_Seal(Kenc, nonce, AAD, volume_master_key)   // XChaCha or AES-GCM-SIV
store (C, Kcom) in header; on unlock verify Kcom before accepting plaintext
```

Reuse Blindkey stanza machinery where possible. **Padding-fix** (Albertini) is an acceptable
alternative to explicit `Kcom` if analyzed for the chosen AEAD.

### 3.3 Layer C — Bulk data encryption (the “disk” plane)

#### C-opt1 — Authenticated expand (preferred for Blindkey)

**XChaCha20-Poly1305** or **AEGIS-256** per fixed block (default **32 KiB** plaintext;
tunable **16–32 KiB** class + nonce + tag — align UC-25 / intent C68).

| | XChaCha20-Poly1305 | AEGIS-256 |
|--|--------------------|-----------|
| Standardization | RFC 8439 family; Blindkey C1 | IRTF CFRG draft; libsodium |
| Random nonce budget | 24-byte nonce, huge | 32-byte nonce, “unlimited” practical |
| Speed on AES-NI Macs | Excellent | Often **faster** than GCM (AES round based) |
| Blindkey reuse | ✓ already in tree | New dep — justify via C3 auditability |
| Partitioning | Same family issues — needs Kcom on wraps | ~ better receiver-binding claims; still design Kcom |

**AAD must include:** `volume_id ‖ block_id ‖ version ‖ kind` (domain separation — normative
in UC-25 §4 / intent C68 / MSV patterns; `tree_level` is not a separate AAD field).

#### C-opt2 — Length-preserving wide-block (if sector size must match)

Only when expansion is impossible (rare for a Blindkey-owned container format):

| Construction | Proof | Auth | Notes |
|--------------|-------|------|-------|
| **HCTR2** (Crowley–Huckleberry–Biggers, ePrint 2021/1441; Google) | TSPRP, fixes HCTR bugs | ✗ | Best modern length-preserving on AES-NI; Polyval from GCM-SIV |
| **HCTR3** / Samvadini lineage | Stronger tweak hashing, anti-commitment attacks on keys | ✗ | 2025 ecosystem (Denis et al. ePrint 2025/1888 discusses) |
| **Adiantum** (Crowley–Biggers, ToSC 2018; ePrint 2018/720) | HBSH; SPRP | ✗ | NH+Poly1305+XChaCha12+1×AES; Android low-end; Linux dm-crypt |
| EME2-AES | IEEE 1619.2-2025 | ✗ | Standard wide-block survivor |
| XCB-AES | **broken** | ✗ | **Forbidden** — ePrint 2024/1554 two-query recovery |
| AES-XTS | NIST 800-38E | ✗ | **Forbidden as sole MSV plane** |

**Critical:** HCTR2/Adiantum/EME2 still need a **separate MAC tree** for L1. Else you only bought
diffusion, not authenticity.

#### C-opt3 — iXTS (ToSC 2025)

Inoue–Minematsu–Ueno–Homma, IACR ToSC **2025**(4): black-box conversion of an XTS engine into
randomized AE with small expansion. Useful if forced to sit on XTS hardware — **not**
Blindkey’s preferred greenfield path.

### 3.4 Layer D — Integrity aggregation

Per-block AEAD tags are necessary but not sufficient for structural integrity.

| Structure | Role | Refs |
|-----------|------|------|
| Merkle hash tree | Bind all blocks to a root | Classical; Oprea–Reiter USENIX’07 |
| MAC tree / universal-hash stateful MAC | Faster integrity | CCSW’09 “MAC tree” CFS paper |
| CryFS block graph + versions | Structure + rollback | ePrint 2017/773 |
| Blindkey C9/C10 HMAC blocks | Existing pattern | Intent |

**MSV:** store AEAD tag per block; maintain a **Merkle root of (block_id → tag ‖ version)** in
the header (encrypted) or in a dedicated authenticated root block; update on write; verify on
read path for metadata ops and periodically for data.

### 3.5 Layer E — Freshness

CryFS: per-block version counters in **local** state. Blindkey C16: monotonic vault counter +
local anchor.

**MSV:** every block write increments `version`; local anchor stores `max_version` / root hash;
mismatch → fail closed (rollback detected). Multi-machine = explicit “trust baseline” ritual
(same honesty as CryFS docs).

### 3.6 Layer F — Size / shape hiding

- Fixed plaintext block size (32 KiB class, CryFS-like).
- Padmé on total container length (already Blindkey).
- Optional: allocate sparse capacity in coarse buckets so free-space pattern leaks less.

### 3.7 Layer G — Post-quantum / future

Volume encryption is **symmetric**. PQ matters for:

- Optional unlock via PQ KEM-wrapped stanzas (ML-KEM) — niche;
- Long-term archive threat to **asymmetric** unlock paths, not AES/ChaCha bulk.

**MSV v1:** stay symmetric; document PQ as future stanza type, not data-plane change.
Ascon (NIST SP 800-232) is for constrained devices — not the primary desktop bulk cipher.

---

## 4. Deep study notes — constructions worth internalizing

### 4.1 Why XTS is the wrong “secure disk” default in 2026

1. No authenticity (NIST’s own words).
2. Narrow-block leakage of change locality.
3. Industry inertia ≠ security optimality.
4. QuarksLab-era VeraCrypt issues show implementation + suite complexity dominate risk.

### 4.2 Why XCB must never ship

ePrint 2024/1554 (“Breaking the IEEE Encryption Standard – XCB-AES in Two Queries”): shared
difference attack via polynomial-hash **separability**; breaks claimed STPRP. IEEE 1619.2-2025
**removed** XCB. Any “IEEE disk encryption” cargo-cult that still cites XCB is stale.

### 4.3 HCTR2 — best length-preserving confidentiality upgrade over XTS

- Hash-Encrypt-Hash; Polyval; single AES key; variable tweak length.
- Fixes HCTR AXU / proof bugs.
- Still **confidentiality-only** → pair with MAC/AEAD tree for MSV.
- Reference: https://github.com/google/hctr2 · ePrint 2021/1441.

### 4.4 Adiantum — ChaCha-native wide sector SPRP

- HBSH: NH → AES-256 (once) → XChaCha12 → NH/Poly1305 family hashing.
- Security reduces to XChaCha + AES (paper §5).
- Ideal when AES-NI absent; on Apple Silicon AES-NI/AMX, HCTR2 or AES-GCM/AEGIS may win.
- **Does not authenticate.**

### 4.5 AEGIS — high-speed AEAD (commitment still explicit)

- CFRG draft; libsodium; CAESAR finalist lineage.
- AEGIS-256: 256-bit key/nonce → practical unlimited random nonces.
- ~ libsodium/CFRG claim better margin than GCM and stronger receiver-binding than GCM —
  **not** a substitute for an explicit key-commitment construction on password wraps
  (Albertini’22 / Len’21 still set the bar).
- libaegis offers **RAF (random-access file)** API aimed at encrypted FS/DB — relevant prior art
  for MSV I/O shaping: https://github.com/aegis-aead/libaegis

### 4.6 AES-GCM-SIV (RFC 8452) — NMR only

- ✓ Nonce-misuse resistant AEAD; synthetic IV from Polyval.
- ✗ **Not key-committing** (Albertini et al. USENIX Sec 2022; also noted in Len et al. appendix).
- Use for header/key wraps when nonce hygiene is hard — **always pair with Kcom / padding fix**.
- For bulk disk, XChaCha/AEGIS with synthetic nonces from `(block_id ‖ version)` is fine if
  engineered carefully.

### 4.7 CryFS security model (the FS-level north star)

Messmer et al. ePrint 2017/773:

- IND-naCFA / IND-aCCFA notions for file systems.
- Lemma: IND-CPA + INT-CTXT components → FS-level CCA-style goals under their framework.
- Hides content **and** metadata (except total size).
- Integrity + rollback via AEAD blocks + local version state.

**Blindkey MSV should aim to be instantiable in this model** (or a documented strengthening),
not only “use AEAD somewhere.”

### 4.8 Partitioning oracles (password unlock)

Any online unlock oracle (agent broker, CLI that returns distinct errors, network unlock) must
assume partitioning attacks if wraps are non-committing. Mitigations:

1. Committing AEAD / key commit tag.
2. Uniform errors + constant-time failure (Blindkey UC-10 culture).
3. Rate-limit / KDF cost already from Argon2id (necessary, not sufficient alone).

---

## 5. “Create something better” — what that means without rolling crypto

Blindkey C3 forbids custom primitives. Better than the field =

### 5.1 Composition theorem (informal)

```
MSV =
  Argon2id_floor                     // L0 password
  ⊕ Explicit_KeyCommitment           // Kcom or Albertini padding fix — NOT GCM-SIV alone
  ⊕ AEAD_KeyWrap                     // XChaCha or AES-GCM-SIV (NMR)
  ⊕ Blindkey_MultiStanza_Envelope    // hardware factors, recovery
  ⊕ FixedSize_AEAD_Blocks            // L1 INT-CTXT + L4 metadata
       (XChaCha20-Poly1305 | AEGIS-256)
  ⊕ MerkleRoot(block_tags, versions) // structural integrity
  ⊕ LocalFreshnessAnchor             // L2 rollback
  ⊕ Padmé(container)                 // size channel shrink
  ⊖ XTS ⊖ XCB ⊖ cascades ⊖ PD claims ⊖ ORAM (v1)
  ⊖ "GCM-SIV implies commitment"     // false per Albertini'22
```

### 5.2 Where Blindkey can beat each competitor

| Competitor | Blindkey MSV win |
|------------|------------------|
| VeraCrypt | +integrity, +metadata posture, +committing wrap, −cascade theater, modern AEAD |
| LUKS+XTS | +integrity default, +metadata FS, cross-platform userspace, IVD constraints |
| Cryptomator | +hidden tree/sizes, +rollback anchor, CLI-native, Rust memory hardening |
| gocryptfs | +active-adversary integrity, +metadata |
| CryFS | ≈ same AEAD+blocks model; +explicit Kcom, +Blindkey stanza/hardware, +Padmé, +IVD falsifiability |
| Apple sparsebundle | +auditable open crypto, +cross-platform, +constraints |

### 5.3 Explicit non-improvements (do not waste effort)

- Cipher cascades “for paranoia.”
- Hidden volumes / PD (unless separate research program).
- Full ORAM for Finder UX.
- Compatible VeraCrypt format (forces XTS world).
- Ascon as bulk desktop cipher (wrong niche).
- Post-quantum bulk encryption (symmetric already PQ-safe at AES-256/ChaCha level).

---

## 6. Proposed Blindkey MSV cryptographic profile (intent-ready)

*Draft for a future Gate-0 — not shipped.*

| Element | Choice | Rationale |
|---------|--------|-----------|
| Container magic | Distinct (`VLTD` — 4-byte draft; freeze in Gate-0 ADR) | ADR-0005 hygiene |
| Unlock KDF | Argon2id (C2 floor/ceiling) | Existing |
| Stanzas | Blindkey any-of-N | Existing |
| Master secrets | `volume_key`, `mac_key`, `nonce_key` via HKDF | Domain separation |
| Block size | 32 KiB plaintext default (tunable; CryFS docs 16–32 KiB class) | CryFS-class |
| Block AEAD | XChaCha20-Poly1305 **default** (C1 reuse); **optional** AEGIS-256 profile | Prove one path first |
| Key wrap | AEAD (XChaCha or AES-GCM-SIV) **+ explicit Kcom** | Albertini’22 / Len’21 |
| Nonce | `XChaCha nonce = HKDF/PRF(nonce_key, block_id ‖ version)[0:24]` | No random-nonce log |
| AAD | `volume_id ‖ block_id ‖ version ‖ kind` | Bind context |
| Tree | BLAKE3 or HMAC-SHA-256 Merkle over `(id, version, tag)` | Fast, keyed |
| Root | In encrypted header; dual-copy | LUKS2 lesson |
| Freshness | Local anchor file (C16-like) | Rollback |
| Padding | Padmé default-on | C66 |
| Length-preserving mode | **Not in v1** | Prefer AEAD expansion inside container |
| Forbidden | XTS-only, XCB, EncFS patterns, plaintext filenames | — |

### 6.1 Optional “paranoid” profile (later)

HCTR2 (or Adiantum) **inside** each block **before** AEAD — wide diffusion + authenticity.
Cost: extra pass. Benefit: mitigates some partial-block analytical leakage if AEAD nonce/AAD
mishandled. Only after base AEAD profile is proven.

### 6.2 Security claims MSV may advertise (falsifiable)

1. Offline IND-CPA for contents under standard AEAD assumptions.
2. Detection of any bit modification to any stored block (INT-CTXT per block + tree).
3. Detection of rollback given intact local anchor.
4. No plaintext filenames, sizes, or tree on disk (only capacity + Padmé bucket).
5. Password wrap resists partitioning-oracle speedups via key commitment.
6. No network; no telemetry.

Claims **not** allowed: “immune to evil maid with DMA,” “hides access patterns,” “plausibly
deniable,” “stronger than AES because three ciphers.”

---

## 7. Side-channel & implementation security (equals algorithm choice)

| Topic | Practice |
|-------|----------|
| Memory | `zeroize` + `mlock` (C11); wipe page cache of cleartext via umount |
| Timing | Constant-time tag compare; no error oracle distinctions |
| Core dumps | `RLIMIT_CORE=0` (existing) |
| Swap | Document; optionally `madvise(MADV_DONTDUMP)` / disable swap for mount process |
| FUSE TOCTOU | Handle races; no plaintext spill to log paths |
| Compression before AEAD | **Off by default** (size oracle); if ever on, pad after compress |
| Secure delete | Free blocks re-encrypted with fresh random or hole-punch + overwrite policy |

---

## 8. Comparison matrix (security properties only)

| Property | VC XTS | LUKS XTS | Cryptomator | gocryptfs | CryFS | **MSV** |
|----------|--------|----------|-------------|-----------|-------|---------|
| AEAD data | ✗ | ✗* | ✓ | ✓ | ✓ | ✓ |
| Wide-block diffusion | ✗ | ✗ | — | — | — | optional |
| Hidden directory tree | ✓† | ✓† | ✗ | ✗ | ✓ | ✓ |
| Hidden file sizes | ✓† | ✓† | ✗ | ✗ | ✓ | ✓ |
| Rollback detection | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Key-committing wrap | ✗ | ✗* | ✗ | ✗ | ✗ (scrypt+AE) | ✓ **explicit Kcom** |
| Published FS proof | ✗ | ✗ | ✗ | ✗ | ✓ | target |
| Modern (post-2024) mode hygiene | XCB risk if copied | OK | OK | OK | OK | forbids XCB/XTS-only |
| Memory hardening story | C++ | kernel | Java | Go | C++ | Rust zeroize |

\* LUKS can add `--integrity` (expansion). CryFS/Cryptomator use AEAD but **not**
standardized key-commitment on password wraps (scrypt + GCM/ChaCha class). † While locked;
inner FS visible when mounted.

---

## 9. Research program to go **beyond** CryFS (ordered)

If Leo wants “better than anything published,” climb this ladder **after** MSV v1 ships:

1. **Proof adaptation:** restate CryFS theorems for Blindkey’s envelope + Padmé + stanza model
   (paper-quality writeup in `research/`).
2. **Committing AEAD standardization:** track CFRG / academic committing ChaCha constructions;
   adopt when RustCrypto-quality crates exist.
3. **Beyond-birthday HCTR2++ / CHCTR2** only if a length-preserving profile is required.
4. **woORAM PD** (Shufflecake line) — separate product, not MSV v1.
5. **Formal verification** of the Rust AEAD glue (not the AES proof) with hax/f* subset — high cost.

Do **not** start at (4)–(5). Most of the world’s “more secure disk” gap vs VeraCrypt is closed
by (MSV v1 = AEAD + tree + metadata + freshness + committing wrap).

---

## 10. Libraries for a security-maximal implementation

| Need | Library | Note |
|------|---------|------|
| XChaCha20-Poly1305 | existing Blindkey | Prefer |
| AEGIS | `libaegis` / future Rust port | RAF API interesting |
| AES-GCM-SIV | RustCrypto `aes-gcm-siv` | Header wrap |
| HCTR2 | google/hctr2 reference | Optional profile |
| Adiantum | google/adiantum; Linux crypto | Optional |
| BLAKE3 | `blake3` crate | Merkle |
| Argon2 | existing | |
| FUSE | `fuser` | Mount |
| Ascon | NIST SP 800-232 impls | Not bulk MSV |

License review before linking anything GPL into Blindkey core.

---

## 11. Updated recommendation (supersedes mount research §0 crypto choice)

For Blindkey live volumes, optimize **security first**:

1. **Data plane:** fixed-size **XChaCha20-Poly1305** (or AEGIS-256) blocks — **not** XTS.
2. **Structure:** CryFS-class graph + Merkle root + local freshness anchor.
3. **Unlock:** Argon2id + AEAD wrap + **explicit key commitment** (not GCM-SIV alone) + Blindkey stanzas.
4. **Size:** Padmé.
5. **Forbidden:** XCB, XTS-only, cascades, PD claims, inventing primitives.
6. **Mount:** FUSE/FSKit as in the architecture research — crypto does not depend on Apple’s
   opaque sparsebundle.

That is the strongest **practical** folder/disk encryption design available from public
cryptography in 2026 that still fits Blindkey’s IVD / C3 constraints.

---

## 12. Source index (security-critical)

### Standards & RFCs
- NIST SP 800-38E (XTS) — https://csrc.nist.gov/publications/detail/sp/800-38e/final
- NIST SP 800-232 (Ascon, Aug 2025) — https://csrc.nist.gov/pubs/sp/800/232/final
- RFC 8452 (AES-GCM-SIV) — https://www.rfc-editor.org/rfc/rfc8452
- RFC 9106 (Argon2) — https://www.rfc-editor.org/rfc/rfc9106
- IEEE 1619-2025 / 1619.1-2018 / 1619.2-2025 — https://standards.ieee.org/
- AEGIS CFRG draft — https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html

### Papers (algorithm / attack / model)
- HCTR2 — ePrint 2021/1441 — https://eprint.iacr.org/2021/1441
- Adiantum — ePrint 2018/720 — https://eprint.iacr.org/2018/720
- CryFS — ePrint 2017/773 — https://eprint.iacr.org/2017/773
- XCB breaks — ePrint 2024/1554, 2024/1527 — https://eprint.iacr.org/2024/1554
- iXTS — Inoue et al., ToSC 2025(4) — https://tosc.iacr.org/index.php/ToSC/article/view/12614
- Partitioning oracles — ePrint 2020/1491 / USENIX Sec 2021
- Key commitment abuse/fix — Albertini et al., ePrint 2020/1456 / USENIX Sec 2022
- Snapshot adversaries — ePrint 2018/195
- Shufflecake / PD / woORAM — ePrint 2023/1529
- HCTR2-FP / HCTR3 notes — ePrint 2025/1888
- XTS key scopes (IEEE 1619-2025 discussion) — arXiv:2502.18631
- Padmé / PURBs — PoPETs 2019 (see Blindkey padmé research)
- gocryptfs audit — https://defuse.ca/audits/gocryptfs.htm
- CryFS how it works (cipher/KDF) — https://www.cryfs.org/howitworks
- VeraCrypt Header Key Derivation — https://veracrypt.io/en/Header%20Key%20Derivation.html

### Implementations
- google/hctr2 — https://github.com/google/hctr2
- google/adiantum — https://github.com/google/adiantum
- libaegis — https://github.com/aegis-aead/libaegis
- Fuse-T — https://www.fuse-t.org/ (commercial embed license; FSKit on macOS 26+)
- QuarksLab VeraCrypt audit — OSTIF 2016 PDF

### In-repo
- [`encrypted_volume_mount_research.md`](encrypted_volume_mount_research.md)
- [`encrypted_cloud_storage_research.md`](encrypted_cloud_storage_research.md)
- [`padme_padding_research.md`](padme_padding_research.md)
- [`blindkey_intent.yaml`](../blindkey_intent.yaml)

---

## 13. Source cross-check log (2026-07-21)

| Claim | Verdict | Fix |
|-------|---------|-----|
| AES-GCM-SIV ⇒ key commitment | ✗ **FALSE** (Albertini USENIX’22; Len’21) | Rewrote wrap layer; explicit Kcom required |
| AEGIS “is committing” | ~ overstated | Softened; still require Kcom on wraps |
| CryFS password config | Incomplete | Documented **scrypt** + XChaCha20-Poly1305 default |
| CryFS block size “32 KiB” | ~ | Noted 16–32 KiB class (changelog vs docs) |
| iXTS “ToSC 2024 / Homma et al.” | ✗ | Inoue–Minematsu–Ueno–Homma, ToSC **2025**(4) |
| Fuse-T FSKit “newer macOS” | ✗ | macOS **26+** native FSKit; commercial license |
| VeraCrypt Argon2id details | Incomplete | 192 B derive; PIM 12 → 416 MiB / 6 iter (official) |
| rage-mount | ✓ | Confirmed RO tar/zip via libfuse |
| IEEE 1619-2025 key scopes | ✓ | Cited Brož et al. arXiv:2502.18631 |
| Comparison “MSV AEAD stronger than CryFS” | Vague | Clarified win = Kcom + Padmé + stanzas + IVD, not a stronger bulk cipher; §0 table now “same class as CryFS” |
| AAD `tree_level` vs profile `kind` | ✗ inconsistency | Normative AAD = `volume_id ‖ block_id ‖ version ‖ kind` (UC-25 / C68 / patterns) |
| Block size “32–64 KiB” example | ~ drift | Aligned to **32 KiB default / 16–32 KiB class** |

---

## 14. Changelog

| Date | Note |
|------|------|
| 2026-07-21 | Initial maximum-security cryptographic expansion for Blindkey live volumes. |
| 2026-07-21 | **Source cross-check:** fixed AES-GCM-SIV commitment error; Albertini/Len cites; CryFS scrypt; iXTS citation; Fuse-T license/version; key-scope paper; wrap recipe. |
| 2026-07-21 | **Full-surface audit:** AAD `kind`; block-size class 16–32 KiB; CryFS comparison wording aligned with §13. |
