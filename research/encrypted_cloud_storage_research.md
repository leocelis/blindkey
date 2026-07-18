# Encrypted cloud storage — Research

> **Task:** Full survey — open-source (non-paid) tools, libraries, academic literature,
> and community/practitioner knowledge — on how to encrypt files and folders so they
> can be securely stored on cloud file hosting (Dropbox, Google Drive, S3, B2, etc.).
> Scope is intentionally provider-agnostic — no git-specific mechanisms (clean/smudge
> filters, git-remote helpers) are in scope; those constraints (forced ciphertext
> determinism for stable diffs) don't apply to plain cloud storage. Feeds UC-07
> (untrusted-storage sync), the Padmé work (`padme_padding_research.md`), and any
> future encrypted-sync design.
>
> Research date: 2026-07-03. Six parallel research passes: OSS overlay/backup tools,
> academic literature, community/practitioner knowledge, VeraCrypt/Picocrypt/crypto
> primitives, cloud-specific community recs + newer papers + breach data, and a
> gap-fill pass on threat-modeling/key-management/practitioner friction.
> Markers: ✓ verified against primary source · ~ inferred/corroborated ·
> ? unverified (flagged inline — check before relying on it for a security decision).

---

## 1. Problem statement

A cloud host is a **multi-snapshot adversary with perfect memory** if it retains version
history (most sync services do). The academic result that frames everything: security
against a snapshot adversary with as few as *three* snapshots is essentially as hard as
against a fully persistent adversary (Amjad–Kamara–Moataz,
[eprint 2018/195](https://eprint.iacr.org/2018/195)). A tool "safe if the attacker sees
the ciphertext once" (EncFS, per its own audit) degrades sharply under this model.

Four sub-problems, largely orthogonal:

1. **Content confidentiality** — the cipher layer (mostly solved; rarely the failure mode in practice).
2. **Metadata confidentiality** — names, sizes, tree shape, change frequency (the dominant real leak).
3. **Integrity + freshness** — a malicious host serving tampered or stale data (rollback/fork).
4. **Key lifecycle** — rotation, revocation, and what history means for either.

Unlike git, plain cloud storage does **not** force ciphertext determinism — there's no
"stable diff" requirement. This means the correct default is **full semantic security**
(fresh random nonce per encryption), which is strictly stronger than the
deterministic/SIV constructions git-oriented tools need. Determinism should only be
reached for if content-addressed deduplication is an explicit, deliberately-chosen
goal (see §5.1) — otherwise it is a pure downgrade with no offsetting benefit for this
use case.

---

## 2. Tool survey — encrypt-before-upload / mountable vaults

### 2.1 Encrypted overlay filesystems (folder → Dropbox/Drive, live sync)

| Tool | Hides | Leaks | Audit | Status (2026) |
|---|---|---|---|---|
| **gocryptfs** | Content (per-file AES-256-GCM, 4 KiB blocks), names (AES-EME) | Tree structure, sizes, file counts, timing; **no active-adversary protection** (audit-acknowledged); community-cited (unlinked) audit finding of "integrity-protection imperfections" — ? unverified, trace to the primary report before relying on it | ✓ Hornby 2017 — strong vs passive adversary | ✓ v2.6.1 (2025-08). Best raw throughput of the FUSE tools (single-source benchmark: ~482/944 MiB/s vs Cryptomator's ~57/113 MiB/s — unreplicated, treat as directional). Weak/no first-party Windows, iOS, Android clients — disqualifying for anyone needing mobile access. No built-in recovery-phrase UX; manual master-key handling. ✓ On macOS depends on closed-source macFUSE, which got gocryptfs **pulled from Homebrew's main registry** over licensing ([gocryptfs discussion #636](https://github.com/rfjakob/gocryptfs)) — a real practical install-friction point, not a crypto weakness. |
| **CryFS** | **Everything** incl. sizes + tree — uniform fixed-size encrypted blocks | Total volume, access/change patterns | Academic (KIT thesis + DBSec 2017, [eprint 2017/773](https://eprint.iacr.org/2017/773)); no independent third-party audit found | ✓ 1.0 shipped (Debian 2025-12); 2.0 Rust rewrite in alpha. Weak large-file performance (community-repeated complaint); thinner platform support (Linux/Mac primary, Windows experimental). Most metadata-private FUSE option. |
| **Cryptomator** | Content (AES-GCM), names (AES-SIV), hierarchy flattened via hashed dir IDs | Sizes, file counts, timestamps | ✓ Cure53 2017 (crypto libs); iOS library (cryptolib-swift) explicitly **out of scope** | ✓ Active, commercial-backed; PrivacyGuides.org's top pick specifically for cloud storage. Most-repeated community recommendation for continuous multi-device sync — per-file encryption keeps incremental sync cheap; cross-platform (Win/Mac/Linux/iOS/Android) repeatedly cited as its deciding edge over gocryptfs. Slower than gocryptfs; no CLI. |
| **securefs** | Content+names; full format hides hierarchy; optional **random size padding** (rare feature) | — | None found (?) | ✓ v2.0.0 (2025-10) |
| **EncFS** | — | **Broken under multi-version observation** — exactly the sync adversary | ✓ Hornby 2014 — failed | **AVOID** — unmaintained since 2024 |
| **eCryptfs** | — | — | — | **AVOID** — kernel-unmaintained 2025 |

**Community verdict (well corroborated across CryFS's own comparison page, Ask Leo,
gocryptfs docs, an HN thread, netguardia.com):** Cryptomator for continuous multi-device
sync (best platform coverage); gocryptfs for Linux power users scripting rclone/restic
pipelines (best throughput, worst platform coverage); CryFS when metadata privacy
(sizes/structure) is the priority and large-file performance is acceptable.

### 2.2 One-shot "encrypt then upload" tools (archive-style, not live-mounted)

| Tool | Design | Audit | Status | Fit |
|---|---|---|---|---|
| **age / rage** | X25519 recipients (or scrypt passphrase), ChaCha20-Poly1305, fresh random file key per encryption, HMAC'd header. Non-deterministic by design. Composable via Unix pipes: `tar cz data \| age -r $KEY \| aws s3 cp - s3://bucket/backup.age` is a natural encrypt-then-upload pattern. Recently added post-quantum key-agreement support. | Not independently audited as a whole; design is simple, widely reviewed, small trusted-computing-base | ✓ Very active ecosystem ([awesome-age](https://github.com/FiloSottile/awesome-age)) | **Strong** — purpose-built for exactly this pattern; `rage-mount` can even FUSE-mount an age-encrypted tar read-only |
| **Picocrypt / Picocrypt-NG** | XChaCha20-Poly1305 + Argon2id + keyed-BLAKE2b (normal mode); XChaCha20 cascaded with Serpent + HMAC-SHA3 + heavier Argon2 (paranoid mode) | ✓ **Radically Open Security audited it in 2024** — no major issues, minor items patched | Original project **archived/frozen Sept 2025** — maintainer declares it feature-complete and explicitly does **not** endorse the community continuation ("Picocrypt-NG"); the fork inherits the audited crypto core but its own changes are unaudited | **Strong fit** for the exact "encrypt a folder into one file, upload once" workflow — better match than VeraCrypt since there's no live-remount/re-sync friction. Long-term format support now rests on an unendorsed fork. |
| **Kryptor** | Passphrase / symmetric / asymmetric multi-recipient encryption; positions itself as "a better age + Minisign"; encrypted output indistinguishable from random; optional filename encryption | Not independently audited; maintainer describes peer review only | ~ Actively maintained (recent release activity) | Good; less battle-tested than age |
| **7-Zip (AES-256)** | AES-256-CBC content, SHA-256-based password KDF (iteration count configurable) | Cipher scheme itself: no known design break when correctly configured. **7-Zip the application** has a real CVE history (buffer overflows, OOB reads in archive parsers — Talos disclosures) | ✓ Ubiquitous, actively maintained | **Conditional** — "Encrypt file names" is **opt-in, not default**; leaving it off leaks filenames, directory structure, file counts, sizes even without the password (the most common real-world misconfiguration). Community verdict: adequate content cipher, but an archiver with crypto bolted on rather than crypto-first design; less favored than purpose-built tools in privacy-focused communities. |
| **VeraCrypt** | AES/Serpent/Twofish/Camellia/Kuznyechik + cascades; PBKDF2 historically, **Argon2id added v1.26.27 (Sept 2025)**, extended to non-system volumes v1.26.29 (June 2026); PIM-scalable KDF cost; hidden volumes + plausible deniability | ✓ **QuarksLab 2016** (commissioned via OSTIF, 32 person-days): 8 critical / 3 medium / 15 low findings — flawed GOST cipher, unauthenticated header ciphertext, unsound keyfile mixing; nearly all fixed in v1.19 same day. No comprehensive independent audit found post-2016 — treat 2020s "audit" claims in SEO blog content as unverified marketing, not primary sources. GHSA-jjcr-75w7-58jp (fixed v1.26.29): hidden-volume "quick format" previously wrote plaintext zero sectors at 128 MiB intervals, undermining plausible deniability. | ✓ Active (IDRIX); ~ operational risk noted March 2026 — Microsoft terminated the code-signing account used for Windows driver/UEFI bootloader releases (distribution risk, not a crypto flaw) | **Architecturally weak fit for live cloud sync**: containers are monolithic files; Dropbox's block-level sync for VeraCrypt has repeatedly broken (community-reported, e.g. post-app-update v83.4.152), causing full re-uploads or corruption; mounting/writing touches header/allocation metadata causing outsized re-sync deltas. Fine as a **one-time sealed archive** upload, poor as a continuously-synced live volume. PrivacyGuides.org's suggested config: AES cipher + SHA-512, not a cascade. |

---

## 3. Backup/sync tools with client-side encryption (snapshot model)

| Tool | Design | Remote sees | Status |
|---|---|---|---|
| **restic** | CDC chunking + dedup; AES-256-CTR + Poly1305-AES MAC; scrypt-derived key | Opaque uniform packs — no names/structure; sizes+timing leak | ✓ Very active; positive Valsorda crypto review (2017) |
| **Borg / borg2** | 1.x: AES-CTR+HMAC (nonce-management fragility in multi-client setups); 2.0: AEAD session keys + argon2 | Encrypted segments | 2.0 in beta (? GA date); needs a borg-capable server for full efficiency |
| **rclone crypt** | XSalsa20-Poly1305 content (random nonce per file, 64 KiB chunks); **deterministic AES-EME names per segment** (needed so files can be located) | Tree structure, sizes (+~1.05%, computable), name equality/frequency | ✓ Very active; **no rekey at all** — password change means re-uploading everything. Community-cited advantage: combines encryption *and* the cloud transport in one tool, no separate sync client needed (unlike Cryptomator). ✓ **No block-level/delta sync** — a small edit to a large file still forces a full re-upload of that file ([rclone forum feature request #30855](https://forum.rclone.org/t/block-level-file-sync-or-chunking-with-crypt-backend/30855), unresolved). ✓ Documented **filename-length ceiling**: spec allows up to 156 chars, practical limit found closer to ~143 ([rclone#2040](https://github.com/rclone/rclone/issues/2040); rclone forum); an experimental `filename_encoding` option (base64/base32768) is the workaround. |
| **Kopia** | AES-256-GCM (default) or ChaCha20-Poly1305, per-content HKDF keys from a master key (envelope encryption) | Opaque blobs | ✓ Active; no third-party audit found (?) |
| **duplicity** | GPG'd tar full+incremental chains | Volume sizes, chain cadence | ✓ v3.0.7 (2025-12); historically fragile chains (a corrupted increment breaks the chain) |
| **Tahoe-LAFS** | Convergent encryption + per-client convergence secret; erasure coding across untrusted servers; **capability-based access** (read/write/verify caps) | Provider-independent security | Alive but slow; operationally heavy for a single-user cloud-folder use case |

---

## 4. Cryptographic building blocks (for anyone building a custom tool)

| Library | Design philosophy | Audit status |
|---|---|---|
| **libsodium / NaCl** | High-level, hard-to-misuse API around vetted primitives (XSalsa20-Poly1305 / XChaCha20-Poly1305 `secretbox`, Curve25519, Ed25519, Argon2id `pwhash`) | ✓ Matthew Green audit, 2017 (v1.0.12–1.0.13, commissioned via Private Internet Access): "secure, high-quality library... no major vulnerabilities," some low-severity API/RNG-customization items. Widely considered the safest default in 2026 for a purpose-built encrypt-before-upload tool. |
| **Google Tink** | API shapes designed to make misuse (e.g. nonce reuse) structurally hard; reuses vetted primitives; backed by the Wycheproof test-vector project | No standalone full third-party audit report found (? unverified/not found this session), though design + Google-internal review is well documented. Best pick when you need built-in key-management/envelope-encryption/rotation scaffolding, not just a cipher call. |
| **RustCrypto crates** (`aes-gcm`, `chacha20poly1305`, `argon2`, …) | Pure-Rust reimplementations, no C bindings | Per-crate, not ecosystem-wide — check individually. One credible 2026 data point: Ente's `ente-core` crate (built on RustCrypto primitives) audited by winfunc, April 2026, medium/low findings only (winfunc is an LLM-powered audit firm — weight accordingly vs. traditional firms like NCC/Cure53/Trail of Bits/QuarksLab). |
| **PyNaCl** | Python bindings to libsodium | Inherits libsodium's audit; actively maintained by PyCA; recent work bumped to libsodium 1.0.20 resolving CVE-2025-69277. |

### KDF standards (for whatever wraps the master key/passphrase)

- ✓ **RFC 9106** (Argon2, IETF) two recommended profiles: **(1)** Argon2id t=1 p=4 m=2 GiB
  — ample-RAM systems, maximizes cost against dedicated cracking hardware; **(2)**
  Argon2id t=3 p=4 m=64 MiB — memory-constrained. 128-bit salt, 256-bit tag.
- ✓ **OWASP Password Storage Cheat Sheet** current guidance is lighter (m=19 MiB t=2 p=1
  minimum, m=46 MiB t=1 p=1 higher) — that reflects **server login-latency** budgets, not
  local file encryption. A local encrypt-before-upload tool has no such constraint and
  should use RFC 9106's heavier profile.
- ✓ 2026 practitioner consensus: **Argon2id has superseded scrypt** (absorbed its benefits
  plus years more cryptanalysis); **PBKDF2 retained only for FIPS-140 compliance**, not
  general use — its lack of memory-hardness caps GPU/ASIC advantage far less (roughly
  1.5–5× for memory-hard KDFs vs. up to ~5000× for non-memory-hard ones like raw PBKDF2).
  This matters specifically because an attacker who obtains encrypted-file ciphertext
  from a cloud host can crack the passphrase offline, indefinitely, with no rate limit.

---

## 5. Academic foundations

### 5.1 Determinism, dedup, and its cost (no git constraint — this is now optional)

- Deterministic encryption's best achievable guarantee is privacy for high-min-entropy
  plaintexts; equality leakage is *inherent* (Bellare–Boldyreva–O'Neill, CRYPTO 2007,
  [eprint 2006/186](https://eprint.iacr.org/2006/186)). **SIV**
  (Rogaway–Shrimpton, EUROCRYPT 2006, [eprint 2006/221](https://eprint.iacr.org/2006/221);
  RFC 5297 / RFC 8452) is the textbook-correct primitive *if* determinism is ever wanted
  (e.g. deliberate dedup), leaking only full-message equality when path is bound as AD.
- Message-locked / convergent encryption is provably secure **only for unpredictable
  messages** (Bellare–Keelveedhi–Ristenpart, EUROCRYPT 2013,
  [eprint 2012/631](https://eprint.iacr.org/2012/631)); guessable plaintexts are
  confirmable by the host via **confirmation-of-file** and **learn-remaining-information**
  attacks (Harnik–Pinkas–Shulman-Peleg, IEEE S&P Mag 2010). DupLESS
  ([eprint 2013/429](https://eprint.iacr.org/2013/429)) fixes this with a rate-limited
  OPRF key server. Two 2023–2024 follow-ups keep patching the same weakness rather than
  closing it: Ahmad et al., *Concurrency and Computation: Practice and Experience* 2024
  (peer-reviewed, Wiley — [doi.org/10.1002/cpe.8205](https://onlinelibrary.wiley.com/doi/abs/10.1002/cpe.8205))
  and an "Enhanced Convergent Encryption" (ECEcipher) paper in a smaller venue (lower
  confidence, Scientific Temper journal). Both add extra KDF/cipher layers on top of CE
  without eliminating the underlying predictability weakness.
- **Practical takeaway for cloud (not git):** since nothing forces determinism, **default
  to fresh random nonces per encryption (full semantic security)**. Only reach for
  SIV/convergent encryption if global or cross-device deduplication is an explicit,
  deliberately accepted trade — and if so, mix in a per-user secret (DupLESS-style),
  never derive the key from content alone.

### 5.2 Metadata: sizes and shape are the dominant leak

- ✓ **PURBs/Padmé** (Nikitin et al., PoPETs 2019, [arXiv:1806.03160](https://arxiv.org/abs/1806.03160)):
  ciphertexts indistinguishable from random bits (no plaintext headers) + padding leaking
  only O(log log M) bits of length at ≤12% overhead. Already explored for Blindkey — see
  `padme_padding_research.md` (shipped opt-in `PadMode`).
- ✓ **CryFS model** ([eprint 2017/773](https://eprint.iacr.org/2017/773)): fixed-size
  encrypted blocks provably hide sizes, tree, and metadata from an honest-but-curious
  storage provider; only total volume + access/change patterns remain. The cost is
  performance and (per community reports) large-file handling — the central tension:
  **metadata-hiding and raw sync/diff efficiency pull in opposite directions.**
- ✓ Leakage-abuse literature (Blackstone–Kamara–Moataz NDSS 2020; Cash et al. CCS 2015;
  Zhang–Katz–Papamanthou file-injection USENIX 2016): "we only leak sizes/access
  patterns" is routinely exploitable; an adversary who can *cause* you to store chosen
  content amplifies dedup/determinism leaks. ORAM is the theoretical fix; no practical
  cloud-encryption tool pays its polylog bandwidth overhead.

### 5.3 Freshness/rollback: encryption doesn't solve it

- ✓ **SUNDR** (OSDI 2004): an untrusted server can always fork users onto divergent
  histories; the best achievable without extra trust is **fork consistency** — forks
  become detectable on any out-of-band comparison. **Depot** (OSDI 2010) weakens this to
  Fork-Join-Causal to let forked clients rejoin safely.
- ~ For plain cloud storage (no Merkle DAG to lean on, unlike git), freshness must be
  supplied explicitly — a monotonic counter or out-of-band witness. **This is exactly
  Blindkey's C17 rollback anchor design** — the per-`vault_id` monotonic counter is the
  freshness witness the literature prescribes, and it generalizes cleanly to any cloud
  backend since it doesn't depend on git's object model.

### 5.4 Key rotation: forward-only, and history is forever

- ✓ Plutus (FAST 2003): filegroup keys + **lazy revocation** (re-encrypt on next write);
  formalized by Backes–Cachin–Oprea ([eprint 2005/334](https://eprint.iacr.org/2005/334)).
- ✓ Everspaugh–Paterson–Ristenpart–Scott (CRYPTO 2017): rotating only the KEK in envelope
  encryption does NOT protect data from an old-key compromise — holders of old DEKs keep
  access. Updatable encryption with post-compromise security exists
  (Lehmann–Tackmann, [eprint 2018/118](https://eprint.iacr.org/2018/118)) but no
  mainstream tool ships it.
- **Cloud-history wrinkle:** any host retaining version history keeps old ciphertexts
  forever, so *no* rotation scheme retroactively protects already-uploaded data. A
  compromised key means re-encrypting and re-uploading everything, or accepted exposure
  of old snapshots.

### 5.5 The 2022–2024 E2EE-cloud breaks: the failure mode is authenticity, not ciphers

- ✓ **MEGA** (Backendal–Haller–Paterson, IEEE S&P 2023, [eprint 2022/959](https://eprint.iacr.org/2022/959)):
  malicious server recovers the user's RSA key in 512 logins (unauthenticated ECB key
  material + decryption oracle), then decrypts and **injects files passing all client
  checks**. Follow-up attacks survived the patches (EUROCRYPT 2023).
- ✓ **"A Broken Ecosystem"** (Albrecht–Backendal–Coppola–Paterson, CCS 2024,
  [eprint 2024/1616](https://eprint.iacr.org/2024/1616.pdf)): 4 of 5 audited E2EE
  providers broken (Sync, pCloud, Icedrive, Seafile; Tresorit mostly survived) —
  unauthenticated modes, unauthenticated key material, file/folder injection, directory
  tampering. Systemic, not one-off.
- ✓ First formal model for E2EE cloud storage vs a fully malicious server:
  Backendal–Davis–Günther–Haller–Paterson, CRYPTO 2024,
  [eprint 2024/989](https://eprint.iacr.org/2024/989) — the reference framework to
  evaluate any design against. Nextcloud E2EE also broken
  ([eprint 2024/546](https://eprint.iacr.org/2024/546)).

**Lesson: every real-world break since 2022 was an authenticity/binding failure —
unauthenticated key wrapping, missing binding of keys↔paths↔tree position, protocol
oracles — never the cipher.** AEAD everything, including key wraps; bind ciphertexts to
path and position; assume malicious (not honest-but-curious) host.

### 5.6 Standards/regulatory guidance and the academic gap

A dedicated 2023–2026 "confidential cloud backup for individuals" paper was **not
found** — searched explicitly and came up short. The nearest 2023–2026 literature
clusters elsewhere: TEE/FHE confidential-computing papers (data processed *in* the
cloud, not the encrypt-before-upload pattern) and org-facing standards (NIST SP 800-209
storage-infra guidelines, SP 800-111 end-user storage encryption, ENISA's cryptographic
measures + Oct-2024 NIS2 technical guidance) — all assume an enterprise/provider
context, not a single user encrypting a folder for Dropbox. This niche is genuinely thin
in the literature; the applicable theory is the general E2EE/leakage/rotation results
above, not a purpose-built body of work.

---

## 6. Community/practitioner findings

### 6.1 What real breaches actually demonstrate (well corroborated)

- ✓ **Dropbox 2012 breach** (disclosed 2016): 68.6M accounts — stolen email + password
  hashes, root cause an employee's reused, breached password. A **credential/account**
  breach, not content exposure — but commonly (and correctly) cited as evidence that
  providers get breached.
- ✓ **Dropbox Sign breach (2024)**: detected 2024-04-24, disclosed 2024-05-01 + SEC
  filing. Compromised emails, usernames, phone numbers, hashed passwords, API keys, and
  OAuth tokens for the separate Dropbox Sign product; Dropbox's core storage service and
  document contents were not implicated. Corroborated across multiple independent
  security outlets (Huntress, Security Boulevard, Trend Micro). Same lesson as the 2012
  breach: account/credential-layer compromise, not a break of any file-content crypto.
- ✓ **Ateam Inc. Google Drive misconfiguration** (disclosed Dec 2023): a Drive instance
  set to "anyone with the link" for **6.5–6.8 years** (reports vary: ~2017–2023),
  exposing ~925,728–935,779 people's personal data (customers, partners, employees).
  Corroborated across independent outlets (CyberInsider, TechRadar, BleepingComputer).
- ~ **S3 exposure rate**: Datadog's 2024 State of Cloud Security Report puts "effectively
  public" S3 buckets at ~1.5% (stable 2023→2024) — the more defensible figure. A separate
  2025 claim ("nearly half of all S3 buckets potentially misconfigured") circulated in
  secondary tech media without a traceable primary source — **flag as unverified, do not
  cite as fact.**
- **The load-bearing argument these incidents actually support**: both concrete,
  corroborated incidents are **access-control/credential failures**, not cryptographic
  breaks. This is precisely the strongest case for client-side encryption — if the file
  itself is ciphertext, a sharing-permission mistake or a credential breach exposes only
  "an encrypted blob exists here," not its contents.

### 6.2 Consensus tool set and the "why" behind it

Across CryFS's comparison page, Ask Leo, a substantive HN thread
([32092185](https://news.ycombinator.com/item?id=32092185)), netguardia.com, and
PrivacyGuides.org, the same short list keeps recurring for the personal
encrypt-before-cloud-upload problem: **Cryptomator, gocryptfs, CryFS, rclone crypt,
VeraCrypt, Picocrypt, restic, borg.** See §2–3 tables above for the per-tool trade-offs;
the consensus split is fundamentally **live-synced folder** (Cryptomator/gocryptfs/CryFS/
rclone crypt) vs. **one-shot sealed archive** (VeraCrypt/Picocrypt/age/7-Zip) — pick
based on which workflow the data actually needs, not on cipher strength (the ciphers
are all adequate; the workflow fit is what fails in practice).

### 6.3 Threat-modeling framing

The general framework — ✓ [EFF SSD "Your Security Plan"](https://ssd.eff.org/module/your-security-plan):
what you're protecting, from whom, how bad failure would be, how likely, how much effort
to invest. Applied to cloud-encryption tool choice:

- **Honest-but-curious provider** (won't attack you, but you don't want them reading
  your files) → any of the tools above with a client-side key the provider never sees is
  sufficient.
- **Compelled disclosure** (subpoena, legal request against the *provider*) → same
  client-side encryption holds, provided the key was never given to the provider or any
  third party — but then your own device/backup security becomes the threat surface.
- **Provider breach** (attacker gets read access to provider infra) → client-side
  encryption fully neutralizes content exposure; this is the threat class both §6.1
  incidents actually represent, and the strongest, most directly-matched real-world
  argument for the whole "encrypt before cloud" pattern.

**A sharper, more directly-applicable source: Freedom of the Press Foundation's "2026
journalist's digital security checklist"** (✓ published 2024-12-10, updated
2025-12-17 — [freedom.press/digisec](https://freedom.press/digisec/blog/journalists-digital-security-checklist/)).
This is the most concretely-scoped threat model found for exactly this question:

- Frames the threat explicitly as **legal compulsion against the provider** — "adversaries
  who can subpoena the information you've stored with account providers (e.g., Dropbox,
  Google, iCloud)" — grounded in the U.S. **Stored Communications Act**, which lets law
  enforcement compel a cloud provider to hand over customer data without the customer's
  knowledge or consent. Cites the **Paul Manafort case** as a concrete precedent: he was
  indicted partly on the strength of iCloud/WhatsApp cloud backups obtained by subpoena
  from the provider, not from his own devices.
- **Recommends VeraCrypt by name** for pre-upload file encryption ("use VeraCrypt to
  encrypt files before uploading them to cloud storage"), independent of the sync-friction
  caveats in §2.2 — for a one-shot "encrypt, then upload once" archive (not a live-synced
  volume), the sync-friction downside doesn't bite, which is consistent with this report's
  §2.2/§7 workflow-fit framing.
- Advocates a **risk-tiered "bright lines" approach** rather than blanket encryption:
  decide up front what must never touch a provider unencrypted (e.g., sensitive interview
  transcripts) vs. what's acceptable in the clear (e.g., a final published article) —
  matching the same effort-proportional-to-stakes logic as the EFF framework, but with a
  concrete legal mechanism and a real case behind it.
- Also recommends checking a provider's published transparency report to gauge its actual
  exposure to legal process — a practical due-diligence step this report's other sources
  don't mention.

~ Micah Lee and EFF.org were searched specifically for a comparable applied writeup;
none was found matching this framing (Lee's visible work is adjacent — critiquing
providers with weak/no user-controlled-key encryption — not a dedicated "cloud storage
threat model" document). Flag as **not found**, not as "doesn't exist."

### 6.4 Individual key/passphrase management (not team workflows)

- ✓ Baseline consensus: store the passphrase in a password manager, **never inside the
  same synced location it protects** (breaks the "one compromise = total loss" chain).
- ~ Encrypted export + 3-2-1 backup (3 copies, 2 media, 1 offsite) is the repeated
  Privacy Guides community recommendation for the encrypted vault itself — with the
  acknowledged residual single point of failure: the one passphrase protecting the
  export.
- ~ Bundling all recovery material (password-manager export, 2FA backup codes) inside one
  encrypted vault, so only one passphrase must be remembered, was raised in the same
  community thread — with an explicit dissenting concern: tool-abandonment risk (what if
  the chosen tool stops being maintained — a real risk given Picocrypt's own 2025 freeze,
  §2.2).
- ✓ **Cryptomator's built-in recovery-key mechanism** is a concrete, well-documented
  counter-example to the "extrapolation only" pattern above — official docs
  ([docs.cryptomator.org](https://docs.cryptomator.org/desktop/password-and-recovery-key/)):
  a human-readable recovery key derived from the vault's master key, independent of the
  vault password, meant to be stored in a password manager or printed on paper. The vault
  password itself is not persisted to disk unless the user opts into OS-keychain storage.
  Third-party plugins exist to store the vault password in KeePassXC/Bitwarden Secrets
  Manager. This is a purpose-built answer to the "don't lose the only key" problem, not a
  generic technique borrowed from elsewhere.
- ✓ **age-plugin-yubikey** ([github.com/str4d/age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey))
  gives hardware-backed age identities via a YubiKey's PIV applet — private key material
  is non-exportable even with physical possession + PIN (3 failed PIN attempts locks it;
  3 failed PUK attempts permanently locks the PIV applet). ~ A documented community backup
  pattern (independent blog, moderate credibility) is: primary YubiKey as daily driver +
  a second YubiKey in a fireproof safe + a passphrase-protected software identity as a
  third fallback, with files encrypted to at least two recipients so no single lost/broken
  key causes data loss.
- **Shamir Secret Sharing** (`ssss` and similar) and generic **YubiKey-gated keys**
  (VeraCrypt and KeePass both support hardware keyfile/challenge-response) are real,
  well-documented techniques — but essentially all found *generic* usage examples are
  from the crypto-wallet seed-phrase world, not documented specifically for
  cloud-file-encryption passphrases. Applying either to this use case beyond the two
  concrete examples above is a reasonable, low-risk extrapolation, not a verified
  community practice — flagged accordingly (? unverified for this specific application,
  though the underlying techniques are sound and independently verified).

### 6.5 PrivacyGuides.org curated recommendations (✓ fetched directly)

- **Cryptomator** — their top pick specifically for cloud storage, for the reasons in §2.1.
- **VeraCrypt** — recommended for disk/container encryption, not cloud sync; suggested
  config is AES + SHA-512 (not a cascade).
- **OS-native encryption** (BitLocker/FileVault/LUKS) — preferred where applicable
  because of hardware-backed key storage (TPM/Secure Enclave); not applicable to files
  headed to third-party cloud storage.
- **Kryptor, Tomb** listed under command-line file encryption.
- No tool is explicitly flagged as insecure on that page — criticism is confined to
  complexity trade-offs (e.g., OpenPGP judged too complex for casual file encryption),
  not security condemnation of any specific tool.

---

## 7. Design principles distilled

1. **Assume the multi-snapshot malicious host from day one.** Single-snapshot-safe
   designs (EncFS-class) fail against any cloud host that retains version history.
2. **Default to non-deterministic, semantically-secure encryption.** Nothing about
   cloud storage forces determinism (unlike git); reach for SIV/convergent encryption
   only if dedup is an explicit, deliberately accepted trade, and mix in a per-user
   secret if so (never derive the key from content alone).
3. **Metadata is the real battle.** Names, sizes, tree shape, and change cadence leak
   more in practice than content — fixed-size blocks (CryFS) hide the most; Padmé
   padding is the cheap middle ground; access/change timing generally cannot be padded away.
4. **AEAD everything, including key wraps; bind everything to position.** Every
   real-world break in the E2EE-cloud-storage literature since 2022 (MEGA, CCS 2024)
   was an authenticity/binding failure, not a broken cipher.
5. **Freshness needs an explicit witness.** Cloud storage has no built-in Merkle DAG
   (unlike git) — a monotonic counter or out-of-band head comparison (SUNDR/Depot
   lineage) is required to detect rollback/staleness.
6. **Rotation is forward-only; history is forever** on any host that retains versions.
   Envelope encryption + lazy revocation makes rotation cheap going forward, but nothing
   retroactively protects already-uploaded ciphertext.
7. **Match the tool to the workflow, not just the cipher.** The dominant real-world
   failure mode in this space is workflow mismatch (VeraCrypt monolithic containers
   fighting incremental sync, Picocrypt used for continuous folder sync it wasn't
   designed for) — not weak cryptography. Live-synced folder vs. one-shot sealed
   archive is the first decision, before choosing a specific tool.
8. **KDF cost should max out what the workflow tolerates.** A local encrypt-before-upload
   tool has no login-latency budget — use RFC 9106's heavier Argon2id profile (2 GiB),
   not OWASP's server-oriented lighter one.
9. **The strongest concrete threat is access-control failure, not cryptanalysis.**
   Both corroborated real-world incidents (Dropbox 2012, Ateam 2023) were
   credential/permission failures. Client-side encryption's real value is turning "a
   sharing mistake exposes your files" into "a sharing mistake exposes an opaque blob."

---

## 8. Relevance to Blindkey

Blindkey's existing design already embodies most of §7 — useful validation and a map of
what a future sync feature (ROADMAP: "sync/merge" pending) must NOT regress:

| Principle (§7) | Blindkey today |
|---|---|
| Multi-snapshot adversary | UC-07 threat model; single `.vlt` blob = no per-entry churn leakage (an observer sees only "vault changed") |
| Non-deterministic by default | XChaCha20-Poly1305 STREAM with fresh nonces — no forced determinism, unlike git-oriented tools |
| Metadata | Zero plaintext metadata (stronger than Cryptomator/gocryptfs/rclone crypt); Padmé `PadMode` opt-in for size channel (`padme_padding_research.md`); mtime/frequency channel remains (documented) |
| AEAD + binding | XChaCha20-Poly1305 STREAM, encrypt-then-MAC, HMAC'd header/blocks (C9/C10 as amended by G0.2) |
| Freshness witness | C17 rollback anchor — per-`vault_id` monotonic counter; exactly the SUNDR-gap fix the literature prescribes, and it generalizes cleanly to any cloud backend |
| Rotation | Full-save KDF upgrades (G0.3) avoid the header-only-rotation trap Everspaugh et al. proved insufficient |
| Workflow fit | Single-file vault model sidesteps the VeraCrypt monolithic-container sync problem *and* the Cryptomator/gocryptfs per-file-tree metadata leak — but see the implication below |
| KDF cost | Argon2id floor **and** ceiling enforced on open — matches the "no login-latency constraint" reasoning in §4 |

Implications for future work:

1. **Cloud sync as a Blindkey feature** (if ever pursued): the whole-blob model means each
   save = a new full blob upload → every sync produces size + timing metadata (§5.2,
   §6.1's own analysis of the S3/Drive incidents underscores that access-control
   mistakes, not crypto, are the dominant real risk — worth weighing if any sharing/link
   feature is ever considered). The literature-backed shape is opaque single-blob
   transport + the existing C17 counter for freshness; do **not** move to per-entry
   files for diff-friendliness — that would trade away the metadata profile that
   differentiates Blindkey from Cryptomator/gocryptfs/rclone crypt (§5.2 tension).
2. **Multi-snapshot size channel**: with Padmé off (default), a backend retaining every
   version sees a fine-grained size trajectory ≈ entry-count history. Strengthens the
   case in `padme_padding_research.md`'s v2-promotion criterion 2 (longitudinal
   adversary analysis) — now backed by community evidence that hosts *do* retain
   long version histories (Dropbox Rewind, Drive version history) by default.
3. **Building-block choice, if any custom crypto surface is ever extended**: §4's
   findings reinforce Blindkey's existing non-custom-crypto stance (AG4/cowork.yaml) —
   libsodium-class audited primitives, not bespoke constructions, is the safest 2026
   default; RustCrypto's audit coverage is improving but still per-crate.
4. **Docs/marketing**: the CCS 2024 "broken ecosystem" and CRYPTO 2024 formal-model
   results remain strong citations for Blindkey's "verify the claims" positioning.
   Evaluating blindkey-core against the eprint 2024/989 malicious-server games is a
   candidate differentiating exercise for `docs/THIRD_PARTY_AUDIT.md`. The real-breach
   evidence in §6.1 (access-control, not crypto, failures) is also useful supporting
   material for Blindkey's threat-model narrative in README/THREAT_MODEL.md.

---

## 9. Tool fit quick reference

- **Continuous multi-device sync to Dropbox/Drive/OneDrive:** Cryptomator (best platform
  coverage) or gocryptfs (best throughput, Linux/CLI-only) or CryFS (best metadata
  privacy, weaker large-file performance).
- **A single folder, encrypt once, upload once:** age (scriptable, pipe-friendly, no
  audit but simple/reviewed design) or Picocrypt-NG (audited crypto core, unaudited fork
  changes) over VeraCrypt (sync-hostile) or bare 7-Zip (remember to enable filename encryption).
- **Any cloud bucket via one tool that also handles transport:** rclone crypt — accept
  deterministic filenames and computable sizes, no rekey without full re-upload.
- **Versioned encrypted backups:** restic or Kopia (opaque blobs, dedup); borg if you
  control an SSH-capable server, or wait for borg2 GA.
- **Building a custom tool:** libsodium/PyNaCl for a simple, best-audited default; Tink
  if you need built-in key-rotation/envelope-encryption scaffolding.
- **Avoid:** EncFS (failed audit, unmaintained), eCryptfs (kernel-unmaintained), VeraCrypt
  as a *live-synced* volume (works fine as a one-time archive), Picocrypt for continuous
  folder sync (wrong workflow, not a crypto weakness).

---

## References

**Academic (all ✓ verified unless noted):**
Bellare–Keelveedhi–Ristenpart, MLE, EUROCRYPT 2013 — [eprint 2012/631](https://eprint.iacr.org/2012/631) ·
DupLESS, USENIX Sec 2013 — [eprint 2013/429](https://eprint.iacr.org/2013/429) ·
Harnik et al., dedup side channels, IEEE S&P Mag 2010 ·
Ahmad et al., convergent-encryption dedup hardening, *Concurrency and Computation* 2024 — [doi:10.1002/cpe.8205](https://onlinelibrary.wiley.com/doi/abs/10.1002/cpe.8205) ·
Bellare–Boldyreva–O'Neill, deterministic PKE, CRYPTO 2007 — [eprint 2006/186](https://eprint.iacr.org/2006/186) ·
Rogaway–Shrimpton, SIV/DAE, EUROCRYPT 2006 — [eprint 2006/221](https://eprint.iacr.org/2006/221) ·
Nikitin et al., PURBs/Padmé, PoPETs 2019 — [arXiv:1806.03160](https://arxiv.org/abs/1806.03160) ·
Messmer et al., CryFS, DBSec 2017 — [eprint 2017/773](https://eprint.iacr.org/2017/773) ·
Amjad–Kamara–Moataz, snapshot adversaries — [eprint 2018/195](https://eprint.iacr.org/2018/195) ·
Blackstone–Kamara–Moataz, leakage abuse, NDSS 2020 ·
Li et al., SUNDR, OSDI 2004 · Mahajan et al., Depot, OSDI 2010 ·
Kallahalla et al., Plutus, FAST 2003 ·
Backes–Cachin–Oprea, lazy revocation — [eprint 2005/334](https://eprint.iacr.org/2005/334) ·
Everspaugh et al., key rotation for AE, CRYPTO 2017 ·
Lehmann–Tackmann, updatable encryption, EUROCRYPT 2018 — [eprint 2018/118](https://eprint.iacr.org/2018/118) ·
MEGA attacks, IEEE S&P 2023 — [eprint 2022/959](https://eprint.iacr.org/2022/959) ·
Formal E2EE cloud storage, CRYPTO 2024 — [eprint 2024/989](https://eprint.iacr.org/2024/989) ·
Broken Ecosystem, CCS 2024 — [eprint 2024/1616](https://eprint.iacr.org/2024/1616.pdf) ·
Nextcloud E2EE — [eprint 2024/546](https://eprint.iacr.org/2024/546) ·
RFC 9106 (Argon2) — [datatracker.ietf.org/doc/rfc9106](https://datatracker.ietf.org/doc/rfc9106/)

**Audits:** EncFS — [defuse.ca/audits/encfs.htm](https://defuse.ca/audits/encfs.htm) (Hornby 2014) ·
gocryptfs — [defuse.ca/audits/gocryptfs.htm](https://defuse.ca/audits/gocryptfs.htm) (Hornby 2017) ·
Cryptomator — Cure53 2017 · restic — [Valsorda review 2017](https://words.filippo.io/restic-cryptography/) ·
VeraCrypt — [QuarksLab 2016](https://blog.quarkslab.com/resources/2016-10-17-audit-veracrypt/16-08-215-REP-VeraCrypt-sec-assessment.pdf) ·
libsodium — [Matthew Green / PIA 2017](https://www.privateinternetaccess.com/blog/libsodium-audit-results/) ·
Picocrypt — Radically Open Security 2024 (see [tracking issue](https://github.com/Picocrypt/Picocrypt/issues/32))

**Tools:** [Cryptomator](https://docs.cryptomator.org/security/architecture/) ·
[gocryptfs](https://github.com/rfjakob/gocryptfs) · [CryFS](https://www.cryfs.org/howitworks) ·
[securefs](https://github.com/netheril96/securefs) · [age](https://github.com/FiloSottile/age) ·
[rage](https://github.com/str4d/rage) · [Picocrypt](https://github.com/Picocrypt/Picocrypt) ·
[Kryptor](https://www.kryptor.co.uk/) · [VeraCrypt](https://veracrypt.io) ·
[restic](https://restic.readthedocs.io/) · [borg](https://github.com/borgbackup/borg) ·
[rclone crypt](https://rclone.org/crypt/) · [Kopia](https://kopia.io/docs/advanced/encryption/) ·
[duplicity](https://duplicity.gitlab.io) · [Tahoe-LAFS](https://tahoe-lafs.org) ·
[libsodium](https://libsodium.org) · [Google Tink](https://github.com/tink-crypto/tink)

**Standards/guidance:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) ·
[PrivacyGuides.org encryption](https://www.privacyguides.org/en/encryption/) ·
[EFF Surveillance Self-Defense — Your Security Plan](https://ssd.eff.org/module/your-security-plan) ·
[Freedom of the Press Foundation — journalist's digital security checklist (2026)](https://freedom.press/digisec/blog/journalists-digital-security-checklist/) ·
NIST SP 800-209, SP 800-111 · ENISA cryptographic measures + NIS2 (Oct 2024) guidance ·
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) ·
[Cryptomator recovery key docs](https://docs.cryptomator.org/desktop/password-and-recovery-key/) ·
[ssss (Shamir's Secret Sharing)](https://point-at-infinity.org/ssss/)

**Community/incidents (representative):** [HN 32092185](https://news.ycombinator.com/item?id=32092261) (gocryptfs vs Cryptomator) ·
CryFS comparison — [cryfs.org/comparison](https://www.cryfs.org/comparison) ·
Privacy Guides forum, key-management thread — [discuss.privacyguides.net/t/27354](https://discuss.privacyguides.net/t/27354) ·
[rclone crypt vs Cryptomator discussion](https://discuss.privacyguides.net/t/recommendation-encryption-rclone-crypt-as-an-alternative-to-cryptomator/12453) ·
[rclone filename-length issue #2040](https://github.com/rclone/rclone/issues/2040) ·
[rclone block-level sync feature request](https://forum.rclone.org/t/block-level-file-sync-or-chunking-with-crypt-backend/30855) ·
Dropbox 2012 breach disclosure (2016) · Dropbox Sign breach (May 2024) ·
Ateam Google Drive misconfiguration (disclosed Dec 2023) ·
Datadog 2024 State of Cloud Security Report (S3 exposure rate)

**Explicit unresolved gaps (flagged ? — verify before treating as load-bearing):**
- gocryptfs "integrity-protection imperfections" audit claim — sourced only from an
  unlinked HN commenter reference; trace to the actual audit report before citing.
- "~Half of S3 buckets misconfigured" (2025) and "over half contain PII" — secondary
  tech-media claims with no traceable primary source; the Datadog ~1.5% figure is the
  defensible one.
- Google Tink and Kopia: no third-party audit report found (absence-of-evidence, not evidence of absence).
- Shamir Secret Sharing / YubiKey challenge-response applied specifically to
  cloud-encryption passphrases: real, sound techniques, but documented usage found was
  crypto-wallet-seed-specific — applying to this use case is extrapolation, not a
  verified community practice.
- Reddit-specific primary threads (vs. HN/forum secondary discussion) were largely not
  surfaced by search this session — community-consensus claims lean on HN, Cryptomator
  forum, and Privacy Guides forum instead.
- **VeraCrypt + cloud-sync "corruption"** specifically (as opposed to inefficient
  re-upload / sync-conflict behavior) — no first-hand community report of actual data
  corruption was located, despite the mechanical reason (monolithic container) being
  well established. Don't overstate this beyond "inefficient/conflict-prone."
- **Picocrypt and 7-Zip community sentiment on cloud-backup fit** — both areas came back
  thin/inconclusive in the gap-fill pass; no concrete forum threads were located.
- **NIST/ENISA guidance specifically for individual pre-upload encryption** — does not
  appear to exist in the 2023–2026 window; the closest ENISA document on this exact
  topic is from 2013 (outside the window), and 2024–2025 ENISA output (NIS2 technical
  guidance) is organizational/provider-facing, not personal-workflow-facing.
- A dedicated 2023–2026 "confidential cloud backup for individuals" academic paper was
  not found; nearest literature is TEE/FHE confidential-computing work (different
  problem) and enterprise-facing NIST/ENISA guidance.
