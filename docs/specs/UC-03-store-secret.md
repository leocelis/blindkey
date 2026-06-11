# UC-03 — Store a Secret

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-3 · **Constraints:** C18, C19, C17, C11 (touches C10, C16, C26)
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

`vault add NAME` end to end: the entry data model, the serialization format *inside* the encrypted
payload, the inner-stream double encryption of Protected fields, the in-memory secret types, the
add flow, the atomic save, and how `vault_version` increments. Out of scope: retrieval/delivery
(UC-4/UC-5), search (UC-6), import (UC-12).

Goals, in constraint terms: every field of every entry — including URLs, titles, tags, and
timestamps — lives inside the AEAD payload (C18); passwords and OTP secrets get a second
ChaCha20 pass under a per-open inner stream key (C19); the vault stays a single opaque blob with
no per-entry files (C17); in memory, secrets exist only in zeroize-on-drop types (C11).

## 2. Prior art

### 2.1 Open source

- **KDBX 4** ([spec](https://keepass.info/help/kb/kdbx_4.html);
  [palant.info walkthrough](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/)):
  the inner header + "inner random stream" protecting password fields inside the encrypted payload
  — C19 copies this design, substituting plain ChaCha20 for Salsa20/ChaCha20 variants. KDBX's
  header fields are themselves a type-length-value encoding — precedent for §3.2.
- **KeePassXC** ([Molotnikov audit, 2023](https://keepassxc.org/blog/2023-04-15-audit-report/)):
  the audit's unresolved finding — in-memory secrets not encrypted/zeroized aggressively — is what
  C11 answers at the type level with `zeroize`/`secrecy`.
- **Bitwarden Security White Paper**: per-cipher random keys with randomized IVs — supporting
  evidence that randomized (never deterministic) entry encryption is the industry-correct model.
- **pass** ([passwordstore.org](https://www.passwordstore.org/)): the anti-pattern C17 exists to
  kill — per-entry plaintext-named files leaking the whole taxonomy via `ls` and git history.
- **RustCrypto `zeroize` / `secrecy`** crates: volatile-write + fence zeroization and
  `[REDACTED]`-on-Debug wrappers (C11).
- **RUSTSEC-2021-0127**: `serde_cbor` is unmaintained — disqualifying it in §4.

### 2.2 Academic / standards

- **Grubbs, Sekniqi, Bindschaedler, Naveed, Ristenpart (IEEE S&P 2017),
  [eprint 2016/895](https://eprint.iacr.org/2016/895)** and **Cash, Grubbs, Perry, Ristenpart
  (CCS 2015)**: leakage-abuse attacks recovering ~99% of first names from deterministic
  ciphertext — why entries are never deterministically or individually-observably encrypted.
- **Hoang, Reyhanitabar, Rogaway, Vizár — "Online Authenticated-Encryption and its Nonce-Reuse
  Misuse-Resistance", CRYPTO 2015**: the STREAM construction the payload rides in (C1).
- **Wheeler — "zxcvbn: Low-Budget Password Strength Estimation", USENIX Security 2016**: the
  estimator behind the C26 weak-password warning in the add flow.
- **palant.info LastPass post-mortems (2022)**: plaintext URLs enabled precision phishing — the
  origin of C18's "zero plaintext fields, timestamps included".

## 3. Proposed design

### 3.1 Entry data model

```rust
/// Lives ONLY inside the decrypted payload, in mlock'd memory (C12). No field of this
/// struct is ever serialized outside the AEAD body (C18).
pub struct Entry {
    pub id: Uuid,                            // 16 B, random, generated once
    pub title: String,
    pub username: String,
    pub password: Protected,                 // C19: inner-stream double-encrypted at rest
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub otp_secret: Option<Protected>,       // C19
    pub created_at: i64,                     // unix seconds — encrypted like everything else
    pub modified_at: i64,
    pub expires_at: Option<i64>,
    pub custom_fields: Vec<CustomField>,     // name + value + protected flag
}

/// Secret-bearing value. Zeroized on drop; Debug prints "[REDACTED]" (C11).
pub struct Protected(SecretBox<[u8]>);
```

Non-secret fields (`title`, `url`, …) may use `String` *inside the payload model* — C11 binds key
material and Protected values, while C18 is satisfied by the model never existing outside the AEAD
boundary. The decrypted payload buffer as a whole is `Zeroizing` + mlock'd (C12), so even
non-Protected strings are wiped on lock.

### 3.2 Payload serialization: custom bounded TLV

**Decision: a hand-rolled TLV encoding. Rejected: `bincode`, CBOR (`serde_cbor`/`ciborium`),
`postcard`** — see §4 for the table.

Justification: (a) the trust boundary stays serde-free — the encoder/decoder is ~200 auditable
lines with explicit bounds, matching the hardened-parser posture of UC-10; (b) KDBX 4 demonstrates
the pattern at production scale; (c) unknown-tag-skip gives forward compatibility without a schema
compiler; (d) the layout is byte-deterministic, which keeps C4's "payload ciphertext identical
after password rotation" test meaningful. The payload parser runs on *authenticated* plaintext
(every STREAM tag and block HMAC verified first — C1/C10), so its threat level is below the header
parser's, but it is still fuzzed (§6).

Record shape, all integers little-endian:

```
record := tag u16 | len u32 | value [len]
```

- **Tag bit 15 (0x8000) = Protected**: any record whose tag has the P bit set has its `value`
  encrypted by the inner stream (§3.3) before being placed in the payload.
- `len` is validated against the remaining buffer before any allocation; per-field cap 1 MiB,
  whole-payload structural recursion depth 1 (entries contain fields; nothing nests deeper).
- Unknown tags: skip `len` bytes (forward compat); writers never emit tags they don't define.

Payload layout:

```
0x0001 inner_stream_algorithm   u8 = 1 (ChaCha20)        ┐ inner header (C19)
0x0002 inner_stream_key         [64]                     ┘
0x0010 vault_version            u64                        (C16)
0x0020 entry                    nested records, one per entry:
       0x01 id[16] · 0x02 title · 0x03 username · 0x8004 password (P)
       0x05 url · 0x06 notes · 0x07 tag (repeated) · 0x8008 otp_secret (P)
       0x09 created_at i64 · 0x0A modified_at i64 · 0x0B expires_at i64
       0x0C custom_name · 0x0D custom_value | 0x800D custom_value (P)
0x0000 end-of-payload
```

### 3.3 Inner-stream double encryption (C19, KDBX4-style)

- On every vault **open**, generate a fresh `inner_stream_key: [u8; 64]` from OsRng. Bytes 0–31 key
  ChaCha20; bytes 32–63 provide IV/counter material, following the KDBX 4 convention of feeding the
  full 64 bytes to the construction. The key is stored in the inner header — i.e. *inside* the AEAD
  payload, never in the plaintext header.
- All Protected values are passed through **one sequential ChaCha20 keystream in document order**
  (not independently keyed per field): writers encrypt field values in the exact order the records
  are emitted; readers decrypt in the same order. Reordering records therefore garbles Protected
  values — the canonical order in §3.2 is normative.
- Effect: code that decrypts the outer payload but hasn't consumed the inner header cannot read
  password bytes; a partial payload disclosure (bug, memory dump of the serialized buffer) does not
  directly expose Protected fields. Regeneration per open means the inner key is never a persistent
  static target (intent C19 wording).
- Consequence worth stating: because the inner key changes per open, **any save rewrites the whole
  payload** — acceptable, since a save already re-runs STREAM encryption end to end.

### 3.4 In-memory secret types (C11)

| Material | Type | Why |
|---|---|---|
| master password | `Zeroizing<String>` | wiped on drop; exists only during KDF |
| master/data/wrapping/payload keys | `Secret<[u8; 32]>` | no Debug/Clone leakage |
| inner stream key | `Secret<[u8; 64]>` | per-open, dropped on lock |
| Protected field plaintext | `SecretBox<[u8]>` | heap, zeroized, mlock'd |
| serialized plaintext payload buffer | `Zeroizing<Vec<u8>>` in mlock'd region | the one buffer that transiently holds everything |

CI grep gates from the C11 `test:` block apply to the modules introduced here
(`entry.rs`, `payload.rs`).

### 3.5 The add flow

```
vault add github-prod --username leo --url https://github.com/org
```

1. Unlock: prompt master password (no echo, TTY) → UC-10 verification pipeline → data key from the
   password stanza → decrypt payload into mlock'd memory.
2. Prompt entry password — `Password [Enter = generate]`; Enter invokes the `vault gen` CSPRNG path
   (C26). A typed password is estimated with zxcvbn; < 60 bits ⇒ stderr WARNING suggesting
   `vault gen`, but the add proceeds (warn-don't-block, C26).
3. Reject duplicate `NAME` (titles are unique keys for the CLI; the stable identity is `id`).
4. Build `Entry` (`created_at = modified_at = now`), append to the in-memory entry list.
5. `vault_version += 1` (§3.7), re-serialize (§3.2), inner-encrypt Protected fields (§3.3),
   STREAM-encrypt, wrap in HmacBlockStream blocks with a **freshly generated `master_seed`** (C8),
   recompute `header_hash`/`header_hmac`, atomic save (§3.6), update the local rollback anchor
   (C16), zeroize the serialization buffer.

### 3.6 Atomic save (temp + rename + fsync)

Same mechanism as UC-01 §3.6 with two differences for the overwrite case:

1. Take an advisory `flock(LOCK_EX)` on the vault file for the whole read-modify-write (two
   concurrent `vault add`s must serialize — coverage-gap C1).
2. Write `vault.vlt.tmp.*` (0600, same dir) → `fsync` file → rename **over** the target (plain
   atomic rename; replacement is intended here) → `fsync` directory. The previous generation is
   first hard-linked to `vault.vlt.bak` so a verified-good predecessor survives until the next save.
3. On any failure the target is untouched; the temp file is unlinked best-effort.

### 3.7 `vault_version` increments

- `vault_version` lives **inside the payload** (C16/C18 — even the counter is invisible to the
  sync backend). Initialized to 0 at `init`; **every payload-mutating save increments it by
  exactly 1** (`add`, `edit`, `rm`, `import`, `merge`).
- Header-only operations (password change, `upgrade-kdf`, stanza enrollment) re-wrap stanzas
  without touching the payload, so they cannot and do not increment it — that is exactly C4's
  "payload ciphertext byte-for-byte identical" property. (The rollback-detection consequence is
  flagged in UC-11 §7.)
- The increment is computed from the *decrypted* counter under the §3.6 flock, then mirrored to the
  local state file only after the rename succeeds — so a failed save never advances the anchor.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| `bincode` | fast, tiny output | not self-describing; field/enum evolution silently breaks old payloads; serde in trust boundary | Rejected |
| CBOR via `serde_cbor` | self-describing standard | **unmaintained (RUSTSEC-2021-0127)** | Rejected |
| CBOR via `ciborium` | maintained, RFC 8949 | pulls full serde machinery into the security core; canonical byte layout and hard bounds are harder to enforce/audit | Rejected — strongest contender |
| `postcard` | compact, embedded-grade | serde again; varint framing complicates bounded reads | Rejected |
| **custom TLV** | ~200 auditable lines, zero deps, explicit bounds, KDBX precedent, P-bit elegance | we own the code (mitigated: it's fuzzed, and it parses post-AEAD data) | **Chosen** |
| per-entry random keys (Bitwarden model) | finer compromise containment | extra key hierarchy for no leakage win inside one AEAD blob; complicates C4's identity test | Rejected for v1; revisit with `rotate-data-key` (gap C2) |
| independently keyed Protected fields | random access to one secret | KDBX-divergent; more nonce bookkeeping; intent specifies the sequential stream | Rejected — intent wins |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C18 | every field incl. `created_at`/`modified_at`/`expires_at`, tags, URL serialized only via §3.2 inside the STREAM payload; plaintext header holds no entry-typed field (type-level test below) |
| C19 | inner header records 0x0001/0x0002 inside the payload; 64-byte per-open CSPRNG key; Protected fields ChaCha20-passed sequentially in document order before AEAD |
| C17 | one blob, one rename target; entries never become files; only `vault.vlt` (+ `.bak`) in the vault dir; state file lives at the XDG path |
| C11 | §3.4 type table; no plain `Vec<u8>`/`[u8; N]` for key material; Debug prints `[REDACTED]`; CI grep gates |
| C10 (touched) | save re-blocks the new ciphertext with fresh `master_seed`-keyed HMACs |
| C16 (touched) | +1 per payload save, computed under flock, anchor updated post-rename |
| C26 (touched) | zxcvbn warning path in the add flow, generation offered by default |

## 6. Test plan

From the intent `test:` blocks: C18's `strings`/`xxd` no-leak integration tests (the canonical
"github-prod" probe); C19's two-stage decryption unit tests; C17's single-file `ls` test and XDG
state-file placement; C11's drop-zeroization, Debug-redaction, and grep gates; C16's
init→save×3→version==3 test.

Spec-specific additions:

1. **TLV round-trip & fuzz**: `proptest` round-trip over arbitrary entries (incl. empty strings,
   1 MiB-cap fields, max tags); a `payload_parse` fuzz target alongside the UC-10 targets,
   asserting no panic/OOM on arbitrary authenticated-plaintext bytes.
2. **Unknown-tag skip**: payload containing tag 0x7FFF parses, preserving all known fields.
3. **P-bit enforcement**: serialize an entry, decrypt only the outer AEAD, locate record 0x8004,
   assert bytes ≠ plaintext password; apply inner stream, assert equality (C19's test, sharpened
   to the TLV offsets).
4. **Document-order dependency**: swap two Protected records post-encryption; assert decryption of
   the *second* yields garbage (documents the sequential-stream property).
5. **Timestamp encryption**: `xxd vault.vlt | grep` for the LE encoding of a known `created_at`;
   assert empty.
6. **Concurrent add**: two processes `add` under flock; assert both entries present and
   `vault_version` advanced by exactly 2.
7. **Crash-during-save**: SIGKILL between temp-write and rename; assert old vault intact and
   openable; after rename, assert new vault valid and `.bak` is the predecessor.

## 7. Open questions

1. **Field caps**: 1 MiB/field and (say) 100 k entries are parser bounds, not intent constraints —
   promote alongside C28+ so fuzz targets have normative limits?
2. **Timestamp granularity**: seconds are stored encrypted, but the file's *mtime* still leaks save
   times to the sync backend (documented residual leak in [THREAT_MODEL.md](../THREAT_MODEL.md)).
   Worth coarsening `modified_at` to days for plausible-deniability? Likely no — defer.
3. **Duplicate titles**: hard error vs auto-suffix (`github-prod-2`)? Spec says hard error; confirm
   ergonomics with UC-12 import (imports may collide heavily).
4. **`.bak` retention**: one generation kept (gap C1). Should `--no-backup` exist for users whose
   threat model dislikes a second ciphertext copy? (Both are equally opaque; default keep.)
