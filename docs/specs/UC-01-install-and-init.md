# UC-01 — Install and Create a Vault

> **Tech spec** · Accepted v0.2 · implemented pre-1.0 · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-1 · **Constraints:** C20, C2, C4, C5, C7, C8 (touches C9, C16, C26)
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Everything from `cargo install vault-cli` to a valid, openable, single-stanza vault file on disk:
the static build strategy, the `vault init` interactive flow (prompt budget, timing), master-password
entry, data-key generation, password-stanza wrapping, header serialization, atomic file creation,
and the on-disk directory/state layout. Out of scope: adding entries (UC-03), hardware stanzas
(UC-9), opening existing/hostile files (UC-10).

Goals, in constraint terms: a statically linked binary with one-command install (C20); `init` →
first entry in **< 5 prompts and < 60 s** (C20); Argon2id defaults m=64 MiB/t=3/p=4 (C2); a CSPRNG
data key never derived from the password (C4); a password stanza that always exists (C5); a
versioned, magic-prefixed file (C7) whose KDF params live in the file, not the binary (C8).

## 2. Prior art

### 2.1 Open source

- **age / rage** ([C2SP age spec](https://github.com/C2SP/C2SP/blob/main/age.md);
  [str4d/rage](https://github.com/str4d/rage), the Rust implementation): the file-key + stanza
  envelope we copy (C4/C5), and proof that a Rust crypto CLI ships as a small static binary. age
  uses scrypt for its passphrase stanza; we deliberately substitute Argon2id (RFC 9106), a
  documented deviation already recorded in the intent and [CRYPTO.md](../CRYPTO.md).
- **KeePassXC** ([KDBX 4](https://keepass.info/help/kb/kdbx_4.html)): database-creation wizard
  ordering (password → confirm → KDF params), and the header layout C8 mirrors. Its
  [Molotnikov audit (2023)](https://keepassxc.org/blog/2023-04-15-audit-report/) motivates our
  Argon2id (not Argon2d) default.
- **pass / gopass** ([passwordstore.org](https://www.passwordstore.org/)): `pass init` is the
  one-command baseline to beat; gopass's refusal to take secrets on argv informs our prompt-only
  password entry (coverage-gap B1).
- **rpassword crate** (RustCrypto-adjacent, used widely for no-echo prompts): reads from the
  controlling TTY with echo disabled — our prompt model.
- **tempfile crate** + `renameat2(2)`/`RENAME_NOREPLACE` (Linux ≥ 3.15): the write-to-temp +
  atomic-rename pattern in §3.6.

### 2.2 Academic / standards

- **RFC 9106** (Argon2) — parameter defaults and the requirement that Argon2id be supported.
- **Hoang, Reyhanitabar, Rogaway, Vizár — “Online Authenticated-Encryption and its Nonce-Reuse
  Misuse-Resistance”, CRYPTO 2015** — the STREAM construction used for the (initially empty) body.
- **OWASP Password Storage Cheat Sheet** — the m=19 MiB/t=2/p=1 floor recorded in the file.
- **XDG Base Directory Specification** (freedesktop.org) — state/config placement (§3.7).
- **Rust Edition Guide, musl support for fully static binaries** — the C20 build target.

## 3. Proposed design

### 3.1 Static build strategy

- **Pure-Rust crypto stack by default**: `chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`,
  `subtle`, `getrandom`, `zeroize`, `secrecy` (all permitted by C3). No C dependency means
  `cargo build --release --locked --target x86_64-unknown-linux-musl` cross-compiles without a C
  toolchain beyond musl-gcc for libc itself, and `ldd` reports *"not a dynamic executable"* (C20 CI
  gate). libsodium remains an approved alternative (C3) but is not the default — see §4.
- Targets: the four in the intent (`x86_64-unknown-linux-musl`, `aarch64/x86_64-apple-darwin`,
  `x86_64-pc-windows-msvc`). macOS/Windows link only their stable system libs (Security.framework /
  bcrypt come later with hardware stanzas, feature-gated in `vault-hardware`).
- `--locked` always; `rust-toolchain.toml` pins the compiler — groundwork for reproducible builds
  (coverage-gap D1, out of scope here).
- Hardware stanza support (libfido2 etc.) is feature-gated in `vault-hardware` and **off by
  default**, so the C20 binary never grows a dynamic dependency by accident.

### 3.2 `vault init` flow and the prompt budget

```
$ vault init                       # default path, see §3.7
Choose a master password: ████     # prompt 1  (no echo)
Confirm master password:  ████     # prompt 2  (no echo)
Created vault at ~/.vault/vault.vlt (Argon2id m=64 MiB, t=3, p=4)
There is no password reset. Losing every unlock factor loses the vault.
```

C20 requires init → **first entry added** in *fewer than* 5 prompts and < 60 s. Budget:

| # | Prompt | Command |
|---|--------|---------|
| 1 | master password | `vault init` |
| 2 | confirm master password | `vault init` |
| 3 | unlock (master password) | `vault add NAME --username U --url …` |
| 4 | entry password — “Password [Enter = generate with vault gen]” | `vault add` |

Total: 4 < 5. Consequence: in the golden path, **username and URL arrive as flags** (they are not
secrets; argv is acceptable for them — coverage-gap B1 forbids only secrets on argv). Timing: one
Argon2id derivation at init (~300 ms) + one at add (~300 ms) keeps the flow seconds-long, far under
the 60 s ceiling even with human typing.

`vault init --file PATH` overrides the location. If the target exists: hard error
`"refusing to overwrite existing file"` — init never destroys data.

### 3.3 Master-password entry

- Read from the controlling TTY (`/dev/tty`, `CONIN$` on Windows) with **echo disabled**,
  rpassword-style — never from argv (gap B1), and not from stdin by default so that piped stdin
  can't silently supply a weak password. `--password-fd N` is the explicit non-interactive escape
  hatch (consistent with [CLI.md](../CLI.md)).
- Confirmation prompt; on mismatch, re-prompt up to 3 times, then abort.
- The password lands directly in a `MasterPassword(Zeroizing<String>)` (C11); no intermediate
  `String`.
- **Advisory strength check** (C26 pattern, warn-don't-block): run `zxcvbn` on the candidate; if
  estimated entropy < 60 bits, print a stderr warning suggesting a diceware passphrase
  (`vault gen --charset words`). Never refuse — the floor is advisory for the *master* password.
- Unicode: normalize to **NFC** before Argon2id so the same passphrase typed on macOS (NFD-leaning
  input) and Linux derives the same key (coverage-gap E2; flagged in §7 pending intent promotion).

### 3.4 Key generation and password-stanza wrapping

```rust
pub struct DataKey(Secret<[u8; 32]>);            // C4, C11 — OsRng, never password-derived
pub struct MasterKey(Secret<[u8; 32]>);          // Argon2id output (IKM only, per C2)
pub struct PasswordStanza {                      // public bytes — safe to serialize
    wrap_nonce:  [u8; 24],                       // OsRng, fresh per (re)wrap
    wrapped_key: [u8; 48],                       // 32 B data key + 16 B Poly1305 tag
}
```

Creation algorithm (all randomness via `getrandom`/OsRng):

1. `vault_id ← UUIDv4` (16 B), `argon2id_salt ← 32 B`, `master_seed ← 32 B`, `nonce_prefix ← 16 B`, `data_key ← 32 B`.
2. `master_key = Argon2id(password_nfc, argon2id_salt, m=65536 KiB, t=3, p=4, out=32)` (C2).
3. `wrapping_key = HKDF-SHA-256(ikm=master_key, salt=vault_id, info="vault-pw-wrap-v1")` (C5 —
   the Argon2id output is IKM, never the wrapping key directly).
4. `wrapped_key = XChaCha20-Poly1305-Seal(wrapping_key, wrap_nonce, data_key)` → 48 B.
5. Stanza record: `stanza_type=1, stanza_data_len=72, stanza_data = wrap_nonce ‖ wrapped_key`
   (no `extra` bytes for the password type). C5: this stanza is mandatory; `stanza_count=1` at init.

### 3.5 Header serialization

Exactly the C8 layout (all integers little-endian); see [FILE_FORMAT.md](../FILE_FORMAT.md) for the
boxed diagram. Fixed prefix is **116 bytes** (`magic 4 + version 2 + vault_id 16 + kdf_algorithm 1 +
m/t/p 12 + salt 32 + master_seed 32 + nonce_prefix 16 + stanza_count 1`), followed by stanza records, then:

- `header_hash = SHA-256(magic ‖ … ‖ last stanza byte)` (C9, keyless corruption check);
- `header_hmac = HMAC-SHA-256(same bytes, key = HKDF-SHA-256(ikm=data_key, salt=b"",
  info="vault-header-hmac-v2"))` (C9 — data-key-keyed per G0.2, so every unlock path verifies it; KDF downgrade is caught by the password stanza tag).

Minimal init-time header: 116 + 77 (password stanza record) + 64 = **257 bytes**. Serialization is
hand-rolled field-by-field writes (no serde in the trust boundary), mirroring the hand-rolled
bounded parser of UC-10.

The body is written even for an empty vault: inner header + `vault_version=0` (C16) + zero entries,
TLV-encoded (UC-03 §3.2), STREAM-encrypted under
`payload_key = HKDF-SHA-256(ikm=data_key, salt=nonce_prefix, info="vault-payload-v1")` (C1), wrapped in
HmacBlockStream blocks keyed from `data_key`/`master_seed` (C10, `info="vault-block-hmac-v2"` — G0.2).

### 3.6 Atomic file creation

1. Create `vault.vlt.tmp.<pid>.<rand>` **in the destination directory** (same filesystem, so rename
   is atomic) with `O_CREAT|O_EXCL|O_WRONLY`, mode **0600** at creation time (no chmod-after-write
   window). Windows: `CREATE_NEW` + default-private user ACL.
2. Write header + body; `fsync` the file.
3. Atomically move into place **refusing to replace**: `renameat2(…, RENAME_NOREPLACE)` on Linux;
   `renamex_np(RENAME_EXCL)` on macOS; `MoveFileExW` *without* `MOVEFILE_REPLACE_EXISTING` on
   Windows; fallback `link(2) + unlink(2)` where none exists. This closes the TOCTOU between the
   §3.2 existence check and the rename.
4. `fsync` the directory (Unix) so the rename itself is durable.
5. On any failure: best-effort unlink of the temp file; the destination is never touched.

(For *saves* over an existing vault — UC-03 §3.6 — the same pattern runs with a replacing rename
plus a `.bak` generation; init is the no-replace special case.)

### 3.7 Directory and state-file layout

| Artifact | Default path (Linux) | Notes |
|---|---|---|
| Vault file | `~/.vault/vault.vlt` | overridable with `--file`; the directory holds exactly this one file (C17 test) |
| Rollback state | `$XDG_DATA_HOME/vault/<vault_id>.state` (`~/.local/share/vault/…`) | **never synced**; created at init with `last_seen = 0` (C16); macOS `~/Library/Application Support/vault/`, Windows `%APPDATA%\vault\` |
| Config | `~/.vault.toml` | optional; path fixed by C13/C25 |

Directories are created with mode 0700. The state file is plaintext (a u64 plus a cached KDF
throughput figure, UC-11 §3.4) — it contains no secret and must not, since it lives outside the
encrypted file.

### 3.8 Error paths

| Condition | Behavior |
|---|---|
| target file exists | abort before any prompt: `refusing to overwrite existing file` |
| password confirmation mismatch ×3 | abort, nothing written |
| `getrandom` failure | abort (never fall back to a weaker RNG) |
| temp write / fsync / rename failure | abort, unlink temp, destination untouched |
| state-file dir not writable | **warn and continue** — the vault is valid; rollback detection degrades (mirrors C12's graceful-degradation posture) |

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| libsodium (via -sys crate) as default crypto | PIA-audited C, secretstream built-in | C cross-compilation against musl; complicates "one static binary"; FFI = `unsafe` surface | Rejected as default; allowed by C3, revisit if RustCrypto gains an advisory |
| glibc + `crt-static` instead of musl | no musl quirks | not fully static in practice (NSS dlopen); intent names musl explicitly | Rejected — intent wins |
| scrypt passphrase stanza (age parity) | byte-compat with age tooling | C2 mandates Argon2id; scrypt lacks the id-variant side-channel posture | Rejected (documented deviation from age) |
| vault file in `$XDG_DATA_HOME` too | one root for everything | C17's test separates vault dir from state path; users sync the vault dir, state must never ride along | Rejected — separation is load-bearing |
| prompt for username during `add` golden path | zero flags to learn | blows the <5 prompt budget (would be #5) | Rejected for golden path; available via `--interactive` |
| `chmod 600` after write | simpler code | window where umask-default perms expose the file | Rejected — mode set at `open(2)` time |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C20 | musl static target + `ldd` CI gate (§3.1); 4-prompt budget table, < 60 s (§3.2); `cargo install vault-cli` only |
| C2 | defaults m=65536 KiB/t=3/p=4 baked into the *written file* (§3.4 step 2); salt 32 B OsRng, stored in header |
| C4 | data key from OsRng (§3.4 step 1), never password-derived, exists on disk only inside `wrapped_key` |
| C5 | password stanza mandatory and sole stanza at init; HKDF recipe with `info="vault-pw-wrap-v1"`, salt=`vault_id`; 48-byte wrapped_key (§3.4) |
| C7 | file begins `56 4C 54 00` + `format_version=1` u16 LE (§3.5) |
| C8 | full header layout serialized verbatim from runtime values; `vault_id`/salt generated once; `master_seed` fresh; binary holds defaults only for *writing*, never for reading |
| C9 (touched) | both integrity tags computed at creation so the very first open verifies cleanly |
| C16 (touched) | `vault_version=0` in payload; state file anchored at 0 |
| C26 (touched) | zxcvbn advisory warning on the chosen master password (§3.3) |

## 6. Test plan

Intent `test:` blocks already cover: C20 CI musl/ldd + Docker fresh-install round-trip; C2 timing
and floor tests; C4 dual-vault distinct-data-key and re-wrap tests; C5 no-password-stanza hard
error; C7 magic/version tests; C8 round-trip serialization identity.

Spec-specific additions:

1. **Prompt-count harness**: drive `init` + `add` via a PTY; assert exactly 4 prompts (C20).
2. **Atomicity**: kill the process (SIGKILL) at randomized points during §3.6 steps 1–4; assert the
   destination either doesn't exist or is a fully valid vault — never a partial file.
3. **No-replace**: pre-create the destination; assert `init` exits non-zero before prompting.
4. **Permissions**: assert `stat` mode 0600 on the vault file and 0700 on created dirs, *including*
   on the temp file mid-write (inject a pause).
5. **NFC**: init with an NFD-encoded password; reopen supplying the NFC encoding; assert unlock
   succeeds (pending §7 Q2).
6. **State anchor**: after init, assert `<vault_id>.state` exists at the XDG path with value 0.
7. **Fuzz round-trip** (ties to UC-10): serialize the init-produced header, parse it with the
   hardened parser, assert field-for-field equality.

## 7. Open questions

1. **Default vault path** `~/.vault/vault.vlt` vs `$XDG_DATA_HOME/vault-file/`: the C17 test implies
   a dedicated vault dir distinct from the state path; confirm the dotted-home choice before M6.
2. **NFC normalization (gap E2)** is adopted here but not yet an intent constraint — promote
   (candidate C41) before M2 freeze, since it changes key derivation irreversibly.
3. **Non-interactive `init`** (`--password-fd`): in scope for v1 CI users (P4), or M9?
4. Should init offer an optional **recovery-code stanza** (gap C3 proposal C37)? One extra prompt
   would consume the remaining budget headroom.
