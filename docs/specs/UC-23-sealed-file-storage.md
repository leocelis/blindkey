# UC-23 — Seal Any File or Folder for Storage You Don't Trust

> **Tech spec** · **Accepted v1.0** · shipped July 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-23 · **Constraints:** proposed C61–C66; reuses C1, C2, C7, C11, C27, C30, C31, C32; extends the UC-07 posture to arbitrary files
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.
> C61–C66 are drafted as **forward constraints** (G16, intent v1.8.0 + conflict SC9) — vacuously
> satisfied until UC-23 ships; the intent amendment lands with code-owner sign-off per GOVERNANCE.

## 1. Scope & goals

First concrete step of the ROADMAP "bigger vision" (credential vault → developer secret
vault): encrypt any file or folder into a **single sealed container** (`.vltf`) the user can
place on any storage they don't trust — Dropbox, Drive, S3, a git remote — with the same
trust properties as the credential vault: zero plaintext metadata, AEAD everywhere, one
crypto path, model-blind terminal behavior.

Goals:

1. `vault seal <path>...` → one `<name>.vltf`; `vault open <file>.vltf` restores;
   `vault peek` lists the inner tree post-unlock. GUI: drag-and-drop both directions.
2. **Zero observable metadata** (C62): names, paths, sizes, counts, permissions, mtimes all
   inside the AEAD payload; Padmé padding default-on (C66).
3. **Streaming, bounded memory** (C63): multi-GB inputs on small machines; ≥ 400 MiB/s
   release throughput target; stdin/stdout pipe modes for scripted cloud upload.
4. **Hostile-container safety**: fail-closed extraction (C64), path-traversal rejection
   (C65), fuzzed inner parser (per C30 discipline).
5. Same unlock story as the vault: passphrase always; keyfile/YubiKey stanzas reuse the
   shipped UC-09/UC-21 machinery. No new key formats, no new recovery story.

**Non-goals:** live-synced/mounted folders (FUSE, watch daemons) — the sealed-archive model
is a deliberate product stance, see §2; hosted sync (intent `non_goals`); deduplication or
any deterministic-encryption mode; per-file random access inside a container (v1 is
seal/open whole-container).

## 2. Prior art

Full survey: [research/encrypted_cloud_storage_research.md](../../research/encrypted_cloud_storage_research.md)
(tools, academic literature, community, primitives, breach data). Condensed decision drivers:

| Source | Lesson for UC-23 |
|---|---|
| Cryptomator / gocryptfs / rclone crypt | Live per-file vaults permanently leak tree structure, file counts, sizes, change timing — the metadata class Vault refuses (C17 precedent) |
| VeraCrypt + sync clients | Monolithic *live-mounted* containers conflict/corrupt under sync; as **seal-once artifacts** the monolithic shape is the strong option (FPF recommends exactly this workflow) |
| age | Reference UX for streaming encrypt-then-upload pipes; fresh-file-key non-determinism is the correct default absent git-diff constraints |
| Picocrypt (audited ROS 2024) | Independent validation of XChaCha20-Poly1305 + Argon2id for exactly this one-shot use case |
| 7-Zip | Opt-in filename encryption is the canonical usability trap → metadata protection must be default-on, not a flag |
| MEGA (S&P 2023), "Broken Ecosystem" (CCS 2024), Nextcloud (2024) | Every real E2EE break was unauthenticated key material / missing binding — never the cipher → reuse the existing authenticated envelope, add nothing bespoke |
| PURBs/Padmé (PoPETs 2019) | Size channel bounded to O(log log M) bits at ≤ 12 % overhead — already shipped in vault-core (S-12); default-on here |
| SUNDR/Depot | Freshness needs a witness; sealed artifacts are immutable one-shots, so the C16 counter question becomes an open question (§7 Q2) rather than a requirement |

## 3. Design

### 3.1 Container format

One new **inner payload type** behind the existing envelope — the outer layers are byte-
identical machinery to `vault.vlt`:

```
[C7 magic + version + KDF params + stanza records]     ← existing header (parsed by existing code)
[STREAM: XChaCha20-Poly1305, 64 KiB chunks]             ← existing C1 envelope, fresh random data key
  └── inner plaintext: FILE-ARCHIVE TLV stream          ← NEW (this spec)
        entry := TLV{ path, mode, mtime, len, body }    (bounded reads, length caps — C30 rules)
        terminator := END marker
        [Padmé padding to bucket]                       ← existing pad.rs, default-on (C66)
```

- **Container-kind decision (Phase A, day one):** `.vltf` uses a **distinct magic string**
  (recommendation: `VLTF1`, same length/position as the vault's magic) with the header
  layout otherwise byte-identical to format v1 — one header parser branches on magic into
  two payload types. Distinct magic (vs a kind byte inside the vault's magic) keeps ADR-0005
  untouched by construction: `.vlt` bytes cannot change because `.vltf` never shares its
  magic. `vault open` on a `.vlt` (and vice versa) fails with a clear kind-mismatch error,
  not a parse error.
- Deterministic-order entry walk (sorted paths) so seal output depends only on content +
  fresh key — no filesystem-iteration-order nondeterminism in tests.
- No compression in v1 (compressed-size oracle risk; revisit as an explicit opt-in later —
  §7 Q3).

### 3.2 Streaming pipeline (C63)

Seal: walk tree → for each entry, stream body through the TLV framer into the STREAM
encryptor in 64 KiB chunks → temp file → fsync → atomic rename (C32 discipline). Peak RSS
bounded by O(chunk); zeroizing buffers for plaintext chunks; Argon2id runs **once** per
seal regardless of file count. Open: mirror image; each inner file writes to a temp path
inside the destination and renames only after its final chunk authenticates.

Pipe modes: `vault seal - < tarball` / `vault open --stdout single.vltf`. `--stdout`
buffers-and-verifies small single-file containers; above a size threshold it refuses with
guidance (a pipe cannot be un-written on late auth failure — fail-closed wins over
convenience; threshold calibrated during implementation, IVD Rule 5).

### 3.3 Extraction safety (C64, C65)

- **Fail-closed** (C64): any chunk auth failure → delete in-flight temp, remove nothing
  already-completed? No — *whole-container* semantics: completed files remain only after
  the END marker authenticates; before that, everything lives under a `.vltf-partial/`
  staging dir that is removed on any error. Uniform error text regardless of failure
  position (no format oracle — UC-10 house style).
- **Traversal-safe** (C65): reject absolute paths, `..` components, symlink-escape writes;
  every entry resolves strictly under the destination root. AEAD proves who sealed it, not
  that its paths are safe — hostile-but-validly-sealed is in-threat-model (UC-10 stance).
- **Fuzzing** (C30): new `file_archive_parse` fuzz target from day one.

### 3.4 CLI / GUI surface

```
vault seal <path>... [-o out.vltf] [--no-pad] [--append]
vault open <file>.vltf [-C dir] [--stdout]        # --stdout: single-file, size-capped
vault peek <file>.vltf                            # inner tree (names/sizes), post-unlock
vault --vault <file>.vltf upgrade-kdf …           # header-only KDF re-wrap
vault --vault <file>.vltf rotate-data-key         # full inner re-encrypt
vault stanzas … <file>.vltf                       # same stanza management as the vault
```

- **`--append`:** unlock an existing `.vltf`, merge new paths (same inner path replaces), full
  re-encrypt of the inner archive; cannot combine with `seal -`.
- **`upgrade-kdf` on `.vltf`:** password stanza re-wrap only — inner STREAM body bytes preserved
  (unlike credential vault G0.3 full save).
- **`rotate-data-key` on `.vltf`:** new data key + re-wrap stanzas + full inner re-encrypt;
  FIDO2/TPM OR stanzas must be removed first (v1 limitation).
- FIDO2/TPM enroll on `.vltf` via `vault --vault FILE.vltf enroll fido2` / `enroll-tpm`.

- Zero flags on the happy path; passphrase prompted + confirmed, never argv (C31).
- `open`/`peek` never print file **contents** to stdout by default (C27 extended to files);
  restoring to disk is the feature, the terminal/scrollback channel stays protected.
- Exit codes extend the stable table (UC-04/G0.8); no new ad-hoc codes.

#### Desktop app (`vault-gui`) design

Follows the shipped UC-18/UC-20/UC-21 architecture: thin egui shell, all crypto in
`vault-core`, no secret rendering by default.

- **Drop targets**: `egui`'s `raw.dropped_files` — dropping a folder/file on the window
  opens the **seal dialog** (output name pre-filled, passphrase + confirm fields using the
  existing a11y-labeled password widgets from C54, keyfile/YubiKey enrollment reusing the
  UC-21 pickers, "Pad size" shown checked + disabled-off only via an explicit expander —
  C66 default-on). Dropping a `.vltf` opens the **open dialog** (destination picker via the
  existing `rfd` dependency, unlock flow identical to vault unlock incl. 2FA).
- **Threading (the one new GUI mechanism)**: seal/open run on a **worker thread** calling
  the streaming `vault-core` API; the UI thread never blocks. Progress reports over a
  channel as `(bytes_done, bytes_total)`; the worker calls `ctx.request_repaint()` on
  progress ticks (UC-20 reactive-repaint rule: no busy polling, ~0% CPU when idle).
  Cancel button sets an atomic flag the worker checks between chunks; cancellation runs
  the same cleanup path as auth failure (C64 staging-dir removal — cancel must not leak
  partials either).
- **Progress + errors**: progress bar with throughput readout (the C63 bench numbers make
  this honest); failure states show the uniform C64 error text — the GUI must not decorate
  errors with position detail the CLI deliberately withholds (no format-oracle via the GUI).
- **Peek view**: inner tree listed post-unlock with the existing virtualized list widget
  (C52 threshold applies — a 50k-file container must not freeze the shell); names/sizes
  only, never content previews (C27-extended; no thumbnailer, no quick-look).
- **Hygiene**: passphrase buffers zeroizing (C11, same widgets as vault unlock); no inner
  path names in any log line; lock-on-blur (C47) and idle auto-lock policies do NOT
  interrupt an in-flight seal/open worker — the job completes or cancels cleanly, but no
  NEW seal/open can start while locked.
- **TUI**: parity follows the CLI surface; same worker/progress pattern with a ratatui
  gauge. Nothing GUI-specific blocks Phase B — the GUI lands in Phase C against the same
  core API.

### 3.5 Performance budget (release-gated)

Seal and open sustain **≥ 400 MiB/s** on the reference machine for large inputs (manual
sign-off on audit hardware). Automated gate in `just audit-ready` uses
`VAULT_SEAL_BENCH_MIN_MIB_S` (default **20** MiB/s on dev/CI; set **400** on the reference
machine). Debug builds skip the bench (C58 pattern). One Argon2id invocation per operation —
never per file.

### 3.6 Implementation notes (Phase A spikes — resolved)

| Topic | v1 behavior |
|-------|-------------|
| **Symlinks** | Skipped on seal (not followed, not archived). Documented hostile symlink at rest is out of scope — only path strings inside the AEAD payload are extracted. |
| **mtimes** | Stored in inner `FILE_HDR` metadata (inside AEAD); restored on `open` where the host OS permits `utimens`. |
| **`--stdout` cap (SC9)** | 64 MiB single-file limit (`STDOUT_SIZE_LIMIT`); refuse above with uniform C64 error — fail-closed beats late pipe auth failure. |
| **Pipe seal** | `vault seal -` reads payload from stdin; passphrase via TTY, `--password-fd`, or `VAULT_PASSWORD_FILE` (not `--password-stdin`). Inner path name `-`. |

## 4. Constraint mapping

| Constraint | Status | How |
|---|---|---|
| C61 (proposed) | one crypto path | Existing STREAM envelope + stanzas; no new primitives/KDF/key formats; review gate + dep diff |
| C62 (proposed) | zero plaintext metadata | All entry metadata inside AEAD; ciphertext-grep test for inner names |
| C63 (proposed) | bounded-memory streaming | RSS ceiling test (`c63_rss_ceiling_large_on_disk_seal`); cancel abort; single-KDF via one `create()` per op |
| C64 (proposed) | fail-closed extraction | Chunk-corruption matrix; staging dir removed on error; uniform errors |
| C65 (proposed) | traversal-safe extraction | Zip-slip corpus rejected; nothing written outside destination root |
| C66 (proposed) | Padmé default-on | Bucket-identical outputs for near-size inputs; `--no-pad` explicit |
| C1/C2/C7 | reused | Same envelope, KDF floor/ceiling, header rules — no format-v1 changes |
| C11 | reused | Zeroizing chunk buffers; keys under existing mlock budget |
| C27 | extended | No content bytes to stdout by default; warned `--stdout` opt-out |
| C30 | extended | `file_archive_parse` fuzz target; bounded TLV reads |
| C31/C32 | reused | No secrets on argv; temp+fsync+rename outputs |

## 5. Test plan

1. **Round-trip**: seal/open across file-count × size × depth matrix; permissions/mtimes
   restored; pipe modes round-trip.
2. **Metadata** (C62/C66): ciphertext grep for inner names; Padmé bucket equality;
   `--no-pad` exact-size.
3. **Hostile containers** (C64/C65): chunk-corruption position matrix → zero partial
   plaintext, uniform errors; zip-slip corpus → no external writes; fuzz target green.
4. **Memory/perf** (C63, §3.5): >RAM seal under RSS ceiling; release bench ≥ 400 MiB/s;
   single-KDF-invocation assertion.
5. **Unlock parity**: keyfile/YubiKey-sealed containers open through existing CLI + GUI
   flows; stanza add/remove on `.vltf`.
6. **Joint satisfaction** (IVD, 3+ constraints): one hostile+large corpus sealed once;
   C61–C66 all asserted on that single artifact.

## 6. Rollout

Phase A: `vault-core` archive payload + seal/open API (lane A — format/crypto boundary).
Phase B: CLI verbs + exit codes (lane B, against the frozen core API).
Phase C: GUI drag-and-drop + TUI (lane B; design review by lane A).
Gate: intent amendment C61–C66 signed off (code owner) **before** Phase A merges — Gate-0
style, constraints first.

**Phase C design review (C10):** GUI worker/cancel path reviewed against spec §3.4 — byte
progress via `SealedIoOpts`, cancel flag between chunks, `SEALED_OPEN_ERROR` parity with CLI;
verified by `vault-gui/tests/uc23_constraints.rs`.

**Craft patterns (D5):** validation rules remain in this spec + `research/encrypted_cloud_storage_research.md`;
no separate `*_patterns.yaml` distilled for v1 (optional post-ship).

## 7. Open questions

1. **Extension & naming**: `.vltf` vs `.vlts`; `seal/open` vs `lock/unlock` verb choice —
   bikeshed deliberately deferred to the intent-amendment PR.
2. **Rollback/freshness for re-seal workflows**: sealed artifacts are immutable one-shots,
   so C16's counter doesn't apply as-is; but a user re-sealing `project.vltf` weekly to the
   same cloud path recreates the rollback question. Option: opt-in anchor keyed on a
   user-chosen container ID. Needs its own design pass — not v1 of this feature.
3. **Compression**: off in v1 (size-oracle risk interacts with padding). Revisit as
   explicit opt-in with Padmé interaction analysis.
4. **PURB-style full indistinguishability**: C7's honest magic header contradicts
   ciphertext-indistinguishable-from-random. Keeping the header is the current stance
   (parseability, error quality, C7 precedent); a `--purb` research mode is possible
   post-v1 if a real user need appears.
5. **Per-file random access** (open one file from a huge container without full
   extraction): STREAM supports seek-by-chunk in principle; deferred until demanded —
   would need an authenticated inner index (more metadata surface to design carefully).
