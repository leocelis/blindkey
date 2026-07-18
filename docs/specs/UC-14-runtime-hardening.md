# UC-14 — Survive a compromised-adjacent machine

> **Tech spec** · Accepted v0.2 · implemented pre-1.0 · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-14 · **Constraints:** C11, C12, C25, C13
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Not malware-with-root resistance ([THREAT_MODEL.md](../THREAT_MODEL.md) rules that out) — layered
hardening against the *common* adjacent threats: a stolen swap partition or hibernation file, a
crashed process leaving a core dump, a same-uid infostealer scraping memory or clipboard, a
timing side channel on tag comparison, an unlocked vault on an unattended machine.

Three layers, outermost to innermost: **process** (what leaves the process), **page** (where
secret bytes may physically land), **type** (how long secret bytes live and who can print them).
Plus the comparison discipline (C25) and the two session-surface mitigations (clipboard C13,
auto-lock C25) that UC-04/UC-06 own and this spec only wires in.

## 2. Prior art

### 2.1 Open source

- **libsodium memory management** ([doc.libsodium.org/memory_management](https://doc.libsodium.org/memory_management)) —
  `sodium_malloc`: guard pages before/after the allocation, canary, `0xdb` fill, automatic
  `mlock`; `sodium_munlock` zeroes before unlocking. The prior art for our page layer; we get the
  zeroing from `zeroize` and the locking from `lock_pages`, and treat guard pages as a v2 option.
- **RustCrypto `zeroize` / `secrecy` / `subtle`** — volatile-write + compiler-fence zeroization
  (the C11 mandate; plain `memset` was *refuted* as a guarantee in `research/vault_spec.md` §5),
  no-Debug/no-Clone secret wrappers, constant-time equality.
- **KeePassXC** (Molotnikov audit, 2023; memory-security blog, 2019) — disables core dumps and
  memory reading but "currently does not encrypt data in memory"; the auditor flagged
  deallocation. The gap C11/C12 are designed to close at the type-system level.
- **gopass** — `/dev/shm` for transient plaintext (ramdisk never hits disk); same intent as our
  page layer, weaker mechanism.

### 2.2 Academic / standards

- **Halderman, Schoen, Heninger, Clarkson, Paul, Calandrino, Feldman, Appelbaum, Felten —
  "Lest We Remember: Cold Boot Attacks on Encryption Keys", 17th USENIX Security Symposium, 2008**
  ([usenix.org](https://www.usenix.org/conference/17th-usenix-security-symposium/lest-we-remember-cold-boot-attacks-encryption-keys),
  verified June 2026): DRAM retains contents seconds-to-minutes after power loss; recovered keys
  from BitLocker, FileVault, dm-crypt, TrueCrypt. Grounds two design points: (a) cold-boot is
  **out of scope** (no software fix for retained DRAM), (b) *minimizing key lifetime and copies*
  (the type layer) shrinks the cold-boot window as a side effect.
- **`memfd_secret(2)`** ([man7](https://man7.org/linux/man-pages/man2/memfd_secret.2.html),
  [LWN](https://lwn.net/Articles/865256/), verified June 2026): Linux ≥ 5.14; pages are removed
  from the **kernel direct map** — even most kernel-level read primitives can't reach them.
  **Disabled by default before kernel 6.5** (`secretmem.enable=y` boot param required). Upgrade
  path for the page layer (§3.2).
- **mlock(2) / prctl(2) / setrlimit(2)** man pages — locking semantics, `RLIMIT_MEMLOCK` budget,
  `PR_SET_DUMPABLE` (non-dumpable processes refuse same-uid `ptrace` attach and produce no core).
- **MSDN** — `VirtualLock`, `SetErrorMode(SEM_NOGPFAULTERRORBOX)`.

## 3. Proposed design

### 3.1 Type layer (C11) — `crates/blindkey-core/src/memory/mod.rs`

The scaffolded aliases are the only legal carriers of secret bytes:

```rust
pub type MasterPassword = SecretBox<[u8]>;       // from no-echo prompt/stdin, never argv (C31)
pub type DataKey        = SecretBox<[u8; 32]>;   // C4
pub type SecretBuffer   = Zeroizing<Vec<u8>>;    // decrypted payload, wrapped-key plaintext, ikm
```

Rules (enforced by the C11 grep gate over secret-handling modules):

- No `Vec<u8>` / `[u8; N]` / `Box<[u8]>` for secret material — `SecretBox`, `Zeroizing` only.
  Drop = volatile write + fence, never elided (zeroize guarantee).
- `Debug` on any secret type prints `[REDACTED]` (secrecy default); no `Clone`, no `Display`,
  no `serde::Serialize` impls on secret types.
- Derived keys (`wrapping_key`, `payload_key`, block-HMAC keys, inner stream key) are constructed
  inside `Zeroizing` buffers and passed by reference; intermediate KDF state (the Argon2id memory
  arena) is zeroized by the `argon2` crate's buffer-drop path — verify, don't assume (§6.2).
- Lifetime discipline: derive on demand, drop at the end of the operation. `blindkey lock` and
  auto-lock drop every live secret type explicitly (C25 "zero all mlock'd pages via zeroize
  before releasing").

### 3.2 Page layer (C12) — keep secrets off the disk

`lock_pages` (scaffolded) implements:

```rust
pub struct LockedRegion { ptr: NonNull<u8>, len: usize, locked: bool }
// new(): mmap(MAP_ANONYMOUS|MAP_PRIVATE) page-aligned → mlock(2) / VirtualLock
//        madvise(MADV_DONTDUMP) on Linux (belt for §3.3's coredump_filter braces)
// drop(): zeroize THEN munlock THEN munmap   (libsodium sodium_munlock order)
```

- **Graceful degradation (C12, verbatim behavior):** on `ENOMEM`/`EPERM`/unsupported platform,
  print once to stderr: `WARNING: could not lock memory pages (mlock failed: <errno>). Secrets
  may be swapped to disk. Consider running with CAP_IPC_LOCK or as root.` — and continue. Never
  abort. The warning is per-process, not per-allocation (no stderr spam).
- **Budget:** default `RLIMIT_MEMLOCK` is commonly 64 KiB–8 MiB. Locked set = keys + KDF-adjacent
  buffers + the decrypted payload `SecretBuffer`. Large vaults can exceed the limit → that *is*
  the degradation path; document `ulimit -l` / `CAP_IPC_LOCK` in INSTALL.md.
- **What mlock does NOT cover (documented):** suspend-to-disk — hibernation images write all of
  RAM, locked or not (see mlock(2) NOTES); cold-boot DRAM remanence (§2.2); root reading
  `/proc/<pid>/mem`. First is mitigated only by encrypted swap/hibernation at the OS level —
  stated in user docs, not solved here.
- **Upgrade path — `memfd_secret` (Linux ≥ 5.14):** runtime-probe the syscall; when available
  (and enabled — pre-6.5 kernels need `secretmem.enable=y`), back `LockedRegion` with
  `memfd_secret` + `mmap` instead of anonymous mmap, removing pages from the kernel direct map.
  Fallback chain: `memfd_secret` → `mlock` → unlocked + warning. v1.x feature flag, not v1.0.
- **Guard pages (libsodium prior art):** `PROT_NONE` page on each side of `LockedRegion` to
  catch linear overreads. Cheap, but our parsers are fuzzed and bounds-checked Rust — v2 option.

### 3.3 Process layer (C25 + gap B3) — `harden_process()` at startup

First statements in `main()`, before any secret exists:

| Platform | Call | Effect |
|---|---|---|
| Unix | `setrlimit(RLIMIT_CORE, {0,0})` | No core file on crash (C25) |
| Linux | write `"0"` to `/proc/self/coredump_filter` (if writable) | Belt-and-braces with RLIMIT_CORE (C25) |
| Linux | `prctl(PR_SET_DUMPABLE, 0)` | Non-dumpable: blocks same-uid `ptrace` attach and `/proc/<pid>/mem` reads by non-root (gap B3); also suppresses core dumps |
| Windows | `SetErrorMode(SEM_NOGPFAULTERRORBOX \| SEM_FAILCRITICALERRORS)` | No WER crash UI/report capture (C25) |

Failures here are warnings, not aborts (same philosophy as C12). macOS `PT_DENY_ATTACH` is
evaluated-and-deferred: trivially bypassed pre-attach, breaks debugging, low value (gap B3 notes).

### 3.4 Constant-time comparisons (C25) — the comparisons WE write

The AEAD layer already does its own constant-time tag checks (the `chacha20poly1305` crate
verifies Poly1305 tags via `subtle` internally) — so wrapped-key opens (C5) and STREAM chunk
verification (C1) need nothing from us. The comparisons **we** author, exhaustively:

| Comparison | Where | Mechanism |
|---|---|---|
| `header_hmac` (C9 step 3) | header verify | `hmac::Mac::verify_slice` (subtle-backed) — never `==` on the tag |
| Per-block HMAC (C10) | body block reader | same `verify_slice` discipline |
| Data-key equality in `blindkey merge` (UC-08 §3.5) | merge | `subtle::ConstantTimeEq` on the two unwrapped keys |
| Protected-field equality in merge diffs (UC-08 §3.4) | merge | `ct_eq` (scaffolded wrapper over `ConstantTimeEq`) |
| `header_hash` (C9 step 1) | header verify | plain compare **permitted**: SHA-256 over public header bytes, both operands attacker-known — documented exception, not an oversight |
| Passwords | — | **No password comparison exists by design**: verification is KDF → keyed HMAC (C9), never string equality |

Static gate (C25 test): `grep -rn " == " ` over the modules touching HMAC tags/wrapped keys must
return zero results; the `header_hash` exception lives in a module outside that gate's scope with
a comment citing this section.

### 3.5 Session surfaces (wired in, owned elsewhere)

- **Clipboard auto-clear (C13)** — design in UC-04: 30 s default (5–300 s), background timer,
  best-effort clear on SIGTERM, transient/concealed clipboard flags (C33). This spec's only
  requirement: the clipboard write path takes its bytes from a `SecretBuffer` and zeroizes after
  the OS handoff.
- **Auto-lock (C25)** — design in UC-06: 300 s idle default (30–3600, 0=off). Lock = drop every
  `LockedRegion`/secret type (zeroize-then-munlock order, §3.2) and invalidate the session.
  `blindkey lock` is the manual trigger of the same path — one code path, not two.

### 3.6 Explicit non-goals (residual risk — THREAT_MODEL.md)

Root/kernel compromise while unlocked · cold-boot DRAM extraction (Halderman et al.) · DMA /
bus-level physical attacks · an attacker who already holds the unlocked master key. We reduce the
*window* (short key lifetimes, auto-lock) but claim no resistance once those lines are crossed.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| `zeroize`/`secrecy` types (proposed) | Compiler-proof zeroization; misuse is a type error; greppable | Discipline needed at FFI edges | **Adopt** (C11 mandate) |
| `memset`/`sodium_memzero` | Familiar | Dead-store elimination; guarantee refuted in research §5; prohibited by intent | **Prohibited** |
| `sodium_malloc` for all secret allocs | Guard pages + canary + mlock in one | Pulls libsodium allocator across the Rust boundary; mixes allocators | Reject; replicate the pieces natively (§3.2) |
| `memfd_secret` as the v1 baseline | Strongest page isolation | Linux ≥ 5.14 only; **off by default before 6.5**; EPERM in containers | Upgrade path with runtime probe, not baseline |
| Encrypt-in-memory (KeePassXC-style in-RAM cipher over the working set) | Narrows scrape window further | Key for it must also live in RAM (turtles); complexity vs. C11+C12 marginal gain | Defer; revisit post-audit |
| `PT_DENY_ATTACH` (macOS) | Cheap | Bypassable pre-attach; breaks dev debugging | Defer (gap B3) |
| Whole-payload mlock always-on | Simplest mental model | Blows default RLIMIT_MEMLOCK on big vaults | Keep, but with the C12 degradation path as designed |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| C11 | All secret material in `SecretBox`/`Zeroizing` (§3.1); Debug prints REDACTED; no plain byte containers in secret modules (grep gate) |
| C12 | `LockedRegion` mlock/VirtualLock with the exact C12 warning string on ENOMEM and continue-not-abort; zeroize-before-munlock on drop |
| C25 | `subtle`/`verify_slice` for every authored secret comparison (§3.4 enumerates them); RLIMIT_CORE=0 + coredump_filter + SetErrorMode at startup (§3.3); auto-lock drops and zeroes all locked state (§3.5) |
| C13 | Clipboard path consumes `SecretBuffer` and zeroizes post-handoff; timer/clear semantics per UC-04 |

## 6. Test plan

1. **UNIT (C11):** drop a `Zeroizing<Vec<u8>>`, re-read the address (test-only unsafe) → bytes
   zeroed; `format!("{:?}", DataKey)` contains no key bytes.
2. **UNIT (KDF arena):** after `derive`, scan the argon2 working buffer region (test hook) for
   the password bytes → absent. (Closes the §3.1 "verify, don't assume" item.)
3. **INTEGRATION (C12):** open vault → `/proc/self/status` `VmLck > 0` (Linux) / `vm_region`
   lock bit (macOS); mock mlock → ENOMEM → vault opens, stderr contains "mlock failed", exactly once.
4. **INTEGRATION (C25 process):** `/proc/<pid>/limits` shows max core size 0;
   `/proc/<pid>/status` shows the process non-dumpable; on Linux, `ptrace` attach from a
   same-uid helper fails with EPERM.
5. **INTEGRATION (crash):** SIGSEGV a test build holding a marker secret → no core file appears
   in cwd / coredumpctl.
6. **STATIC (C25):** the `==`-grep gate over tag/key modules returns empty; `subtle` and
   `verify_slice` usage asserted by grep in the same gate.
7. **INTEGRATION (auto-lock):** mock timer → after idle, `blindkey get` re-prompts; heap scan test
   hook finds no live key bytes post-lock.
8. **INTEGRATION (memfd_secret, gated):** on a ≥ 6.5 kernel runner, `LockedRegion` reports
   secretmem backing; on older/disabled kernels, falls back to mlock without error.
9. **SWAP (manual/doc test):** documented procedure — unencrypted-swap VM, force pressure,
   scan swap for a marker secret with vault locked vs. mlock-degraded; expected: absent when
   locked, possibly present when degraded (that is what the C12 warning means).

## 7. Open questions

1. **FFI edges:** libfido2/TPM/DPAPI calls (UC-09) receive ikm bytes in C-owned buffers our
   zeroize cannot reach. Audit each binding for who owns/zeroes; wrap with copy-in/zeroize-out
   shims where the library doesn't guarantee it.
2. **`memfd_secret` + container reality:** seccomp default-deny in Docker/podman returns EPERM —
   does the probe distinguish "kernel too old" from "blocked" well enough for an honest warning?
3. **Windows WER:** is `SetErrorMode` alone sufficient (C25 says yes), or add
   `WerAddExcludedApplication` for full crash-report suppression? Needs a Windows CI probe before M4.
4. **Argon2 arena zeroization:** if the `argon2` crate doesn't zeroize its memory blocks on drop
   (test 6.2), upstream a fix or wrap allocation in `LockedRegion` ourselves — decide at M4.
5. **Auto-lock vs. long operations:** does a running `blindkey export` of a huge vault count as
   activity, or can the timer fire mid-operation? Proposal: timer arms only between subcommands.
