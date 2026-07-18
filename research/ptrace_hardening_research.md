# ptrace / live-memory hardening — Research

> **Task:** Close gap B3 — same-uid `ptrace` / `/proc/<pid>/mem` scrape of unlocked secrets.

## Problem (gap B3)

C25 disables **core dumps**, but a same-uid infostealer can still attach with `ptrace` or read
`/proc/<pid>/mem` while vault is unlocked.

## Linux mitigation (shipped)

| Mechanism | Effect |
|-----------|--------|
| `prctl(PR_SET_DUMPABLE, 0)` | Non-dumpable process: blocks same-uid `ptrace` attach and non-root `/proc/<pid>/mem` under default Yama `ptrace_scope=1` |
| `setrlimit(RLIMIT_CORE, 0)` | No core file on crash (C25) |
| Write `"0"` to `/proc/self/coredump_filter` | Belt-and-braces — no VMAs in core even if limit mis-set (C25 intent) |

Called from `vault_core::memory::harden_process()` at startup in CLI/TUI/GUI `main`.

## Admin hardening (documented, not enforced)

Recommend `kernel.yama.ptrace_scope = 1` (default on most distros) or `2` (ptrace restricted to
`CAP_SYS_PTRACE`). See INSTALL.md § Linux runtime hardening.

## macOS — deferred

`PT_DENY_ATTACH` is trivially bypassed if set after attach race; breaks debugging. macOS relies on
core-dump-off + mlock + auto-lock; live attach by same-user malware remains residual (THREAT_MODEL).

## References

- `docs/specs/UC-14-runtime-hardening.md` §3.3
- `research/security_coverage_gaps.md` B3
- `blindkey_intent.yaml` C25 (coredump_filter)
- Linux `man 2 prctl`, `man 7 yama`
