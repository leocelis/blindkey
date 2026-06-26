# mlock / Docker graceful degradation — Research (security-gap review P2)

> **Task:** INSTALL.md documents C12 mlock degradation in containers; recommend host-native for production.

## Problem

Default `RLIMIT_MEMLOCK` on Linux is often 64 KiB–8 MiB. Docker/Podman/Kubernetes default
seccomp profiles block `mlock(2)` → **EPERM**. Vault must continue (C12: never abort) but users
need honest guidance on swap risk and mitigations.

## C12 behavior (shipped)

| Condition | Behavior |
|-----------|----------|
| `mlock` succeeds | Decrypted payload pages stay off swap while unlocked |
| `ENOMEM` / `EPERM` / unsupported | One stderr warning per process; vault continues |
| Large vault + low limit | Partial lock failure possible → same degradation path |

Warning string (UC-14 §3.2): `WARNING: could not lock memory pages (mlock failed: <errno>). Secrets may be swapped to disk. Consider running with CAP_IPC_LOCK or raising ulimit -l.`

## Container reality

- **Docker default:** `mlock` denied (seccomp); `--cap-add=IPC_LOCK` + `--ulimit memlock=-1:-1` may restore locking.
- **Kubernetes:** `securityContext.capabilities.add: [IPC_LOCK]`; no guarantee on all runtimes.
- **Rootless podman:** often stricter; host-native install preferred for high-value secrets.

## Recommendation (production)

**Host-native install** (`./scripts/install.sh` or distro package) for production master passwords.
Use containers only for CI/automation with low-value test vaults, or after explicit hardening.

## References

- `mlock(2)`, `getrlimit(2)` — RLIMIT_MEMLOCK
- UC-14 §3.2 — page layer + container EPERM
- vault_intent.yaml C12
