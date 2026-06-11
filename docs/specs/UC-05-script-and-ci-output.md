# UC-05 — Scripts & CI: Explicit, Warned Plaintext Opt-Outs

> **Tech spec** · Draft v0.2 (pending acceptance review; updated for intent v1.3.0–v1.4.0, 2026-06-10) · June 2026
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-5 · **Constraints:** C27, C21, SC5 (resolution); C23; C31 (promoted from gap B1, §3.5)
> Where this spec and [`vault_intent.yaml`](../../vault_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

Persona P4 (automation/CI) needs plaintext on purpose. SC5 resolves the C27↔C21 tension:
plaintext paths **exist**, but every one is an *explicit, warned opt-in* and none is the
default — `C27_default > C21_convenience`. This spec defines:

- `--stdout` flag semantics (exact warning text, exit codes),
- the non-TTY behavior matrix (deterministic, no prompts when piped),
- `vault export --format json` (schema, warning, confirmation),
- recommended CI secret-injection patterns and a possible future `vault exec`,
- C31 (was gap B1): **no secrets on argv, ever** — promoted 2026-06-10,
- audit-trail position (there is none, by design — C23).

Non-goals: an agent/MCP interface (UC-16, post-v1), CSV export (gap A3 — formula injection;
not offered in v1), a daemon (UC-06 §3.4).

## 2. Prior art

### 2.1 Open source

| Source | Relevance |
|---|---|
| `pass` ([passwordstore.org](https://www.passwordstore.org/)) | `pass show NAME` prints to stdout *by default* — the ergonomics scripts love and the exact default C27 prohibits. We keep the pipe pattern but flip it to opt-in. |
| [gopass](https://github.com/gopasspw/gopass) | pass-compatible CLI; reads secrets via prompts/stdin rather than argv flags — the B1 discipline we adopt. Its "safecontent" mode (hide password unless asked) prefigures our default-deny. |
| [sops](https://github.com/getsops/sops) | `sops exec-env FILE 'cmd'` — decrypts into the **environment of a subprocess**, never to disk; `exec-file` uses a tempfile/FIFO. Template for a future `vault exec`. |
| 1Password CLI [`op run`](https://developer.1password.com/docs/cli/secret-references/) (verified June 2026) | Scans env for `op://` secret references, injects resolved values into the subprocess env, and **masks secrets that appear on stdout via a PTY** (disable with `--no-masking`). The most complete prior art for warned, scoped plaintext. |
| KeePassXC CLI (`keepassxc-cli show -s`) | Requires an explicit flag to reveal protected fields — reveal-is-opt-in precedent. |

### 2.2 Academic / standards

- [research/llm_offensive_threats.md §7](../../research/llm_offensive_threats.md): CI is an
  *agent-adjacent* environment — Wiz's "prt-scan" (500+ malicious PRs harvesting cloud creds
  from CI) and the Johns Hopkins GitHub-Actions agent hijacks both exfiltrated via CI logs and
  tool results. A warned `--stdout` in CI is a calculated risk the operator owns.
- [research/security_coverage_gaps.md B1](../../research/security_coverage_gaps.md): argv leaks
  to shell history and `/proc/<pid>/cmdline` (any same-host process can read it); C20's original
  example violated it — the CLI scaffold ([crates/vault-cli/src/main.rs](../../crates/vault-cli/src/main.rs))
  already removed secret-bearing flags.
- POSIX `isatty(3)` semantics for the detection matrix (§3.3).

## 3. Proposed design

### 3.1 `vault get NAME --stdout`

Behavior, in order:

1. Unlock (non-interactive rules per §3.3 if stdin is not a TTY).
2. Write to **stderr**, verbatim (C27's exact string):
   `WARNING: plaintext written to stdout; ensure no AI agent or untrusted process captures this stream.`
3. Write the secret to **stdout**, followed by a single `\n`. Nothing else ever goes to stdout
   (no labels, no formatting) so `vault get db --stdout | psql ...` composes cleanly.
4. Exit 0.

The warning is unconditional — TTY or pipe, interactive or CI. Scripts that find it noisy can
`2>/dev/null`; the act of discarding it is itself the explicit acknowledgment. There is no
`--quiet` that suppresses only this warning (that would make the opt-out silent, violating SC5).

The trailing newline is included because every Unix line-oriented consumer expects it; secrets
that must be newline-free should be consumed with `$(...)` (strips it) or `--field` reads piped
through `tr -d '\n'`. Documented in CLI.md rather than adding a `--no-newline` flag (v1 keeps
the surface minimal; revisit on demand — §7 Q2).

**Exit codes — the normative map is C21 (intent v1.4.0); this table mirrors it:**

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic / unexpected runtime error (I/O, clipboard failure) |
| 2 | Rollback detected, not overridden (C16 — reserved) |
| 3 | Not a vault file / newer format version (C7) |
| 4 | Corruption — header hash, block HMAC, or AEAD tag (C9/C10/C1) |
| 5 | Authentication — invalid credentials or tampered header (C9) |
| 6 | KDF parameters outside the safe range (C2) |
| 7 | No clipboard available and `--stdout` not given (C27, UC-04 §3.7) |
| 8 | Usage error, incl. missing `--yes` on confirmation-requiring piped commands (clap configured away from its default 2) |
| 9 | Entry or field not found / ambiguous |

### 3.2 Reading secrets in (the other direction)

Non-interactive unlock never takes the master password from argv (§3.5). Accepted channels:

- `--password-fd N` — read the password from file descriptor `N` (gopass-style; the CI-safe
  path: `vault get db --stdout --password-fd 3 3<"$CRED_FILE"`).
- stdin pipe **only when** `--password-stdin` is passed explicitly (avoids ambiguity with
  future commands that consume stdin data).
- `VAULT_PASSWORD_FILE=/path` env var pointing at a 0600 file — the *path* is in the
  environment, never the secret itself. A `VAULT_PASSWORD` env var is **not** offered:
  environments leak into child processes, crash dumps, and CI debug logs.

### 3.3 Non-TTY detection behavior matrix

Detection via `isatty()` on each stream independently. Principle: **never prompt into a pipe;
never block waiting for input that cannot come; behave deterministically** (PRD persona P4).

| stdin | stdout | stderr | Behavior |
|---|---|---|---|
| TTY | TTY | TTY | Full interactive: no-echo password prompt, confirmations allowed |
| TTY | pipe | TTY | Interactive prompts OK (they go via the TTY); `--stdout` output flows to the pipe; warning still on stderr |
| pipe | any | any | **No prompts.** Password must arrive via §3.2 or exit 5. Confirmation-requiring commands (`rm`, `export`) require `--yes` or exit 8 (usage). Rollback condition (C16): abort, exit 2, no prompt — `--allow-rollback` to proceed. |
| any | any | pipe | Warnings are still written to stderr (captured by the pipe — that is the point); no behavior change |

Additional rule: `vault get` *without* `--stdout` in a fully non-TTY context still goes to the
clipboard if one exists (a windowed CI runner is rare but possible); headless → exit 7 with the
UC-04 §3.7 guidance. No environment auto-detection ever flips output to stdout implicitly.

### 3.4 `vault export --format json`

- **Confirmation:** if stdout is a TTY → interactive prompt
  `Export ALL entries as plaintext JSON to stdout? [y/N]`; if stdout is a pipe/file → require
  `--yes` (exit 8 otherwise). Both paths print to stderr first:
  `WARNING: export writes ALL decrypted entries as plaintext. Anything that reads this output (including AI agents) learns every secret.`
- **Schema (v1):**

```json
{
  "vault_export_version": 1,
  "entries": [
    {
      "title": "github-prod",
      "username": "leo",
      "password": "…",
      "url": "https://github.com/org",
      "notes": "…",
      "tags": ["work"],
      "otp_secret": null,
      "custom_fields": {},
      "created_at": "2026-06-10T12:00:00Z",
      "modified_at": "2026-06-10T12:00:00Z",
      "expires_at": null
    }
  ]
}
```

- No `exported_at` / hostname / version metadata beyond the schema number — exports should not
  fingerprint the machine. Timestamps are RFC 3339 UTC. Strings are strict JSON-escaped (gap A3
  containment); **CSV is not offered** in v1 (CVE-2019-20184 class, OWASP CSV-injection).
- Output goes to stdout only (composable with `| age -r … > backup.json.age`); `--output FILE`
  is deliberately absent in v1 — writing plaintext files ourselves invites 0644 mistakes; the
  shell redirect makes the user own the destination. (Revisit with enforced 0600 if demanded.)

### 3.5 C31 — no secrets on argv, ever (promoted from gap B1)

Proposed text for promotion into the intent (numbering per maintainer; gaps doc calls it C32):

> **C32 — No secret material on the command line.** The CLI MUST NOT accept any secret value
> (master password, entry password, OTP secret, recovery code) as a command-line argument, and
> MUST NOT offer any flag that does so. Secrets MUST be read only via (a) a no-echo TTY prompt,
> (b) an explicit `--password-stdin` pipe, or (c) an explicit `--password-fd N` descriptor.
> Vault-internal child processes MUST receive secrets only via inherited pipe descriptors —
> never argv or environment.
> *Test:* STATIC — clap definitions contain no secret-bearing `#[arg]`; grep CI gate.
> INTEGRATION — for each secret-input path, read `/proc/<pid>/cmdline` and `/proc/<pid>/environ`
> of the vault process and any child; assert the secret appears in neither. DOC — every example
> in README/CLI.md uses prompt/fd forms.

Rationale: argv is world-readable on the host (`ps`, `/proc/*/cmdline`), persisted by shells
(history files an agent can read — threats §7 lists shell history as a default agent input),
and logged by CI runners. The scaffold already complies; the constraint locks it in.

### 3.6 CI injection patterns (documentation we ship)

Recommended, in order:

1. **Pipe, single consumer:** `vault get db --stdout --password-fd 3 3<"$MASTER" | psql …` —
   the secret exists only in the pipe buffer; never argv, never env, never disk.
2. **Command substitution into env of one child:**
   `DB_PASS="$(vault get db --stdout …)" some-tool` — acceptable; the secret is in `some-tool`'s
   environment (readable via `/proc/<pid>/environ` by same-uid only) but not on any argv.
3. **Anti-pattern (documented, warned):** `some-tool --password "$(vault get db --stdout …)"`
   — lands on argv; B1 explains why. Our docs show the fixed form.

**Future `vault exec` (M9+ candidate, not v1):**
`vault exec --entry db --as DB_PASS -- cmd args…` — decrypt, inject as env var(s) into the
child, optionally PTY-mask child stdout like `op run`. Prior art: sops `exec-env` (env scoping),
`op run` (reference resolution + masking, verified), gopass. Deferred because v1's surface is
minimal (C21 lists no `exec`) and masking-via-PTY is a substantial subsystem; the pipe patterns
above cover CI today. Recorded here so the design intent survives.

### 3.7 Audit trail considerations

**None — by design.** C23 prohibits telemetry and any network call; a *local* access log would
be plaintext metadata on disk ("which entries exist, when accessed") — precisely what C17/C18
deny to a file-system observer. CI systems wanting audit trails should log the *invocation*
(their own job logs already do), not ask the vault to. If demand emerges, an *encrypted*
in-payload access log is the only shape compatible with the intent — out of scope for v1.

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| stdout-by-default with warning | pass-compatible muscle memory | Violates C27/SC5 outright | **Rejected** |
| `VAULT_PASSWORD` env var for unlock | Easy CI ergonomics | Env leaks to children/crash dumps/CI debug logs; weaker than fd/file | **Rejected** (offer `VAULT_PASSWORD_FILE`) |
| `--quiet` to suppress the `--stdout` warning | Cleaner CI logs | Makes the opt-out silent — exactly what SC5 forbids; `2>/dev/null` exists | **Rejected** |
| CSV export | Spreadsheet interop | Formula-injection CVE class (gap A3, CVE-2019-20184 in KeePass) | **Rejected v1** |
| `vault exec` in v1 | Best-practice injection now | Not in C21's surface; PTY masking is big; pipes suffice | **Deferred** (design sketched §3.6) |
| Auto-detect CI (`CI=true`) and relax warnings | Less noise | Heuristic, spoofable, makes behavior environment-dependent — anti-P4 | **Rejected** |
| `--output FILE` on export with 0600 | Convenience | We become responsible for plaintext-at-rest lifecycle; redirect keeps user ownership | **Rejected v1** |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C27** | `--stdout` is explicit; its stderr warning uses C27's exact string (§3.1); no silent plaintext path exists; export is warned + confirmed (§3.4) |
| **C21** | `get --stdout`, `export --format json`, `import` surfaces match the C21 command list; export carries the security warning C21 mandates |
| **SC5** | Every plaintext emission = explicit flag + unconditional warning + (for bulk export) confirmation; defaults unchanged (clipboard); priority `C27_default > C21_convenience` implemented literally |
| **C23** | No audit/telemetry channel added (§3.7); all flows local |
| **C16** | Non-interactive rollback behavior (abort, exit 2, `--allow-rollback`) folded into the §3.3 matrix |
| Gap B1 (candidate C32) | No secret-bearing flags; fd/stdin/prompt inputs only; child handoff via pipes; constraint text proposed (§3.5) |

## 6. Test plan

1. **INTEGRATION (C27):** `vault get X --field password --stdout` → secret+`\n` on stdout;
   stderr contains `plaintext written to stdout`; exit 0.
2. **INTEGRATION (warning unconditional):** same command with stdout to a pipe and stderr to a
   file → warning present in the file.
3. **INTEGRATION (matrix):** for each row of §3.3: stdin from `/dev/null` + no `--password-fd`
   → exit 5, no prompt, stderr explains; `rm` with piped stdin and no `--yes` → exit 8;
   rollback condition piped → exit 2 (C16 test reuse).
4. **INTEGRATION (export TTY):** under a PTY, `export --format json` prompts `[y/N]`; `n` →
   exit 1 (declined), zero stdout bytes. Piped without `--yes` → exit 8. Piped with `--yes` → valid JSON
   (schema-validated), warning on stderr.
5. **UNIT (schema):** round-trip export→import preserves every field byte-for-byte.
6. **INTEGRATION (B1):** spawn each secret-input form; scan `/proc/<pid>/cmdline` + `environ`
   of vault and children for the known secret → zero hits.
7. **STATIC (B1):** CI grep over clap derive: no `#[arg]` named `password|secret|otp|token`
   taking a value.
8. **DOC test:** CLI.md examples contain no secret literals on argv (lint script).

## 7. Open questions

1. **Promote B1 text (§3.5) into `vault_intent.yaml`** — needed before M2 freeze per PRD §9.1;
   maintainer decision on final ID/group (suggested: G8).
2. **`--no-newline`** on `--stdout` for binary-exact secrets — defer until a real consumer
   needs it, or ship now for `printf`-parity? (Current: defer.)
3. **Export encryption nudge:** should `export` *suggest* piping through `age` in its warning
   text (helpful) or stay neutral (terse)? Leaning helpful: one extra stderr line.
4. **`import --format txt` field mapping** for unstructured files (C21 mentions it; schema
   handshake undefined) — separate mini-spec before M6.
5. **Exit-code table location:** this spec is normative for now; move to CLI.md once stable.
