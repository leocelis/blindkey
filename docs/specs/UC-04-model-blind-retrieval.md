# UC-04 — Model-Blind Retrieval: Get a Secret While an AI Agent Is Watching

> **Tech spec** · Accepted v0.2 · implemented pre-1.0 · June 2026 · **the flagship use case**
> **PRD:** [docs/PRD.md](../PRD.md) §5 UC-4 · **Constraints:** C27 (primary), C13, C23; touches B2 ([gaps](../../research/security_coverage_gaps.md))
> Where this spec and [`blindkey_intent.yaml`](../../blindkey_intent.yaml) disagree, the intent wins.

## 1. Scope & goals

The developer runs `blindkey get github-prod --field password` in a terminal that a coding agent
is attached to. The guarantee this spec implements: **the agent can be told the secret was
delivered; it can never read it.** The secret travels `decrypted payload → OS clipboard`,
touching no channel an LLM ingests by default — not stdout, not a tool result, not a file.

Covered here: the threat model recap, per-platform clipboard delivery (X11, Wayland, macOS,
Windows), the auto-clear timer (C13), clipboard-history/cloud-sync suppression (C33),
stdout/stderr channel discipline, and interaction with scrollback/transcript capture.
The warned opt-outs (`--stdout`, export) are specified in [UC-05](UC-05-script-and-ci-output.md).

## 2. Prior art

### 2.1 Open source

| Source | Relevance |
|---|---|
| 1Password [Secure Agentic Autofill](https://1password.com/blog/closing-the-credential-risk-gap-for-browser-use-ai-agents) (cited in C27) | The design principle: the AI agent and underlying LLM "never need to see nor handle the credentials" — credentials are injected at the destination on the user's authorized behalf. Our clipboard default is the CLI-shaped version of the same principle. |
| KeePassXC [`Clipboard.cpp`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/gui/Clipboard.cpp) | Timed clear (30 s default, C13's source); clears only if the clipboard still holds what it set; per-platform history-suppression hints (verified against source, §3.5): macOS `application/x-nspasteboard-concealed-type`, Linux `x-kde-passwordManagerHint=secret`, Windows `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard` |
| `pass` ([passwordstore.org](https://www.passwordstore.org/)) | `pass show -c`: copies via `xclip`/`wl-clipboard`, **restores** the previous clipboard after 45 s (`PASSWORD_STORE_CLIP_TIME`). We adopt the timed clear but not the restore (§4) |
| [`wl-clipboard`](https://github.com/bugaevc/wl-clipboard) / [`wl-clipboard-rs`](https://crates.io/crates/wl-clipboard-rs) | Wayland copy without keyboard focus via the data-control protocol ([`zwlr_data_control_manager_v1`](https://wayland.app/protocols/wlr-data-control-unstable-v1), successor [`ext-data-control-v1`](https://wayland.app/protocols/ext-data-control-v1)); `wl-copy` forks a child to serve the offer |
| [`arboard`](https://crates.io/crates/arboard) (maintained by 1Password) | Cross-platform Rust clipboard crate; supports X11 "wait" mode and Windows/macOS exclusion flags — candidate implementation crate (§3.3) |
| nspasteboard.org | Community convention for `org.nspasteboard.ConcealedType` / `TransientType` honored by macOS clipboard managers |

### 2.2 Academic / standards

- [research/llm_offensive_threats.md §7](../../research/llm_offensive_threats.md): systematic
  review across 78 studies — **every tested coding agent vulnerable to prompt injection**,
  adaptive attack success > 85%; production agents hijacked to exfiltrate credentials.
  The core problem ("an LLM cannot reliably distinguish instructions from data") is unsolved,
  so the only robust defense is structural: keep the plaintext out of the model's reach.
- ICCCM / X11 selection model (X.Org): clipboard contents live in the *owning client*; when the
  owner exits, the selection vanishes unless a clipboard manager has taken it over. This single
  fact drives the process model in §3.2.
- NIST SP 800-38D etc. are upstream of this spec; no new cryptography is introduced here (C3).

## 3. Proposed design

### 3.1 Threat model recap

Adversary: a prompt-injected coding agent running as the same user, which by default reads
(a) stdout/stderr of commands it runs, (b) the terminal transcript, (c) files in the workspace,
(d) shell history. It can be *instructed* (via a poisoned README, PR comment, or tool output —
threats §7) to run exfiltration commands. It does **not** (in this UC) have a custom native
binary scraping the OS clipboard — that is host-malware territory (C13/B2 narrow it; full
malware-with-root is out of scope per [THREAT_MODEL](../THREAT_MODEL.md)).

| Channel | Agent reads it by default? | Blindkey policy |
|---|---|---|
| stdout | **Yes** (tool result) | Empty on `blindkey get` (C27) |
| stderr | Usually (merged into transcript) | Human-status text only; never secret bytes |
| Files / tempfiles | Yes (workspace reads) | No secret ever written to a file path |
| Shell history / argv | Yes | No secrets on argv (C31 → UC-05 §3.5) |
| OS clipboard | **No** — agents have no clipboard tool by default; reading it requires running a new program, which is a visible, auditable action | **Delivery channel** |

The clipboard is not magically unreadable — it is *outside the model's default input set*, and
that is the property C27 needs. Defense in depth (timer, hints, clear-on-exit) narrows the
remaining window.

### 3.2 Process model: detached clipboard holder

`blindkey get` is a one-shot CLI, but C13's timer must outlive it, and on X11/Wayland the
*selection owner* must stay alive to serve paste requests (ICCCM; same reason `wl-copy` forks).

```
blindkey get NAME
  ├── unlock, decrypt entry, extract field (Zeroizing buffer)
  ├── spawn detached helper:  vault __clip-holder --timeout 30   (secret via inherited pipe fd,
  │     NEVER argv/env; helper closes the read end immediately after reading)
  ├── print to stderr: "Copied 'github-prod' password to clipboard. Clears in 30 s."
  └── exit 0  (parent zeroizes and exits immediately — no lingering unlocked process)

vault __clip-holder (hidden subcommand, same binary — C20 single static binary)
  ├── set clipboard with suppression hints (§3.5)
  ├── X11/Wayland: own the selection, serve paste requests
  ├── after timeout: clear iff clipboard still matches ours (§3.4); zeroize; exit
  └── SIGTERM/SIGINT handler: best-effort clear, zeroize, exit (C13 step 4)
```

- The helper holds **only the one field**, mlock'd (C12) and `Zeroizing` (C11) — never the
  data key or other entries. Compromise of the helper window leaks at most what the user
  already chose to copy.
- On macOS/Windows the OS pasteboard server retains contents after the writer exits, so the
  helper's only job there is the timer; on X11/Wayland it is also the selection owner.
- Secret handoff is via a pipe fd inherited at `fork`/`spawn` — `/proc/<pid>/cmdline` and
  `environ` stay clean (C31 discipline applies to our own internals too).

### 3.3 Per-platform delivery

| Platform | Mechanism | Notes |
|---|---|---|
| Linux / X11 | `CLIPBOARD` selection via the [`x11-clipboard`](https://crates.io/crates/x11-clipboard) crate or `arboard` | Helper owns the selection for the timeout window. `PRIMARY` selection is **not** set (middle-click paste surprises). |
| Linux / Wayland | `wl-clipboard-rs` using `ext-data-control-v1` (fall back to `zwlr_data_control_manager_v1`) | Data-control lets a non-focused CLI set the clipboard — exactly our shape. Compositors without either protocol: treat as headless (§3.7). |
| macOS | `NSPasteboard` general pasteboard (`arboard` or direct `objc2-app-kit`) | Set `org.nspasteboard.ConcealedType` + `TransientType` (§3.5). Universal Clipboard: Concealed/Transient items are skipped by history managers honoring the convention; mark and verify (§7 Q2). |
| Windows | `SetClipboardData` (`CF_UNICODETEXT`) via `arboard` | Set the three exclusion formats (§3.5) to keep the secret out of Win+V history and Cloud Clipboard sync. |

Implementation preference: **`arboard`** as the single facade (one audited dependency, 1Password-
maintained, supports the exclusion flags on Windows/macOS), with `wl-clipboard-rs` for the
Wayland data-control path if `arboard`'s coverage proves insufficient — decide at M6 with a
spike (§7 Q1).

### 3.4 Auto-clear timer (C13)

1. Copy; stderr: `Clipboard will be cleared in <N>s.` (exact string per C13).
2. `N` from `~/.vault.toml` `clipboard_timeout` — default **30**, min **5**, max **300** (C13).
3. Helper sleeps `N` seconds (no busy-wait), then **clears only if unchanged**: it compares a
   SHA-256 of current clipboard contents against the hash of what it set (hash, not plaintext,
   is retained after an early zeroize of the source buffer once the clipboard is set — on
   X11/Wayland the serving copy must be kept until clear, mlock'd). If the user has since
   copied something else, the helper exits without touching it (KeePassXC behavior).
4. Clear = overwrite with the empty string (C13 step 3), then on X11/Wayland release ownership.
5. SIGTERM → best-effort clear before exit; SIGKILL is documented as not survivable (C13 test
   note); on macOS/Windows the OS retains the secret in that case until timeout never fires —
   documented residual risk.

**Restore-previous-contents (pass does this; we don't, v1):** restoring requires *reading and
retaining* the prior clipboard — arbitrary other-app data, possibly itself sensitive — inside a
process built to hold exactly one secret, and it can clobber a newer user copy on a race.
Verdict in §4; revisit post-v1 if user demand is real.

### 3.5 Clipboard-history & cloud-sync suppression (C33)

Set together with the secret, verbatim from KeePassXC's verified implementation:

| Platform | Hint | Effect |
|---|---|---|
| Linux | MIME `x-kde-passwordManagerHint` = `secret` | Klipper and compliant managers skip the entry |
| macOS | `org.nspasteboard.ConcealedType` (+ `TransientType`) — Qt apps spell it `application/x-nspasteboard-concealed-type` | History managers honoring nspasteboard.org skip it |
| Windows | `ExcludeClipboardContentFromMonitorProcessing` = 1; `CanIncludeInClipboardHistory` = 0; `CanUploadToCloudClipboard` = 0 | Excluded from Win+V history and Cloud Clipboard |

**Honest limits:** these are *conventions*, not enforcement. Wayland history tools built on
data-control (e.g. `cliphist`) and non-compliant managers may capture the secret anyway; the
timed clear (§3.4) is the backstop, and the THREAT_MODEL residual-risk list gets a line. This
is why B2 is "PARTIAL" in [security_coverage_gaps.md](../../research/security_coverage_gaps.md)
— promoted as constraint C33 (2026-06-10).

### 3.6 Channel discipline: stdout vs stderr vs scrollback

- **stdout: empty.** Nothing is written on success. `blindkey get X | wc -c` → `0`. This is the
  C27 integration test and keeps every pipe/tool-result path clean.
- **stderr: human channel.** Status lines name the entry and field, never the value:
  `Copied 'github-prod' password to clipboard. Clears in 30 s.` Agents typically *do* capture
  stderr in their transcript — that is fine and intended: the agent learns delivery succeeded
  (so it can proceed) without learning the secret. Stored entry names are control-char/ANSI
  sanitized before echo (C28) so a hostile entry title cannot smuggle escape sequences into
  the agent transcript or terminal.
- **Scrollback:** since the secret never hits the TTY, terminal scrollback, tmux capture-pane,
  asciinema recordings, and agent transcripts contain only the status line. The password prompt
  is no-echo (`rpassword`-style) for the same reason.

### 3.7 Error paths

| Condition | Behavior |
|---|---|
| No clipboard available (headless SSH, no `$DISPLAY`/`$WAYLAND_DISPLAY`, compositor lacks data-control) | **Refuse**, exit 7: `no clipboard available on this session; use --stdout (prints a security warning) if you accept plaintext on stdout`. Never silently degrade to stdout — PRD §9.4's resolution — promoted into C27 with exit code 7, 2026-06-10 (intent v1.4.0). |
| Helper spawn fails | Copy is **not** performed (a copy with no timer violates C13); exit 1 with cause. |
| Entry/field not found | exit 9 per the C21 exit-code map; message echoes the *queried* name only after A2 sanitization. |
| Clipboard write fails mid-flight | Zeroize, exit 1; nothing partial left on the clipboard. |

## 4. Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Print to stdout by default (pass-style `show`) | Simple, script-friendly | The exact prompt-injection exfil path (threats §7); prohibited by C27 | **Rejected** |
| OSC 52 terminal escape to set clipboard | Works over SSH | Secret transits the TTY stream — captured by scrollback, tmux, and agent transcripts; defeats the whole design | **Rejected** |
| Long-lived vault daemon owning the clipboard | One unlock, fast repeat access | New attack surface (socket, live keys); v1 is deliberately per-process (see UC-06 §3.4) | **Deferred** post-v1 |
| Restore previous clipboard after clear (pass) | Friendlier UX | Must read+hold arbitrary third-party clipboard data in the secret-holder process; race can clobber newer copies | **Rejected v1**; clear-to-empty only |
| Type the secret via synthetic keystrokes (autotype) | Never on clipboard | Platform-fragile; keystroke injection is itself a malware-adjacent capability; wrong v1 scope | **Deferred** |
| Direct destination injection (1Password Agentic Autofill model) | Strongest model-blind form | Requires a destination integration surface (browser/app); v1 is CLI-only | **North star** for UC-16, not v1 |
| Set both CLIPBOARD and PRIMARY (X11) | Middle-click paste | Doubles exposure surface and history-manager capture | **Rejected** |

## 5. Constraint compliance map

| Constraint | How this design satisfies it |
|---|---|
| **C27** | Default delivery is the OS clipboard (§3.2–§3.3); stdout is empty on success (§3.6); `--stdout` is the warned opt-in specified in UC-05; no network/LLM path exists (§3.7 has no fallback that emits plaintext silently) |
| **C13** | stderr notice with timeout; default 30 s, configurable 5–300 via `~/.vault.toml`; SIGTERM best-effort clear (§3.4). **Noted deviation:** C13 says "background thread"; a thread dies with the one-shot CLI process, so this design uses a detached helper *process* to honor C13's actual requirements (non-blocking, timer survives to fire). Flagged for intent wording update — §7 Q6; until amended, the intent wins and a reviewer must approve this reading |
| **C23** | Delivery is purely local IPC (X11/Wayland socket, pasteboard server, Win32 API) — no network syscalls; covered by the C23 strace test |
| **C11/C12** | Secret buffers `Zeroizing` + mlock'd in both parent and helper; helper holds one field only (§3.2) |
| C33 (was gap B2) | History/cloud-sync suppression hints on all three platforms, with documented limits (§3.5) |

## 6. Test plan

1. **INTEGRATION (C27):** `blindkey get X --field password` → stdout byte-count 0; clipboard equals
   the secret; stderr contains `Copied` and `Clears in`.
2. **INTEGRATION (C13):** copy; poll clipboard at t=31 s (default config) → empty or changed.
   With `clipboard_timeout = 5`: cleared by t=6 s.
3. **INTEGRATION (C13 SIGTERM):** copy with `--timeout 300`; SIGTERM the holder; clipboard
   cleared before process exit.
4. **INTEGRATION (clear-iff-unchanged):** copy secret; overwrite clipboard with `sentinel`;
   wait past timeout; assert clipboard still `sentinel`.
5. **INTEGRATION (hints, Linux CI):** read back offered MIME types while holder is alive;
   assert `x-kde-passwordManagerHint` present with value `secret`. Windows/macOS equivalents
   behind platform CI gates.
6. **INTEGRATION (headless):** run with `DISPLAY`/`WAYLAND_DISPLAY` unset → exit 7, stderr
   mentions `--stdout`, clipboard untouched, stdout empty.
7. **UNIT (no secret on argv/env):** spawn the holder; read its `/proc/<pid>/cmdline` and
   `environ`; assert the secret appears in neither.
8. **AGENT-SIMULATION (flagship e2e):** drive `blindkey get` under a PTY harness that records
   everything a terminal-attached agent would see (stdin/stdout/stderr merged); assert the
   secret string appears nowhere in the recording.
9. **CI (C23):** `strace -e trace=network` over the full get-and-clear lifecycle → no network
   syscalls (existing C23 harness, extended to the helper).

## 7. Open questions

1. **Crate spike:** `arboard` alone vs `arboard` + `wl-clipboard-rs` for Wayland data-control —
   verify `arboard`'s no-focus Wayland behavior and Windows exclusion-format support on real
   compositors/Win11 before M6. (Claimed capabilities verified against docs, not yet against
   hardware.)
2. **macOS Universal Clipboard:** confirm empirically that `ConcealedType`/`TransientType`
   suppress Handoff sync to other devices, or document as residual risk alongside B2.
3. **Promote the headless-refusal rule** — ✅ Resolved 2026-06-10 (intent v1.4.0): C27 now
   mandates refusal with exit code 7 and the exact guidance message; never a silent stdout
   fallback.
4. **Wayland history tools** (`cliphist` et al.) ignore suppression hints today — pursue an
   upstream `ext-data-control` "sensitive" convention, or accept the timed-clear backstop?
5. **Should the helper re-assert the clipboard** if another process overwrites it within the
   window (anti-clobber vs anti-spam)? Current answer: no — first write wins, user intent rules.
6. **C13 wording amendment:** "background thread" → "background thread or detached helper
   process that does not block the invoking command" — needed because a thread cannot outlive
   a one-shot CLI invocation to fire the clear (§3.2, §5). Maintainer sign-off required.
