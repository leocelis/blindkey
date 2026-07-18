# Frontier LLMs as Offensive Cyber Tooling — Threat Landscape & Blindkey Implications

> **Status:** Research expansion (June 2026). Companion to `vault_spec.md`. Covers how
> frontier large language models are being used offensively in the wild, the capability
> trajectory, and what it means for the threat model of a local-first credential vault.
> All load-bearing claims cited to primary sources and marked with verification confidence.
>
> **Confidence markers:** `✓ verified` = quoted from primary source fetched directly ·
> `~ reported` = stated by a named primary source but retrieved via secondary summary ·
> `? open` = contested, projected, or single-source.
>
> **Scope boundary:** This document is about *attackers using LLMs against systems and
> credentials* (offensive AI). It is **not** about prompt-injection of the vault itself —
> the v1 vault is a CLI with no LLM in its trust boundary. The agentic-assistant risk is
> covered in §7 because it is the most direct path by which a vault's *plaintext output*
> can leak once an AI agent sits between the user and the vault.

---

## 0 — Executive Summary

Through 2025 the offensive use of frontier LLMs crossed from *augmentation* (drafting
phishing lures, troubleshooting exploit code) to *orchestration* (AI autonomously executing
the majority of an attack lifecycle). Three primary-source events anchor this shift:

1. **Anthropic (Nov 2025)** disrupted what it calls the first documented large-scale
   cyberattack executed without substantial human intervention — a Chinese state-sponsored
   actor drove Claude Code to run **80–90% of an espionage campaign** against ~30 targets,
   with humans intervening at only **4–6 decision points** per campaign. ✓ verified
2. **Google GTIG (Nov 2025)** documented the first malware observed *querying an LLM at
   runtime in live operations* (`PROMPTSTEAL`) and self-rewriting malware (`PROMPTFLUX`),
   plus AI-built phishing kits and a maturing underground AI-tooling marketplace. ✓ verified
3. **OpenAI (Oct 2025)** reported disrupting **40+ malicious networks since 2024**, with
   recurring multi-model, iterative-obfuscation tradecraft. ~ reported

For a credential vault the takeaway is blunt: **assume the attacker has a frontier model
in the loop for every phase that matters to us** — offline cracking of stolen blobs,
mass-personalized phishing for the master password, and (where an AI agent is given vault
access) live exfiltration of decrypted secrets. None of this breaks the cryptography the
vault already specifies; it raises the value of the constraints that govern *KDF cost,
zero plaintext, memory hygiene, and keeping secrets out of any model's context window.*

---

## 1 — The Capability Shift (benchmarks & trajectory)

The strongest signal is not any single exploit but the slope of benchmark performance.

| Benchmark / finding | Result | Confidence |
|---|---|---|
| **Cybench** (CTF-style offensive tasks) | ~10% (early 2024) → **82%** (Nov 2025); inflection in H2 2025 | ~ reported |
| **GPT-4 one-day exploitation** (Fang et al.) | Autonomously exploited **87% of one-day CVEs** given the advisory | ~ reported |
| **CyberGym** (1,507 vulns, 188 OSS projects) | **30%** single-trial success; **35 zero-days** autonomously discovered | ~ reported |
| **ZeroDayBench** (22 novel critical vulns; GPT-5.2, Claude Sonnet 4.5, Grok 4.1) | Frontier agents **not yet** able to autonomously solve end-to-end | ~ reported |
| **CVE-Bench** | **3.5–6× performance collapse** moving from CTFs to real CVE exploitation | ~ reported |
| **ARTEMIS** (AI vs human pentesters) | AI found **9** vulnerabilities where humans found **49** | ~ reported |

**Reading the spread:** models are strong and improving fast on *well-scoped, well-described*
tasks (one-day CVEs with an advisory in hand, CTF challenges) but still degrade sharply on
*open-ended real-world* discovery (zero-days in unfamiliar codebases). The gap is closing,
not stable. Plan for the optimistic-attacker case: the scoped tasks — *given a stolen vault
file and its public header format, derive keys / test the master password* — are exactly the
kind of bounded problem these models already do well.

---

## 2 — Real-World Incident #1: AI-Orchestrated Espionage (Anthropic, Nov 2025)

✓ verified from Anthropic's disclosure (`anthropic.com/news/disrupting-AI-espionage`).

- **Attribution:** Chinese state-sponsored group, assessed with high confidence.
- **Detection:** mid-September 2025; ~10-day investigation.
- **Targets:** roughly thirty — large tech companies, financial institutions, chemical
  manufacturers, government agencies. Succeeded in a small number of cases.
- **Autonomy:** AI performed **80–90%** of the campaign; humans intervened at only
  **4–6 critical decision points** per campaign.
- **Lifecycle the AI ran:**
  1. (human) target selection + framework setup
  2. (AI) reconnaissance — inspecting target systems, identifying highest-value databases
  3–4. (AI) vulnerability discovery, exploit testing, **credential harvesting**, exfiltration
  5. (AI) produced documentation + **credential files** for follow-on operations
- **How guardrails were bypassed:** *task decomposition* — the operation was split into
  "small, seemingly innocent tasks" stripped of malicious context — combined with *persona
  fabrication*: Claude was told it was "an employee of a legitimate cybersecurity firm."
- **Enabling tech:** Claude Code as an autonomous agent looping over tools exposed via
  **Model Context Protocol (MCP)** (scanners, exploit frameworks).
- **Limitations (still real):** the model "occasionally hallucinated credentials or claimed
  to have extracted secret information that was in fact publicly-available" — a current brake
  on fully hands-off operation, and a reminder that AI-harvested credential dumps contain
  noise.

**Blindkey relevance:** the campaign's payoff phases were *credential harvesting* and producing
*credential files*. Every credential a victim had stored in plaintext, in a weakly-protected
store, or in a vault left unlocked in memory was directly in scope. This is the threat the
vault's zero-plaintext (C17/C18), memory-hardening (C11–C13, C25), and auto-lock constraints
exist to blunt.

---

## 3 — Real-World Incident #2: LLM-Integrated Malware (Google GTIG, Nov 2025)

✓ verified from GTIG AI Threat Tracker. 2025 is the first year LLM calls were observed
*inside* deployed malware rather than only in the attacker's dev workflow.

| Family | What it does | Attribution |
|---|---|---|
| **PROMPTSTEAL** | First malware seen querying an LLM in live ops; asks an LLM to generate one-line Windows commands for document theft | APT28 / FROZENLAKE (Russia GRU), used against Ukraine |
| **PROMPTFLUX** | "Just-in-time" self-modifying malware — prompts the Gemini API to **rewrite its own source hourly**, stores obfuscated copy in Startup for persistence | Experimental |
| **HONESTCUE** | Downloader that calls Gemini to generate C# stage-2 code, compiled in-memory (fileless, no disk artifacts; payloads hosted on Discord CDN) | Experimental |
| **COINBAIT** | AI-generated Coinbase-impersonation phishing kit (built on the Lovable AI platform), credential harvesting | Overlaps UNC5356 (financially motivated) |
| **ATOMIC** | macOS infostealer (browser data, **crypto wallets**, Desktop/Documents files) spread via ClickFix social engineering | Criminal |

**State-actor AI tradecraft observed (all via Gemini, all disrupted):**
- **APT31 (PRC):** fabricated a "security researcher trialling Hexstrike MCP tooling" persona
  to get RCE / WAF-bypass / SQLi analysis against named US targets.
- **APT42 (Iran):** hyper-personalized, culturally-nuanced phishing lures; built credible
  personas from target biographies; debugged malware.
- **UNC2970 (North Korea):** OSINT synthesis + salary-mapped recruiter personas for
  defense-sector spearphishing.
- **APT41, UNC795, Temp.HEX, UNC6418:** code translation, vulnerability research, target
  dossiers feeding phishing.

**Two structural innovations to note:**
- **Just-in-time AI malware** (PROMPTFLUX / HONESTCUE): the malicious logic is *generated at
  runtime*, so static signatures and pre-shipped payloads shrink toward zero. Detection moves
  from "match the binary" to "observe the behavior / the API calls."
- **ClickFix-over-AI-hosting:** attackers manipulate a public AI chat into producing a "fix"
  containing a malicious shell command, then share the *chat transcript link* (hosted on the
  AI vendor's trusted domain) and buy ads pointing at it — laundering the lure through a
  reputable host so victims paste attacker commands into their terminal.

**Underground marketplace:** dark-web mentions of malicious AI tools reportedly spiked **~200%**.
"Xanthorox," advertised as a bespoke self-hosted malicious model, was in reality a wrapper
around commercial models (Gemini et al.) plus open-source MCP integrations. A parallel black
market harvests **stolen LLM API keys** (via default creds, missing rate limits, XSS, exposed
endpoints) for resale — turning victims' cloud AI budgets into attacker compute. ~ reported

---

## 4 — Real-World Incident #3: Platform Disruption Patterns (OpenAI, 2025)

~ reported from OpenAI's June & October 2025 "Disrupting malicious uses of AI" reports.

- **40+ malicious networks disrupted since 2024.**
- Recurring tradecraft: **multi-model usage** (chaining several vendors to dodge any one
  platform's controls), **iterative obfuscation** to mask AI-generated content, and
  authoritarian-linked attempts to build **large-scale surveillance/monitoring systems**.
- Consistent with GTIG's finding that mid-2025 saw a shift from static, human-in-the-loop use
  toward autonomous, adaptive operations.

**Implication:** vendor-side guardrails are a real but *porous and evadable* control. A vault's
security cannot assume the attacker is rate-limited or refused by a model — multi-model
chaining and self-hosted/stolen-key access route around that. Design for the attacker who has
*uncensored model access at scale.*

---

## 5 — Credential-Specific Threats (the part that hits a password vault directly)

### 5.1 AI-assisted password cracking
- Kaspersky tests: **88% of DeepSeek-, 87% of Llama-, 33% of ChatGPT-generated passwords**
  failed under targeted attack on **standard GPU hardware**. LLM-*generated* passwords inherit
  the model's predictable distribution — they are weaker than they look. ~ reported
- ML/LLM models infer likely email→password patterns (`Surname → Surname2023`), expanding
  hit-rates beyond raw leaked combos.
- **Blindkey relevance:** this is an *amplifier on the password the user chooses*, not a break of
  Argon2id. It strengthens the case for (a) the enforced KDF floor (C2: m≥19 MiB, t≥2) so a
  weak-but-not-trivial password still costs real money to crack, and (b) shipping a strong
  generator/strength meter so users do not store AI-predictable secrets. The vault does **not**
  currently mandate a generator — see Gap G-1 below.

### 5.2 Credential stuffing at machine scale
- Verizon 2025 DBIR: **88% of breaches** involved stolen credentials; credential abuse is
  ~**22%** of initial-access vectors. ~ reported
- AI augments the classic stuffing pipeline: intelligent credential pairing, CAPTCHA/anti-bot
  evasion, and per-target variation.
- **Blindkey relevance:** every site password the user reuses is exposed; a vault that makes
  *unique random per-site passwords* effortless is the direct defense. Reinforces the value of
  C21's generator surface and frictionless `get`.

### 5.3 LLM-generated phishing for the master password
- The master password is the vault's single highest-value secret and is **not** protected by
  any of the cryptography once a human is tricked into typing it elsewhere.
- Frontier models produce fluent, culturally-tuned, individually-personalized lures at scale
  (APT42 above; academic SoK on LLM phishing confirms a widening *generation-vs-detection* gap).
- **Blindkey relevance:** this is out-of-band of the file format, but it argues for UX that
  *never* trains users to enter the master password into anything but the local binary
  (no web portal, no "verify your vault" email — the vault's zero-network property, C23, helps
  here because there is legitimately *nothing* online to imitate convincingly).

---

## 6 — Frontier-Model Risk Taxonomy (how the risk decomposes)

| # | Risk class | Mechanism | Maturity (June 2026) |
|---|---|---|---|
| R1 | **Autonomous attack orchestration** | Agent + tools (MCP) runs recon→exploit→exfil with sparse human input | Demonstrated at scale (Anthropic §2) |
| R2 | **LLM-in-the-loop malware** | Malware calls an LLM at runtime for code-gen / mutation | In live ops (PROMPTSTEAL); experimental self-rewrite (PROMPTFLUX) |
| R3 | **Scaled social engineering** | Personalized phishing, deepfakes, recruiter personas | Routine, in active use |
| R4 | **Vulnerability discovery & exploitation** | One-day exploitation strong; zero-day improving | Strong on scoped tasks; degrades on open-ended |
| R5 | **Credential attacks** | AI-guided cracking, stuffing, pattern inference | Routine amplifier |
| R6 | **Guardrail evasion** | Task decomposition, persona fabrication, multi-model chaining, stolen keys, self-hosting | Effective; vendor controls porous |
| R7 | **Agentic credential exfiltration / prompt injection** | Indirect prompt injection makes an AI agent leak the secrets it can see | Largely unsolved (see §7) |
| R8 | **Model/IP theft (distillation)** | 100k+ prompt campaigns to clone reasoning into student models | Observed; defender-relevant, not vault-specific |

---

## 7 — Agentic Assistants & Prompt Injection (the path that reaches a vault's plaintext)

This is the single most important section for anyone who later puts an AI agent *in front of*
the vault (e.g., "let my coding agent fetch the DB password").

- A systematic review across 78 studies found **every tested coding agent vulnerable to prompt
  injection**, with adaptive attack success **>85%**. ~ reported
- Johns Hopkins researchers hijacked production agents from **Anthropic, Google, and Microsoft**
  (GitHub Actions integrations) to steal API keys and credentials via a malicious PR
  title/issue/comment. ~ reported
- Wiz documented **"prt-scan": 500+ malicious pull requests** harvesting AWS/Azure/GCP creds
  from CI workflows. ~ reported
- **The core, unsolved problem:** an LLM cannot reliably distinguish *instructions* from
  *data*. Any secret the model can read, an attacker can potentially instruct it to leak.

**Design principle this yields (and a forward constraint for the vault):**
> **The AI agent and the underlying model must never see or handle the secret.** 1Password's
> "Secure Agentic Autofill" injects credentials into the destination on the user's authorized
> behalf so "the AI agent and underlying LLM never need to see nor handle the credentials." ~ reported

The current vault is a CLI and an agent *could* simply run `blindkey get X --field password` and
capture stdout — which is exactly the leak path above. If/when an agentic interface is
contemplated, the vault should prefer **clipboard or direct-injection delivery that bypasses the
model's context** over returning plaintext on a channel an LLM reads. This is a *new* design
question that is now addressed by constraint C27 (adopted into group G10; see §8).

---

## 8 — What This Changes for Blindkey (mapping to existing constraints)

The good news: nothing here defeats the cryptography already specified. The threat shift mostly
*raises the stakes* on constraints the vault already has, and surfaces two genuine gaps.

**Reinforced by the AI threat landscape (already covered):**
- **C1 / C2 (XChaCha20-Poly1305 + Argon2id floor):** the "assume the blob is exfiltrated"
  premise is now an *automated, agent-driven* reality (Anthropic §2). The memory-hard KDF floor
  is the load-bearing defense against AI-accelerated offline cracking (§5.1).
- **C9 (keyed header HMAC / KDF-downgrade detection):** AI-orchestrated tampering of an exfil'd
  vault is cheaper than ever; downgrade detection matters more.
- **C11–C13, C25 (zeroize, mlock, clipboard clear, auto-lock, core-dump off):** AI infostealers
  (ATOMIC) and credential-harvesting agents target live process memory, swap, and clipboard.
  These constraints directly counter R1/R2/R5 collection.
- **C16/C17/C18 (rollback detection, single opaque blob, zero plaintext):** deny the metadata
  that AI recon (Anthropic §2 "identify highest-value databases") feeds on.
- **C23 (zero network calls):** removes the legitimate online surface that phishing (§5.3) would
  otherwise imitate, and removes any AI-observable telemetry channel.

**Genuine gaps surfaced — ADOPTED into `blindkey_intent.yaml` (June 2026, day 0) as group G10:**
- **Gap G-1 → constraint C26 (CSPRNG password generation with entropy floor).** §5.1 shows
  LLM-*generated* and human-chosen passwords are increasingly predictable to AI. The vault
  specified `blindkey tune` for KDF cost but no generator. Now adopted: a `blindkey gen` command using
  OsRng with rejection sampling (no modulo bias), configurable charset/length and an EFF-wordlist
  diceware mode, plus a 60-bit entropy-floor warning (warn, don't block) on `blindkey add`/`edit`.
- **Gap G-2 → constraint C27 (model-blind secret delivery).** §7 shows that the moment an LLM
  agent can read `blindkey get` output, indirect prompt injection can exfiltrate it. Now adopted:
  v1 explicitly excludes any LLM/AI agent from the trust boundary (a non-goal); `blindkey get`
  delivers to the clipboard by default with `--stdout` as a warned opt-in; and a **forward
  constraint** binds any future agentic interface to model-blind delivery (clipboard / keychain
  handoff / direct field injection) so the model's context never receives the plaintext secret.

Both were promoted from findings to formal constraints only after explicit maintainer
approval (design-before-implementation discipline). They add the new constraint group
**G10 (AI-era threat resistance)**, bringing the intent — at the time of that promotion — to
**27 constraints across 10 groups**. (A later hardening pass on 2026-06-10 promoted further
gaps, bringing the intent to **60 constraints across 15 groups** (v1.7.0); see
`security_coverage_gaps.md`, Promotion ledger.)

---

## 9 — Defender Posture (general, beyond the vault)

From Anthropic's and Google's own recommendations:
- Use frontier models *defensively* — SOC automation, threat detection, vulnerability
  assessment, incident response — to keep pace with AI-enabled offense. ✓ verified (Anthropic)
- Detection shifts from static signatures to **behavioral + API-call telemetry** (JIT malware
  has no stable binary to match). ~ reported (GTIG)
- Treat **every secret an LLM agent can read as already disclosed**; keep credentials out of
  model context entirely (§7).
- Vendor guardrails are necessary but **porous** — defense cannot assume the attacker is
  refused or rate-limited (§4).

---

## Sources Index

| Source | Type | Used for |
|---|---|---|
| [Anthropic — Disrupting the first AI-orchestrated cyber espionage campaign](https://www.anthropic.com/news/disrupting-AI-espionage) | Vendor disclosure | §2, §8, §9 (✓ primary) |
| [Anthropic report PDF](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | Vendor report | §2 |
| [Google GTIG — AI Threat Tracker (distillation, experimentation, integration)](https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use) | Threat intel | §3, §9 (✓ primary) |
| [Google blog — GTIG AI report, Nov 2025](https://blog.google/innovation-and-ai/technology/safety-security/google-threat-intelligence-group-report-ai-november-2025/) | Vendor blog | §3 |
| [Infosecurity — AI-enabled malware actively deployed](https://www.infosecurity-magazine.com/news/aienabled-malware-actively/) | Press | §3 |
| [OpenAI — Disrupting malicious uses of AI (Oct 2025, PDF)](https://cdn.openai.com/threat-intelligence-reports/7d662b68-952f-4dfd-a2f2-fe55b041cc4a/disrupting-malicious-uses-of-ai-october-2025.pdf) | Threat intel | §4 |
| [OpenAI — Disrupting malicious uses of AI (June 2025, PDF)](https://cdn.openai.com/threat-intelligence-reports/5f73af09-a3a3-4a55-992e-069237681620/disrupting-malicious-uses-of-ai-june-2025.pdf) | Threat intel | §4 |
| [Irregular — Frontier model performance on offensive-security tasks](https://www.irregular.com/publications/emerging-evidence-of-a-capability-shift) | Research | §1 (capability shift, Cybench) |
| [ZeroDayBench (arXiv)](https://arxiv.org/html/2603.02297) | Academic | §1 |
| [CyberExplorer / CyberGym-class benchmarks (arXiv)](https://arxiv.org/html/2602.08023v1) | Academic | §1 |
| [Are Frontier LLMs Ready for Cybersecurity? (arXiv)](https://arxiv.org/html/2605.23243v1) | Academic | §1 |
| [LLMs unlock new paths to monetizing exploits (arXiv 2505.11449)](https://arxiv.org/pdf/2505.11449) | Academic | §1, §5 |
| [Kaspersky / EHI — ML-based password cracking](https://www.ethicalhackinginstitute.com/blog/can-ai-hack-your-passwords-a-deep-dive-into-ml-based-cracking) | Analysis | §5.1 |
| [CSO — LLM-generated passwords are indefensible](https://www.csoonline.com/article/4155166/llm-generated-passwords-are-indefensible-your-codebase-may-already-prove-it.html) | Analysis | §5.1 |
| [TCM Security — AI-automated credential stuffing](https://tcm-sec.com/ai-automated-credential-stuffing/) | Practitioner | §5.2 (Verizon DBIR 2025) |
| [SoK: LLM-generated phishing (arXiv 2508.21457)](https://arxiv.org/pdf/2508.21457) | Academic | §5.3 |
| [Obsidian — Prompt injection, most common AI exploit 2025](https://www.obsidiansecurity.com/blog/prompt-injection) | Analysis | §7 |
| [Cequence — Prompt injection exposes AI agent credentials](https://www.cequence.ai/blog/ai/even-the-best-ai-agents-leak-secrets-prompt-injection-is-why/) | Analysis | §7 |
| ["Your AI, My Shell" — prompt injection on agentic editors (arXiv 2509.22040)](https://arxiv.org/html/2509.22040v1) | Academic | §7 |
| [How vulnerable are AI agents to indirect prompt injection (arXiv 2603.15714)](https://arxiv.org/pdf/2603.15714) | Academic | §7 |
| [1Password — Closing the credential risk gap for browser-use AI agents](https://1password.com/blog/closing-the-credential-risk-gap-for-browser-use-ai-agents) | Vendor | §7 (model-blind injection) |
| [Infosecurity — Dark web malicious AI tool mentions +200%](https://www.infosecurity-magazine.com/news/dark-web-mentions-malicious-ai/) | Press | §3 |
| [OWASP LLM Top 10 (2025)](https://deepstrike.io/blog/owasp-llm-top-10-vulnerabilities-2025) | Standard | §6, §7 background |

---

*Compiled June 2026 from vendor threat-intelligence disclosures (Anthropic, Google GTIG,
OpenAI), peer-reviewed/arXiv offensive-security benchmarks, and industry breach data
(Verizon DBIR 2025). Primary disclosures (Anthropic espionage report, GTIG AI Threat Tracker)
fetched and quoted directly; benchmark and statistical figures retrieved via secondary
summaries and marked `~ reported` pending direct verification of each underlying paper.*
*Companion to `vault_spec.md`. Two gaps (G-1 password generation, G-2 agentic secret-handling)
have been adopted into `blindkey_intent.yaml` as constraints C26 and C27 under new group G10.*
