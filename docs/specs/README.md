# Technical Design Specs

One spec per major use case in the [PRD](../PRD.md). Each spec proposes a concrete design
grounded in prior art (open-source projects and academic/standards sources), maps it to the
binding constraints in [`blindkey_intent.yaml`](../../blindkey_intent.yaml), and ends with a test
plan and open questions.

**Precedence:** where a spec and the intent artifact disagree, the intent wins. Specs are
*how we plan to satisfy* the constraints; the intent is *what must be true*.

| Spec | Use case | Key constraints |
|------|----------|-----------------|
| [UC-01](UC-01-install-and-init.md) | Install and create a vault | C20, C2, C4, C5, C7, C8 |
| [UC-02](UC-02-csprng-generation.md) | Generate provably strong credentials | C26 |
| [UC-03](UC-03-store-secret.md) | Store a secret (zero plaintext) | C18, C19, C17, C11 |
| [UC-04](UC-04-model-blind-retrieval.md) | **Retrieve a secret while an AI agent is watching** | C27, C13, C23 |
| [UC-05](UC-05-script-and-ci-output.md) | Scripts & CI — explicit warned opt-outs | C27, C21, SC5 |
| [UC-06](UC-06-entry-management.md) | Find and manage entries day-to-day | C21, C25, SC2 |
| [UC-07](UC-07-untrusted-storage-sync.md) | Sync over storage you don't trust | C17, C16, C10, C9 |
| [UC-08](UC-08-conflict-merge.md) | Recover from a sync conflict | C21, C16, SC3 |
| [UC-09](UC-09-hardware-factors.md) | Hardware factors without lockout risk | C5, C6, C14, C15 |
| [UC-10](UC-10-hostile-file-parsing.md) | Open a stale or hostile vault file safely | C2, C7, C8, C9, A1 |
| [UC-11](UC-11-kdf-calibration.md) | Keep KDF cost calibrated | C2, C22, C8 |
| [UC-12](UC-12-migration-import.md) | Migrate from an existing manager | C21, C26 |
| [UC-13](UC-13-verifiable-releases.md) | Verify what you're running | C24, C23, C3 |
| [UC-14](UC-14-runtime-hardening.md) | Survive a compromised-adjacent machine | C11, C12, C25, C13 |
| [UC-15](UC-15-vulnerability-reporting.md) | Report a vulnerability (process spec) | — |
| [UC-16](UC-16-agent-interface-future.md) | Agent uses the vault, never sees a secret *(post-v1 exploration)* | C27 (forward) |
| [UC-17](UC-17-quick-capture-raw-import.md) | Quick-capture from a messy `keys.txt` (lenient import + review) | C21, C26, C18, C19, C27 |
| [UC-18](UC-18-native-ui.md) | Native UI shells (TUI + egui GUI shipped; SwiftUI post-v1) | C20, C11, C12, C25, C27, C40–C54 |
| [UC-19](UC-19-omni-search.md) | Fuzzy keyboard-first omni-search (CLI + GUI) | C35–C39 |
| [UC-20](UC-20-desktop-gui-hardening.md) | Desktop GUI performance & security hardening (`blindkey-gui`) | C40–C45; C20, C27, C30, C35, C38 |
| [UC-21](UC-21-desktop-gaps-closure.md) | Desktop gaps closure — session hygiene, keyfile GUI, trust UX | C46–C54; C27, C35, C44, UC-09 |
| [UC-22](UC-22-enterprise-readiness.md) | Fleet deploy & release quality gate | C55–C60; C38, C39 |
| [UC-23](UC-23-sealed-file-storage.md) | Seal any file/folder for storage you don't trust *(Accepted v1.0 · shipped July 2026)* | C61–C66; C1, C2, C7, C11, C27, C30–C32 |
| [UC-24](UC-24-mcp-broker.md) | Serve the handle broker to MCP clients (`blindkey mcp`) *(Accepted v0.2 · shipped)* | C27, C13; extends UC-16 |
| [UC-25](UC-25-local-encrypted-volume.md) | Local encrypted workspace volume — live mount *(Accepted v0.5 · phased implementation · A1 kind table landed)* | C67–C74 (FORWARD); C1–C3, C5, C7, C11, C16, C23, C27, C30–C32, C64 |
| [UC-26](UC-26-desktop-ui-information-architecture.md) | Desktop UI IA & usability redesign (`blindkey-gui`) *(Implemented v1.0)* | C75–C81; C20, C27, C40–C54, C72–C74 |
| [UC-27](UC-27-desktop-ui-visual-craft.md) | Desktop UI visual craft polish (`blindkey-gui`) *(Implemented v1.0)* | C82–C87; C20, C27, C40–C54, C75–C81 |

## Spec lifecycle

`Draft` → reviewed by maintainers → `Accepted` (hard-to-reverse decisions also get an
[ADR](../adr/)) → implementation per the intent's segmentation plan → spec updated to
`Implemented` (or `Accepted · implemented pre-1.0` / `design only` where noted in the header).

Most UC specs through CP-7 are **Accepted v0.2 · implemented pre-1.0** as of the 2026-06-25
constraint sweep. Exceptions: UC-08 and UC-12 (design only, not yet implemented); UC-16 (post-v1
exploration); UC-13 (checksums + reproducible build shipped; cosign/SLSA deferred). **UC-23** is
**Accepted v1.0 · shipped** (July 2026) — sealed `.vltf` containers with C61–C66 verified in-tree.
**UC-24** MCP broker delivery is **Accepted v0.2 · shipped**. **UC-25** (live local volume) is
**Accepted v0.5** — requirements-traced implementation contract; A1 kind table landed; remaining
Gate-0 ADRs (magic freeze, merkle, mount crate, macOS provider) before A2+.
**UC-26** (desktop UI IA & usability) is **Implemented v1.0** — fonts/legibility gate, Credentials |
Workspace mode chrome, mount honesty; **C75–C81 PASS** (intent v1.9.3 / G18).
**UC-27** (desktop UI visual craft) is **Implemented v1.0** — layout/hierarchy/spacing/accent polish;
**C82–C87 PASS** (intent v1.9.4 / G19); ROADMAP **S-26**. Does not change UC-26 IA.

New constraints discovered while spec-writing are proposed as Part-2 candidates — the
2026-06-10 pass promoted the first batch as C28–C34 (see
[research/security_coverage_gaps.md](../../research/security_coverage_gaps.md)).
