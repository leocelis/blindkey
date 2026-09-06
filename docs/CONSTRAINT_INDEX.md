# Constraint test index (IVD Rule 3)

Canonical constraints: [`blindkey_intent.yaml`](../blindkey_intent.yaml) — **102 constraints**, **22 groups**, intent **v1.9.7**
(extends the v1.9.6 / C1–C98 set with UC-30 C99–C102 FORWARD).
C61–C66 (G16, [UC-23 sealed file storage](specs/UC-23-sealed-file-storage.md)) ship in **S-22**
(implemented). C67–C74 (G17, [UC-25 local encrypted volume](specs/UC-25-local-encrypted-volume.md))
are **PASS**. C75–C81 (G18, [UC-26 desktop UI IA](specs/UC-26-desktop-ui-information-architecture.md))
are **PASS** via `uc26_constraints.rs` + theme/mode modules. C82–C87 (G19,
[UC-27 desktop UI visual craft](specs/UC-27-desktop-ui-visual-craft.md)) are **PASS** via
`uc27_constraints.rs` + craft theme helpers. C88–C93 (G20,
[UC-28 desktop UI component kit](specs/UC-28-desktop-ui-component-kit.md)) are **PASS** via
`uc28_constraints.rs` + surface/quiet/list helpers. C94–C98 (G21,
[UC-29 contrast/typography/polarity](specs/UC-29-desktop-ui-contrast-typography.md)) are **PASS** via
`uc29_constraints.rs` + Dark theme force + token retune. C99–C102 (G22,
[UC-30 volume working copy](specs/UC-30-volume-working-copy.md)) are **FORWARD / UNVERIFIED**
until checkout/checkin ships (ROADMAP S-29; blocked on macOS mount).
The CP-7 sweep below is **66/66 PASS** at the automated gate for the original **66 constraints**
through C66; C67–C74 are **PASS** at the core+CLI+GUI+fuzz level; C75–C81 are **PASS** at the
GUI presentation level; C82–C87 are **PASS** at the GUI craft level; C88–C93 are **PASS** at the
GUI component-kit level; C94–C98 are **PASS** at the GUI contrast/polarity level (see the C94–C98 rows);
C99–C102 are **FORWARD** (see those rows).

Tests are **distributed** across crate suites (not a single monolithic file). Run everything with:

```sh
just check          # fmt + clippy + cargo test --workspace
just audit-ready    # release search benches + workspace tests + fmt + clippy (C55)
```

## CP-7 IVD Rule 2 sweep (2026-06-25)

**Summary:** 66 PASS · 0 NEEDS_REVIEW · 0 FAIL

| ID | Title (short) | Status | Evidence |
|----|---------------|--------|----------|
| C1 | XChaCha20-Poly1305 STREAM payload | PASS | `blindkey-core/src/crypto/`, format round-trip tests |
| C2 | Argon2id KDF floor/ceiling + NFC | PASS | `crypto/kdf.rs` unit tests, open rejects hostile params |
| C3 | Supply-chain policy (audit/deny) | PASS | `constraint_gaps.rs` (`c3_*`), `just audit` |
| C4 | Constant data key + stanza re-wrap | PASS | `constraint_gaps.rs`, envelope tests |
| C5 | HKDF wrapping key derivation | PASS | `crypto/envelope.rs` unit tests |
| C6 | Hardware stanza HKDF recipe | PASS | `constraint_gaps.rs`, `blindkey-hardware` |
| C7 | Header parser bounds | PASS | `format/header.rs`, `robustness.rs`, fuzz |
| C8 | Plaintext header fields | PASS | format unit tests |
| C9 | Keyed header HMAC | PASS | `robustness.rs`, tamper tests |
| C10 | HmacBlockStream | PASS | block stream tests + fuzz |
| C11 | mlock / locked memory | PASS | `memory/` unit tests |
| C12 | Zeroize on drop | PASS | `memory/` + `blindkey-sys` |
| C13 | Timed clipboard clear (helper) | PASS | `blindkey-clip` + `clipboard.rs`, `cli.rs` hold-clipboard |
| C14 | FIDO2 PRF stanza (libfido2) | PASS | `fido2_mock.rs` enroll/unlock; salt/HKDF; libfido2 FFI M7 |
| C15 | TPM PCR-sealed stanza + re-enroll | PASS | `tpm_mock.rs`, `enroll-tpm`/`re-enroll-tpm` CLI + `--help` |
| C16 | Monotonic vault_version + rollback warn | PASS | `rollback/`, `vault.rs` tests |
| C17 | Single opaque blob on disk | PASS | `constraint_gaps.rs` (`c17_*`) |
| C18 | Zero plaintext in stanzas | PASS | `payload.rs`, vault tests |
| C19 | Zero plaintext in entries at rest | PASS | entry encryption tests |
| C20 | CLI exact command surface | PASS | `cli.rs` integration tests |
| C21 | Minimum viable CLI + stanzas + exit codes | PASS | `cli.rs`, `main.rs`, `blindkey stanzas list/remove` |
| C22 | `blindkey tune` KDF calibration | PASS | `crypto/tune.rs`, CLI tune tests |
| C23 | Zero network in CLI | PASS | `constraint_policy.rs` |
| C24 | OSS license + dependency policy | PASS | `constraint_policy.rs`, `deny.toml` |
| C25 | Constant-time secret compare | PASS | `memory/` + clipboard helper |
| C26 | CSPRNG generation | PASS | `gen.rs` unit tests |
| C27 | Model-blind retrieval + headless exit 7 | PASS | `cli.rs` C27 test, `blindkey-clip::clipboard_available` |
| C28 | Terminal output sanitization | PASS | `terminal.rs` (`c28_*`), `cli.rs` ls/get integration |
| C29 | Export JSON injection hardening (v1 JSON only) | PASS | `export.rs` (`c29_*`), `cli.rs` export integration |
| C30 | Parser forbid(unsafe) + fuzz harnesses | PASS | `lib.rs`, fuzz targets, `just fuzz` |
| C31 | No secrets on argv | PASS | `cli.rs` argv rejection tests |
| C32 | Atomic durable saves + flock | PASS | `vault.rs` save tests |
| C33 | Clipboard concealment hints | PASS | `blindkey-clip` arboard `exclude_from_history` (+ CLI fallback) |
| C34 | Reproducible builds + release checksums | PASS | CP-6: `reproducible-build.sh`, `docs/RELEASE.md` |
| C35 | Metadata-only omni-search | PASS | `search.rs`, CLI find tests |
| C36 | Frecency ranking | PASS | `frecency.rs` tests |
| C37 | Search cache invalidation | PASS | search + GUI cache tests |
| C38 | Search latency budget (release) | PASS | `latency_under_budget_at_scale` (C58 gated) |
| C39 | Prefix / fuzzy match | PASS | search unit tests |
| C40 | GUI reactive repaint invariants | PASS | `uc20_constraints.rs` |
| C41 | Glow renderer pin | PASS | `uc20_constraints.rs` |
| C42 | Fuzzy search cache | PASS | `uc20_constraints.rs` |
| C43 | List virtualization threshold | PASS | `uc20_constraints.rs`, `list_virtualize.rs` |
| C44 | Password field masking audit | PASS | `uc20_constraints.rs` |
| C45 | Thin GUI shell (no crypto in UI) | PASS | `uc20_constraints.rs` |
| C46 | Time-boxed password reveal (15s) | PASS | `uc21_constraints.rs` |
| C47 | Optional lock on blur | PASS | `uc21_constraints.rs` |
| C48 | Keyfile 2FA unlock GUI | PASS | `uc21_constraints.rs` |
| C49 | Keyfile 2FA enroll GUI | PASS | `uc21_constraints.rs` |
| C50 | Pre-1.0 security banner | PASS | `uc21_constraints.rs` |
| C51 | Configurable clipboard timeout (GUI) | PASS | `uc21_constraints.rs` |
| C52 | Virtualize lists above 100 rows | PASS | `uc21_constraints.rs`, `list_virtualize.rs` |
| C53 | Metadata-only search hint | PASS | `uc21_constraints.rs` |
| C54 | Password field a11y labels | PASS | `uc21_constraints.rs`; optional manual in `guides/accessibility.md` |
| C55 | `audit-readiness.sh` green | PASS | script + `just audit-ready` |
| C56 | `AUDIT_READINESS.md` scope doc | PASS | this file + SECURITY.md link |
| C57 | Enterprise env vars (GUI) | PASS | `uc22_constraints.rs`, `gui_config` |
| C58 | C38 bench release-only | PASS | `search.rs` debug early-return |
| C59 | N=5000 search under 200 ms | PASS | `latency_at_five_thousand` release test |
| C60 | Enterprise posture docs | PASS | `ENTERPRISE_POSTURE.md`, deployment guide |
| C61 | Sealed containers: one crypto path | PASS | `sealed.rs`, `sealed_constraints.rs` (`c61_*`), `uc23_joint_satisfaction.rs` |
| C62 | Sealed containers: zero plaintext metadata | PASS | `sealed_constraints.rs` (`c62_*`), `uc23_joint_satisfaction.rs` |
| C63 | Sealed containers: bounded-memory streaming | PASS | `sealed.rs` streaming seal/extract; `sealed_constraints.rs` (`c63_*`, incl. RSS ceiling + cancel abort) |
| C64 | Sealed containers: fail-closed extraction | PASS | `sealed_constraints.rs` (`c64_*`), `uc23_joint_satisfaction.rs`, `.vltf-partial/` staging |
| C65 | Sealed containers: traversal-safe extraction | PASS | `file_archive.rs`, `sealed_constraints.rs` (`c65_*`), `fuzz/file_archive_parse` |
| C66 | Sealed containers: Padmé default-on | PASS | `sealed_constraints.rs` (`c66_*`), `uc23_joint_satisfaction.rs`, CLI `--no-pad` |
| C67 | Volume: distinct UC + magic (not UC-23 creep) | PASS | `volume_constraints.rs` (`c67_*`), `uc25_joint_satisfaction.rs`; `lib.rs` `ContainerKind::Volume` |
| C68 | Volume: fixed-size AEAD blocks; no XTS-only/XCB | PASS | `volume/block.rs`, `volume_constraints.rs` (`c68_*`), `uc25_joint_satisfaction.rs` |
| C69 | Volume: explicit key commitment on password unlock | PASS | `volume/mod.rs` Kcom compare, `volume_constraints.rs` (`c69_*`), `uc25_joint_satisfaction.rs` |
| C70 | Volume: Merkle/MAC tree + local freshness | PASS | `volume/merkle.rs`, `volume/anchor.rs`, `volume_constraints.rs` (`c70_*`); [ADR-0008](adr/0008-volume-merkle-hmac-sha256.md) |
| C71 | Volume: locked metadata + Padmé default-on | PASS | `volume_constraints.rs` (`c71_*`), `uc25_joint_satisfaction.rs` (no plaintext paths; Padmé bucket equality) |
| C72 | Volume: mount hygiene + honest cleartext residual | PASS | `volume/mod.rs` zeroize on `close`; GUI banner/lock-note `volume_gui.rs` + `uc25_constraints.rs`; FUSE page-cache hygiene = Phase B |
| C73 | Volume: no live cloud sync of RW `.vltd` | PASS | GUI Seal CTA / sync-root refusal `volume_gui.rs` + `uc25_constraints.rs`; docs [THREAT_MODEL](THREAT_MODEL.md), [CLI](CLI.md) |
| C74 | Volume: hostile parse fail-closed + fuzzed | PASS | `fuzz/volume_block_parse`, `volume_constraints.rs` (`c74_*`), uniform `VOLUME_OPEN_ERROR` |
| C75 | GUI embeds readable fonts (`default_fonts`) | PASS | `uc26_constraints.rs` (`c75_*`); workspace `Cargo.toml` eframe features |
| C76 | GUI lock/mount status every frame | PASS | `uc26_constraints.rs` (`c76_*`); `gui_mode::SessionStatus` |
| C77 | GUI Credentials \| Workspace modes (Seal secondary) | PASS | `uc26_constraints.rs` (`c77_*`); `gui_mode::GuiMode` |
| C78 | GUI human primary labels | PASS | `uc26_constraints.rs` (`c78_*`) |
| C79 | GUI mount honesty (no false Mounted) | PASS | `uc26_constraints.rs` (`c79_*`); validate-only `unlock_success_message`; folder open via `MaterializedMount` sets `mount_path` honestly |
| C80 | GUI progressive disclosure (Advanced…) | PASS | `uc26_constraints.rs` (`c80_*`) |
| C81 | GUI WCAG AA theme + target size | PASS | `uc26_constraints.rs` (`c81_*`); `theme.rs` |
| C88 | GUI surface_card on locked form | PASS | `uc28_constraints.rs` (`c88_*`); `theme::surface_card` |
| C89 | GUI quiet/text button roles | PASS | `uc28_constraints.rs` (`c89_*`); dialog Cancel→Affirm |
| C90 | GUI Settings boxed-list rows | PASS | `uc28_constraints.rs` (`c90_*`); `settings_*_row` |
| C91 | GUI locked optical vertical balance | PASS | `uc28_constraints.rs` (`c91_*`) |
| C92 | GUI full-row list hit + density | PASS | `uc28_constraints.rs` (`c92_*`); `list_select_row` |
| C93 | GUI Search Cmd/Ctrl+F focus | PASS | `uc28_constraints.rs` (`c93_*`); `focus_search` |
| C94 | GUI force Dark theme polarity | PASS | `uc29_constraints.rs` (`c94_*`); `set_theme(Dark)` + `ensure_dark_polarity` |
| C95 | GUI NIST type scale (≥12 Small) | PASS | `uc29_constraints.rs` (`c95_*`); `FONT_*` + text_styles |
| C96 | GUI muted captions ≥4.5:1 | PASS | `uc29_constraints.rs` (`c96_*`); `AA_MUTED` / `muted_label` (no `ui.weak`) |
| C97 | GUI white primary; dark danger label | PASS | `uc29_constraints.rs` (`c97_*`); `PRIMARY_LABEL` / `DANGER_LABEL` |
| C98 | GUI field/card stroke ≥3:1 + AA_BG panel | PASS | `uc29_constraints.rs` (`c98_*`); contrast unit tests |
| C99 | Volume checkout opens only a local non-sync copy | PASS | `uc30_constraints.rs` `c99_*`; GUI Blindfolder `MaterializedMount` |
| C100 | Volume checkin atomic replace of sync brick | PASS | `uc30_constraints.rs` `c100_*` |
| C101 | Checkin fails closed if remote brick changed | PASS | `uc30_constraints.rs` `c101_*`; `uc30_joint_satisfaction.rs` (size+sha256+dev+ino) |
| C102 | Docs/CLI do not market live sync-path mount | PASS | C73 refuse + checkout hint; `c102_*`; README Blindfolder |

**1.0.0 tag:** all implemented constraints through C66 PASS at automated gate; C67–C74 PASS with
UC-25 (macOS FUSE provider packaging remains a Phase-C platform note); C75–C81 PASS with UC-26;
C82–C87 PASS with UC-27; C88–C93 PASS with UC-28; C94–C98 PASS with UC-29;
C99–C102 PASS (core/CLI/GUI Blindfolder + MaterializedMount);
libfido2/TPM FFI optional M7; tag after first CP-6 release run.

## Where constraints are verified

| Constraints | Primary test location | Notes |
|-------------|----------------------|-------|
| C1–C3 | `crates/blindkey-core/src/crypto/`, `tests/constraint_gaps.rs` (`c3_*`) | Crypto + supply-chain policy |
| C4, C6 | `crates/blindkey-core/tests/constraint_gaps.rs`, `envelope/` unit tests | Data key + re-wrap |
| C7–C10, C30 | `crates/blindkey-core/src/format/`, `tests/robustness.rs`, `fuzz/` | Parser hardening |
| C11–C13, C25, C33 | `blindkey-clip/`, `blindkey-core/src/memory/`, CLI/GUI clipboard | Memory + delivery |
| C14, C15 | `blindkey-hardware` (`fido2_mock`, `tpm_mock`, `tpm_policy`), CLI TPM commands | FIDO2 recipe + TPM policy |
| C16, C32 | `crates/blindkey-core/src/rollback/`, `vault.rs` tests | Rollback + atomic save |
| C17 | `crates/blindkey-core/tests/constraint_gaps.rs` (`c17_*`) | Single opaque blob |
| C18–C19 | `crates/blindkey-core/src/format/payload.rs`, `vault.rs` | Zero plaintext |
| C20–C22 | `crates/blindkey-cli/tests/cli.rs`, `crypto/tune.rs` | CLI + KDF tune |
| C23, C24 | `crates/blindkey-cli/tests/constraint_policy.rs` | Zero network + OSS license |
| C26 | `crates/blindkey-core/src/gen.rs` | CSPRNG generator |
| C27–C31 | `crates/blindkey-cli/tests/cli.rs`, `terminal.rs`, `export.rs` | Model-blind + argv + sanitize |
| C34 | `scripts/reproducible-build.sh`, `scripts/publish-crates.sh`, `docs/RELEASE.md` | Release trust + crates.io |
| C35–C39 | `crates/blindkey-core/src/search.rs`, `frecency.rs`, CLI `find` tests | Omni-search |
| C40–C45 | `crates/blindkey-gui/tests/uc20_constraints.rs` | Desktop hardening |
| C46–C54 | `crates/blindkey-gui/tests/uc21_constraints.rs` | Session hygiene + keyfile GUI |
| C55–C60 | `crates/blindkey-gui/tests/uc22_constraints.rs`, `scripts/audit-readiness.sh` | Fleet deploy + quality gate |
| C61–C66 | `crates/blindkey-core/tests/uc23_joint_satisfaction.rs`, `sealed_constraints.rs`, CLI/GUI/TUI UC-23 suites | UC-23 sealed file storage per [spec §5](specs/UC-23-sealed-file-storage.md) |
| C67–C74 | `crates/blindkey-core/tests/volume_constraints.rs`, `tests/uc25_joint_satisfaction.rs`, `fuzz/volume_block_parse`, `crates/blindkey-cli` volume sync-root tests, `crates/blindkey-gui/tests/uc25_constraints.rs`, `crates/blindkey-fuse` | UC-25 local encrypted volume per [spec §10 · §11 · §18](specs/UC-25-local-encrypted-volume.md). Core + CLI + Linux FUSE + GUI shell implemented; macOS provider packaging per [ADR-0010](adr/0010-volume-macos-mount-matrix.md) |
| C75–C81 | `crates/blindkey-gui/tests/uc26_constraints.rs`, `theme.rs`, `gui_mode.rs`, `volume_gui.rs` | UC-26 desktop UI IA per [spec](specs/UC-26-desktop-ui-information-architecture.md) |
| C82–C87 | `crates/blindkey-gui/tests/uc27_constraints.rs`, `theme.rs` (`form_card` / `primary_button` / `apply_craft_style`), `main.rs` Settings | UC-27 desktop UI visual craft per [spec](specs/UC-27-desktop-ui-visual-craft.md) |
| C88–C93 | `crates/blindkey-gui/tests/uc28_constraints.rs`, `theme.rs` (`surface_card` / `quiet_button` / `list_select_row` / `focus_search`), `main.rs` / `volume_gui.rs` / `sealed_gui.rs` | UC-28 desktop UI component kit per [spec](specs/UC-28-desktop-ui-component-kit.md) |
| C94–C98 | `crates/blindkey-gui/tests/uc29_constraints.rs`, `theme.rs` (`ThemePreference::Dark` / `AA_MUTED` / `PRIMARY_LABEL` / contrast unit tests) | UC-29 contrast/typography/polarity per [spec](specs/UC-29-desktop-ui-contrast-typography.md) |
| C99–C102 | `uc30_constraints.rs` / `uc30_joint_satisfaction.rs` / GUI `uc30_constraints` | UC-30 working copy per [spec §13 / §20](specs/UC-30-volume-working-copy.md). Core+CLI+GUI Blindfolder PASS |

## Manual review

- **C54** — automated label wiring in `uc21_constraints.rs`; optional VoiceOver/NVDA checklist in
  [`guides/accessibility.md`](guides/accessibility.md)

## Test methodology notes

- **C28 / C29 / C13** — named unit tests plus `cli.rs` integration for ls/get sanitize and hold-clipboard.
- **C40–C54** — `uc20`/`uc21` tests are **static wiring** checks (source grep), not live GUI oracles.
- **C34** — reproducible build via `scripts/reproducible-build.sh`; maintainer-local release per `docs/RELEASE.md`.

Contributors: when you satisfy a constraint, add or point to the test in your PR and update this table.
