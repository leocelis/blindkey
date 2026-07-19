# Export & sanctions compliance notice

This distribution includes cryptographic software. The country in which you currently reside
may have restrictions on the import, possession, use, and/or re-export to another country, of
encryption software. **Before using any encryption software, please check your country's laws,
regulations, and policies concerning the import, possession, or use of encryption software, to
see if this is permitted.** This is a widely-used notice; see, for example, the
[EFF's explainer on publicly available encryption source code](https://www.eff.org/deeplinks/2019/08/us-export-controls-and-published-encryption-source-code-explained).

## US Export Administration Regulations (EAR)

Blindkey's cryptographic code uses only standard, published algorithms — Argon2id (KDF),
XChaCha20-Poly1305 (AEAD/STREAM), HKDF, HMAC-SHA-256 — via audited third-party libraries, never a
custom or novel primitive (constraint C3, [`blindkey_intent.yaml`](../blindkey_intent.yaml)). The
source is published on GitHub without restriction on further distribution.

Under the US Export Administration Regulations (EAR), publicly available encryption source code
of this kind is treated as **not subject to the EAR** once the applicable notification has been
made — see [15 CFR 740.13(e)](https://www.law.cornell.edu/cfr/text/15/740.13) (License Exception
TSU) and [15 CFR 742.15(b)](https://www.law.cornell.edu/cfr/text/15/742.15) (publicly available
encryption source code), and BIS's own summary at
[bis.gov — encryption items not subject to the EAR](https://www.bis.gov/learn-support/encryption-controls/encryption-items-not-subject-to-ear).
For source code implementing only standard, published cryptography (not "non-standard
cryptography" as EAR defines it), recent guidance has simplified this further — see the
[Linux Foundation's plain-language explainer](https://www.linuxfoundation.org/resources/publications/understanding-us-export-controls-with-open-source-projects).

**What this means in practice for Blindkey specifically:**

- The maintainers are not US persons and Blindkey is not a US-origin commercial product; the
  regulations primarily govern exports *from* the United States, and enforcement history against
  individual maintainers of freely published open-source cryptography is effectively nonexistent
  — the "publicly available" carve-out exists precisely because source code like this is
  routinely published worldwide (OpenSSL, libsodium, `age`, `rustls`, and thousands of others
  operate under the same exemption without incident).
- Out of caution, and because it costs nothing, the optional courtesy notification some projects
  send to the relevant US agencies is documented below. **The maintainers have not sent this
  notification as of this writing** — nothing in this document should be read as a claim that it
  has been sent.

### Optional notification (not yet sent)

Projects that want the extra formality can email the repository URL to both:

- `crypt@bis.doc.gov` (US Department of Commerce, Bureau of Industry and Security)
- `enc@nsa.gov` (NSA ENC Encryption Request Coordinator)

Sample text:

> Subject: Notification of publicly available encryption source code
>
> Per 15 CFR 742.15(b), this is notice that the following publicly available encryption source
> code is published without restriction at: `https://github.com/leocelis/blindkey`

This is **not a substitute for legal advice.** If export compliance materially matters for your
use of Blindkey (for example, redistributing a modified or bundled commercial product), consult
counsel — this document is an engineering-level summary of publicly available guidance, not a
legal opinion.

## US sanctions (OFAC) — a separate regime from export control

Export control (above) and sanctions are administered by different US agencies and are easy to
conflate: EAR/BIS (Commerce) governs *what* may cross borders; OFAC (Treasury) governs *who* you
may transact with, regardless of what's being transferred. Both are relevant to a public
repository.

Published, publicly available source code is generally treated by OFAC as exempt
"informational materials" — see [OFAC's own FAQ on sanctions exceptions](https://ofac.treasury.gov/faqs/4)
and the [Linux Foundation's guidance on OFAC sanctions and open source](https://www.linuxfoundation.org/blog/navigating-global-regulations-and-open-source-us-ofac-sanctions).
**This exemption is narrower than it sounds and the guidance is not fully settled** — it
generally covers *one-way receipt* of existing published code. It does **not** clearly cover
*commissioning* new code or modifications from a Specially Designated National (SDN) or a
comprehensively sanctioned jurisdiction, and it does not clearly cover **two-way technical
back-and-forth** — the ordinary code-review conversation that happens on every pull request. This
is not a hypothetical: in October 2024 the Linux kernel project removed several Russia-affiliated
maintainers after sanctions concerns, and the Linux Foundation published its OFAC guidance
partly in response.

**What this means in practice for Blindkey:** the project accepts external contributions (see
[CONTRIBUTING.md](../CONTRIBUTING.md) and the [DCO](../DCO)). If a pull request is submitted by
an account that is, or that a maintainer has reason to believe is, on the
[OFAC SDN list](https://sanctionssearch.ofac.treas.gov/) or operating from a comprehensively
sanctioned jurisdiction, the maintainers will not engage in two-way technical review of that
contribution (discussing, requesting changes to, or merging it) until it's confirmed the
transaction is exempt or licensed. This is the same posture the Linux Foundation now recommends
project-wide; it is not a statement about any contributor to date — none has raised this concern.

## This is not "acceptable use" language

Nothing above restricts *who* may use Blindkey or *for what purpose* — the MIT and Apache-2.0
licenses deliberately grant unrestricted use (Open Source Definition §6, no discrimination
against fields of endeavor). This document only addresses import/export regulation of the
cryptography itself, which is a separate legal question from the software license.
