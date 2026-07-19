# EU Cyber Resilience Act (CRA) — current status

The CRA is EU Regulation 2024/2847, phasing in through 2026–2027, and it's a different kind of
law from [export/sanctions compliance](EXPORT_COMPLIANCE.md): it doesn't restrict who can get the
code, it imposes ongoing security obligations (vulnerability handling, incident reporting, CE
marking) on **manufacturers** of "products with digital elements." The question for any OSS
project is whether the maintainer counts as a "manufacturer" under the Act.

## Where Blindkey stands today

**Out of scope, on current facts** — free and open-source software that is not monetized by its
developers is generally exempt from CRA manufacturer obligations, and individual maintainers
specifically cannot hold the Act's alternative "open-source software steward" status either (that
category requires a legal person — a company, foundation, or association — not a natural person).
Sources: the [European Commission's own CRA open-source page](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source),
[GitHub's developer-facing explainer](https://github.blog/open-source/maintainers/what-the-eus-new-software-legislation-means-for-developers/),
and the [Open Regulatory Compliance Working Group's CRA guide](https://orcwg.org/cra/).

Concretely: Blindkey is (a) maintained by individuals, not a legal entity, and (b) not sold or
monetized — MIT/Apache-2.0, no paid tier, no commercial distribution. Both conditions currently
point the same direction: out of scope.

## The trigger to re-check — before acting, not after

**"Not monetized" is the load-bearing fact, and it's the one most likely to change.** If Blindkey
ever gains a paid tier, a commercial support contract, an enterprise license, or is sold /
transferred as part of a commercial deal, the CRA analysis has to be redone *before* that change,
not discovered afterward — the reporting obligations (e.g., actively-exploited-vulnerability
reporting to ENISA/CSIRTs, phasing in from **11 September 2026** for in-scope manufacturers) carry
real deadlines once triggered. This is not a remote scenario for a project positioned toward
[enterprise adoption](ENTERPRISE_POSTURE.md) — it's the specific condition to watch for.

**Practical trigger checklist — re-run this analysis if any of these become true:**

- Blindkey (or a fork/derivative) is sold for money in any form, including a one-time or
  subscription license.
- A maintainer or a company forms a legal entity that publishes, supports, or is commercially
  associated with Blindkey.
- Paid support, custom development, or an enterprise SLA is offered around Blindkey.

## Not legal advice

Like [EXPORT_COMPLIANCE.md](EXPORT_COMPLIANCE.md), this is an engineering-level summary of public
guidance from the sources cited above, current as of this writing — not a legal opinion. The CRA
is mid-rollout and its secondary guidance (harmonized standards, Commission implementing acts) is
still being published; if a monetization event is ever on the table, this document is the signal
to get real counsel involved before, not after.
