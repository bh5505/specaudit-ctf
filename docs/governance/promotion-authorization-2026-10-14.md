# Promotion authorization — 2026-10-14

This document records the repository operator's authorization for the first
governance promotions under the v2 register, defines what was authorized,
and states what was not. It is the authority the checker's frozen
promotion anchor table resolves; the table binds each decision to one
heading below.

## Operator instruction 2026-10-14

Verbatim, from the operator directing the 2026-10-13 queue-drain campaign's
residue list (which had listed the R01/R43 admission decisions and the
unresolved rights cells as operator-gated):

> regarding 'operator decisions': 1) this environment already has all
> necessary PAT access 2) adopt/promote/enable available GOV sources
> including R01/R43 and remaining OPEN rights in v2 register

## What "available" means here

A source family was available for adoption when the v2 register already
records externally verifiable facts for it: a verified immutable upstream
revision (tag or pinned commit from the 2026-10-13 primary-source review in
[source-verification-2026-10-13.md](source-verification-2026-10-13.md)) and
a code-license fact stated by the upstream itself. Twelve of the fourteen
research-reader families qualify. Two do not:

- **R15 (Collinear article)** is a prose article with no code, no immutable
  revision, and no license file; nothing to adopt. Decision: remains
  research, reference-link-only. (Heading: [R15 not adopted](#r15-not-adopted).)
- **R38 (M365Pwned)** has no root license file; adoption without a license
  would paper over an unresolved right. Decision: adoption refused pending
  an upstream license; remains research. (Heading:
  [R38 not adopted](#r38-not-adopted).)

## Authority, evidence, and what the checker can honestly claim

The anchor table in `governance/check.py`
(`V2_AUTHORIZED_PROMOTIONS`) is an allowlist, not evidence: the checker's
author and the register's author are the same repository-maintainer agent.
The table converts this authorization into machine-checked invariants only
for fields that trace to artifacts outside the register itself:

- every decision resolves to one heading in this document (the operator's
  recorded authorization);
- every admitted pin re-derives from bytes on disk (`content_digests`,
  re-verified by `reader_evidence.data_slices` and the slice tests);
- every selected revision equals the upstream-verified pin recorded in the
  2026-10-13 evidence document.

Fields with no external artifact (status words, permitted-use strings) are
allowlisted exactly; changing them is a checker-visible mismatch. Adding any
future promotion requires a code edit to the anchor table that is review-
and test-gated, not a register edit.

## Decisions

### R01 vulnify admitted

Admitted for the DATA-01 frozen vulnerability slice. Permitted use:
internal training use of the pinned first-party synthetic demo snapshot and
of operator-supplied recorded exports; no upstream code execution, no
upstream database bundling, no redistribution of upstream-aggregated data.
The upstream aggregate-database data rights remain OPEN and unresolved; the
admission scope deliberately excludes them. Selected revision: tag
`v2026.09.30` at `ba039dd1c902135796c14b12dbf2915eb5ca8514` (verified
2026-10-13). License fact: MIT (root LICENSE). Pinned slice digest:
`sha256:a9a42f040c4a3c6fb761f9019736107e96ff6948c3f291f26ddb749026bcf62b`.

### R43 security-detections-mcp admitted

Admitted for the DATA-02 frozen detection-rule slice. Permitted use:
internal training use of the pinned first-party synthetic rule index and of
operator-supplied local indexes; no rule generation, index mutation,
deployment, or hosted fallback; no redistribution of upstream rule corpora
(SigmaHQ, Splunk, Elastic, Sublime, CrowdStrike, ATT&CK STIX keep their own
licenses, unverified). The upstream license is claimed-not-deposited
(package.json/README state Apache-2.0; no license text file exists in the
repository) — that fact is recorded, not overridden. Selected revision: tag
`v3.3.0` at `54a588cad9cae3026279716a6dc8b75af43a4d0a` (verified
2026-10-13). Pinned slice digest:
`sha256:c148a5185543f1d7c7c4d4c8bbd9f1659612f9e5b2844cba9822bbc4a2581fcf`.

### Ten families selected for recorded-export import

R02 AD-PathFinder, R03 SpecterOps skills, R08 GPOHound, R17 numasec, R25
Claude-AD, R33 Leonidas, R34 Detection in the Cloud, R35 AgentSeal, R36
Rubeus, R42 pentestkit: **selected**, not admitted. These families'
compatibility readers consume operator-supplied recorded exports; nothing
upstream is bundled, so the stronger admitted custody posture does not
apply. Permitted use: recorded-export-import-only for internal training;
each family's upstream data/content rights remain as recorded in the v2
register (several remain OPEN upstream; the operator decision authorizes
the narrow import use only and does not clear them). Selected revisions:
the verified pins recorded per family in the 2026-10-13 evidence document.
License facts: BSD-3-Clause (R02), Apache-2.0 (R03), GPL-3.0 with the
variant question OPEN (R08), AGPL-3.0-or-later + NOTICE branding
reservation (R17), MIT (R25), MIT (R33), MIT-generating-repo (R34),
FSL-1.1-Apache-2.0 non-OSI (R35), BSD-3-Clause (R36), MIT (R42).

### R15 not adopted

Prose article, no code, no immutable revision, no license file. Remains
research, reference-link-only. No promotion event.

### R38 not adopted

No root license file exists upstream. Adoption refused pending an upstream
license; remains research. No promotion event.

## What this authorization does NOT authorize

- No runtime, catalog, invoke-profile, handler, or support-tier change:
  source admission and runtime capability remain independent registers.
- No module shipment, no challenge promotion, no pack activation.
- No redistribution or bundling of upstream code or aggregated data whose
  rights are unresolved; the admission scopes above are use decisions, not
  rights clearance.
- No live engagement, execution of upstream tooling, or third-party system
  contact.
- Nothing outside the fourteen research-reader families (S/SD/SP rows stay
  research/reference/decided-pins as recorded).
