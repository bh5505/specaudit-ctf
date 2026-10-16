# Source and currentness verification — 2026-10-13

Owner: specaudit-ctf maintainers. Method and evidence record for the
governance register v2 currentness reviews executed 2026-10-13. This document
records attributed human review and machine-re derivable checks. It is a
review record, not an admission, promotion, custody proof, or support claim:
every register row it cites keeps its existing status.

## Verification method

All external facts below were collected on 2026-10-13 through read-only
primary-source pulls (canonical repository pages, license files, tag and
commit listings, and publisher article pages) by the maintainer research
lane. No upstream repository was cloned, installed, executed, forked, or
contacted beyond read-only retrieval of its public pages and raw files.
Where an upstream exposes no tag, the pinned revision is a default-branch
commit and is labeled as such; where a license file is absent, the row
records the absence rather than inferring permission. A recorded revision or
license closes a register evidence cell only; it selects nothing, admits
nothing, and promotes nothing.

## Per-source primary-source review

### R01 vulnify

- Custodian: GitHub user `mez-0` (Mez0), https://github.com/mez-0/vulnify .
- Verified revision: tag `v2026.09.30` at commit
  `ba039dd1c902135796c14b12dbf2915eb5ca8514` (2026-09-30; equals the
  repository head at review time). The previously suggested tag
  `v2026.07.25.1` at `2b937bbd891b9ff1ba11e1c6b9c6ab674d3729a1` remains a
  valid older pin; the newer tag supersedes it as the freshest verified
  snapshot.
- Code license: root `LICENSE`, MIT (Copyright (c) 2026 Brandon McGrath).
- Data/content rights: `docs/DATASOURCES.md` states the MIT licence covers
  the code and not the upstream datasets; the built database aggregates
  CVE (CVE Program terms), NVD (public domain), CISA KEV (public domain),
  EPSS (FIRST attribution terms), OSV (no license stated - OPEN), Nuclei
  templates (MIT), Exploit-DB CSV, and Metasploit (BSD-3-Clause).
  Aggregate-database redistribution rights remain OPEN.
- Upstream interface: normalized SQLite database with a shipped
  `schema.sql`, a `vulnify-gather` CLI, and a FastMCP stdio server; docs at
  `docs/SCHEMA.md`, `docs/PIPELINE.md`, `docs/MCP.md`. The repository
  reader is an independent JSON/JSONL/YAML compatibility projection, not
  that interface; conversion and loss mapping remain OPEN cells.
- Upstream activity observed: 2026-09-30 (head commit and push).

### R02 AD-PathFinder

- Custodian: GitHub organization `NetSPI`, https://github.com/NetSPI/AD-PathFinder .
- Verified revision: tag `v1.2.0` at commit
  `110ce06aeb182dff11b51abd3047b0157f290a64` (2026-07-22). Default branch
  is ahead of the tag (head `5d20a1b43015f4e155c8c3a8ceb57639c38f0689`,
  2026-08-09).
- Code license: root `LICENSE`, BSD-3-Clause (Copyright (c) 2025, NetSPI).
- Data/content rights: no NOTICE; `sample_data/` and `sample_reports/`
  carry no stated dataset license - OPEN.
- Upstream interface: BloodHound CE / SharpHound zip collections plus
  OpenGraph plugin zips, Neo4j queries, HTML/SVG/JSON reports. The
  repository reader is an independent JSON/YAML export projection;
  field-level correspondence remains OPEN.
- Upstream activity observed: 2026-08-09 (head commit and push).

### R03 SpecterOps skills

- Custodian: GitHub organization `SpecterOps`, https://github.com/SpecterOps/skills .
- Verified revision: no tags exist; default-branch commit
  `e655f93ab694c446b76672efe6e71e62aac0b7b8` (2026-09-03) is the pinned
  revision.
- Code license: root `LICENSE`, Apache-2.0.
- Data/content rights: no NOTICE; skill and plugin markdown/manifest
  content is under the repository Apache-2.0; referenced third-party MCP
  servers are separately licensed - per-skill references OPEN.
- Upstream interface: Claude Code / Codex plugin manifests
  (`plugins/<plugin>/skills/<skill>/SKILL.md`, `.claude-plugin/plugin.json`,
  `.codex-plugin/plugin.json`), auto-generated catalogs. The repository
  reader is an independent JSON/YAML methodology-catalog projection.
- Upstream activity observed: head commit 2026-09-03 (repo pushes through
  2026-09-23).

### R08 GPOHound

- Custodian: GitHub organization `cogiceo`, https://github.com/cogiceo/GPOHound .
- Verified revision: no tags exist; default-branch commit
  `096d0effbee28653c4705a9ea973266b24d6e2a5` (2026-10-02) is the pinned
  revision.
- Code license: root `LICENSE` is GNU GPL v3 text (GitHub SPDX `GPL-3.0`);
  only-vs-or-later is not stated in the file - OPEN at the SPDX-mapping
  level.
- Data/content rights: no NOTICE; the bundled `example.zip` carries no
  stated license - OPEN.
- Upstream interface: SYSVOL/LDAP collection producing structured JSON or
  tree output plus BloodHound Neo4j enrichment. The repository reader is an
  independent JSON/YAML GPO-policy projection; applicability limits are
  recorded as reader limitations.
- Upstream activity observed: 2026-10-02 (head commit and push).

### R15 Collinear cybersecurity simulated worlds

- Custodian: Collinear AI (blog publisher), article
  https://blog.collinear.ai/p/cybersecurity-simulated-worlds-agi .
- Verified revision: article published 2026-08-25 (author Nazneen Rajani);
  no separate last-updated date is displayed.
- Code license: not applicable (prose article).
- Data/content rights: no license or terms beyond the site copyright
  notice - reference-link-only; OPEN.
- Upstream interface: none (prose); the repository scenario projection is
  an independent compatibility format with no upstream schema to
  correspond to.
- Upstream activity observed: 2026-08-25 (publication).

### R17 numasec

- Custodian: GitHub user `FrancescoStabile` (Francesco Stabile),
  https://github.com/FrancescoStabile/numasec .
- Verified revision: tag `v1.2.1` at commit
  `1237a2f3515aebbd5260383c7088aa0ea806b600` (2026-05-08; equals the
  repository head at review time).
- Code license: root `LICENSE` GNU AGPL v3; root `NOTICE` states
  AGPL-3.0-or-later and reserves the numasec name/logo/branding.
- Data/content rights: the NOTICE branding reservation is recorded;
  exported finding-bundle terms are not separately stated - OPEN.
- Upstream interface: npm CLI/TUI with provider config and exported
  finding bundles; no formal upstream schema document is cited in the
  README. The repository reader is an independent JSON/JSONL lifecycle
  projection; lifecycle-state correspondence remains OPEN.
- Upstream activity observed: 2026-05-08 (head commit and push).

### R25 Claude-AD

- Custodian: GitHub user `ADScanPro` (ADscan; adscanpro.com),
  https://github.com/ADScanPro/Claude-AD .
- Verified revision: no tags exist; default-branch commit
  `73efec51207f6f740cb398e1c490e5edd60c1113` (2026-08-24) is the pinned
  revision.
- Code license: root `LICENSE`, MIT (Copyright (c) 2026 ADscan).
- Data/content rights: no NOTICE; methodology markdown credits prior art
  (The Hacker Recipes, BloodHound CE) - companion product licensing is
  explicitly distinct; curated-content rights OPEN.
- Upstream interface: Claude Code plugin of skills/agents/commands in
  Markdown plus `.claude-plugin/plugin.json`. The repository reader is an
  independent JSON/YAML methodology projection.
- Upstream activity observed: 2026-08-24 (head commit).

### R33 Leonidas

- Custodian: GitHub organization `ReversecLabs` (Reversec Labs; repository
  lineage F-Secure/WithSecure LABS),
  https://github.com/ReversecLabs/leonidas .
- Verified revision: no tags exist; default-branch commit
  `77ec6bd17e65a111b30fc490476f28cb29308a0f` (2024-11-22) is the pinned
  revision.
- Code license: root `LICENSE`, MIT (Copyright (c) 2020 F-Secure LABS).
- Data/content rights: no NOTICE; rights over generated Sigma rules and
  docs are not stated - OPEN.
- Upstream interface: declarative YAML technique definitions
  (`template-definition.yml`: name, author, description, platform,
  category, mitre_ids, permissions, input_arguments, executors,
  detection). The repository reader is an independent JSON/YAML corpus
  projection over that declarative shape; inert-import guarantees are
  reader-side.
- Upstream activity observed: 2024-11-22 head commit (repository pushes
  through 2024-11-28) - dormancy recorded as a fact, not a retirement.

### R34 Detection in the Cloud

- Custodian: the site is generated documentation published by the
  `ReversecLabs` organization from the Leonidas repository;
  https://detectioninthe.cloud and
  https://github.com/ReversecLabs/leonidas . The former WithSecureLabs
  repository URL redirects to ReversecLabs.
- Verified revision: the site displays no dates or versions; the pinned
  revision is the generating repository commit
  `77ec6bd17e65a111b30fc490476f28cb29308a0f` (2024-11-22) plus the
  reviewed site snapshot of 2026-10-13.
- Code license: generating repository MIT; site pages display no license
  notice.
- Data/content rights: no NOTICE or corpus terms found - OPEN.
- Upstream interface: per-case playbook/rule documentation pages generated
  from the Leonidas YAML definitions. The repository reader accepts local
  playbook directories; page/definition revision binding is an operator
  gate recorded as a reader limitation.
- Upstream activity observed: 2024-11-22 (generating repository).

### R35 AgentSeal

- Custodian: GitHub organization `getagentseal`,
  https://github.com/getagentseal/agentseal .
- Verified revision: tag `v0.10.0` at commit
  `7c2a22891465ac4c00bd45f4a50c742aa4651275` (2026-06-11; equals the
  repository head at review time).
- Code license: root `LICENSE` is the Functional Source License 1.1
  (FSL-1.1-Apache-2.0; change-date converts to Apache-2.0) - a
  source-available license with a competing-use restriction, not OSI.
- Data/content rights: no NOTICE; `PROBES.md` probe catalog terms follow
  the repository license - redistribution review OPEN.
- Upstream interface: `guard`/`scan-mcp`/`shield` CLI with SARIF/JSON
  output. The repository reader is an independent JSON/YAML static-fixture
  projection; fixture-schema correspondence remains OPEN.
- Upstream activity observed: 2026-06-11 (head commit and push).

### R36 Rubeus

- Custodian: GitHub organization `GhostPack` (primary author Will
  Schroeder), https://github.com/GhostPack/Rubeus .
- Verified revision: the only tag is `1.6.4` at
  `e93119a371606fae56fd63f0d285f3773287394d` (2021; final .NET 3.5
  release); the default-branch head is
  `74215f68ea70bd6a66c008da91bf5fe21d20b154` (2025-11-14, in-code version
  v2.3.3 never tagged). Both facts are recorded; the register records the
  head commit as the verified revision and the tag as the only tagged
  release.
- Code license: root `LICENSE`, BSD 3-Clause (Copyright (c) 2018, Will
  Schroeder; GitHub SPDX NOASSERTION from non-standard text placement).
- Data/content rights: README flags mixed inbound licenses (Kekeo-derived
  code CC BY-NC 4.0 share-alike family, MakeMeEnterpriseAdmin GPLv3);
  example/output material rights OPEN.
- Upstream interface: C# CLI producing `.kirbi` base64 ticket blobs,
  hashcat-format hashes, and file output. The repository reader is an
  independent JSON/JSONL deweaponized-telemetry projection; redaction
  provenance is a reader-side contract.
- Upstream activity observed: 2025-11-14 (head commit).

### R38 M365Pwned

- Custodian: GitHub user `OtterHacker`,
  https://github.com/OtterHacker/M365Pwned .
- Verified revision: no tags exist; default-branch commit
  `15e68ab52341d7e5d9eaac3551a37b5c2d729cee` (2026-03-04) is the pinned
  revision.
- Code license: no root LICENSE file exists; the README states educational
  and authorized-testing intent only - no-license-found recorded, OPEN.
- Data/content rights: no NOTICE or dataset terms - OPEN.
- Upstream interface: two PowerShell WinForms GUI tools driving Microsoft
  Graph with application tokens; CSV/HTML output. The repository reader is
  an independent JSON/YAML consent-case projection; permission semantics
  remain pinned to API-owner documentation (S11), not this source.
- Upstream activity observed: 2026-03-04 (head commit).

### R42 pentestkit

- Custodian: GitHub user `lordx64`,
  https://github.com/lordx64/pentestkit .
- Verified revision: no tags exist; default-branch commit
  `ac492b2a8613c85acee4d7b6cdec1a7abd14ce7f` (2026-07-31) is the pinned
  revision.
- Code license: root `LICENSE`, MIT (Copyright (c) 2026 lordx64).
- Data/content rights: no NOTICE; third-party references (benchmarks,
  SDKs, images) carry their own terms - OPEN.
- Upstream interface: YAML engagement definitions plus per-run output
  directories (`report.md`, `context.json`, `run_summary.md`, evidence
  files). The repository reader is an independent JSON/JSONL/YAML ledger
  projection; imported fields stay distinct from the repository's own
  attempt records.
- Upstream activity observed: 2026-07-31 (head commit).

### R43 Security-Detections-MCP

- Custodian: GitHub user `MHaggis` (Michael Haag),
  https://github.com/MHaggis/Security-Detections-MCP .
- Verified revision: tag `v3.3.0` at commit
  `54a588cad9cae3026279716a6dc8b75af43a4d0a` (2026-06-16; equals the
  repository head at review time).
- Code license: claimed Apache-2.0 (package.json and README state it) but
  no license text file exists in the repository - claimed-not-deposited
  recorded, OPEN.
- Data/content rights: no NOTICE; aggregated third-party rule corpora
  (SigmaHQ, Splunk, Elastic, Sublime, CrowdStrike, ATT&CK STIX) keep their
  own licenses, unverified here - OPEN per corpus.
- Upstream interface: MCP server exposing rules in per-source native
  formats (Sigma YAML, Splunk ESCU, Elastic, KQL, Sublime, CQL) plus
  ATT&CK Navigator layers. The repository reader is an independent
  JSON/YAML/YML detection-rule index projection; per-corpus schema
  correspondence remains OPEN.
- Upstream activity observed: 2026-06-16 (head commit and push).

## Register-row review classes

### Runtime reconciliation review

Each of the 227 governed runtime rows was generated from the authoritative
`extension.invoke_profiles.INVOKE_PROFILES` snapshot and re-derived by the
governance checker at validation time: tier, tool version, timeouts, output
and step caps, spend, approval requirement, and side-effect classes are
reconciled against the live profiles on every check run. The 52 PR97 reader
rows are additionally byte-equivalent to the frozen v1 register records and
re-anchored against the independent literal PR97 constants. The
implementation revision recorded for non-PR97 rows is the governed-as-of
repository baseline `dc43b85`; per-capability introduction revisions are
not individually verified and remain a stated limitation.

### Module architecture review

The 30 module rows were seeded from the program architecture tables in
`PROGRAM.md` and the curriculum blueprints in `CURRICULUM.md` on
2026-10-13. Status words follow the four repository statuses; no module is
recorded shipped, and no module row changes any catalog, challenge, or
runtime surface.

### Spine and supplemental source review

The authoritative source-spine entries (learning/audit/control-assessment,
identity/cloud/application/data/supply-chain,
vulnerability/detection/response/threat-informed, AI/agents/MCP, and
telecom families) and the S01-S12 supplemental families were seeded from
`PROGRAM.md` with reference-link-only permitted use. The nine decided E1
pilot sources carry the pins and rights recorded in
`docs/source-decisions-2026-10-03.md`; recording a pin closes an evidence
cell without selecting or admitting the source.

## Drift-trigger check record

Every register currentness review on 2026-10-13 recorded one trigger check
per listed trigger. Source rows use attributed primary-source review
evidence from the per-source sections above. Runtime rows use the
checker-re derived inventory reconciliation described under runtime
reconciliation review. Module rows use the architecture review above. These
are attributed review records and machine-re-derivable checks respectively;
none of them authenticates an issuer, proves an upstream unchanged, or
converts a review into an admission. The recurring queue and cadence live in
the register's currentness queue section.
