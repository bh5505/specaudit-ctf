# W1a source evidence correction and inventory — 2026-10-18 (U-GOV.a)

Scope: bounded campaign unit U-GOV.a. Fixes the current evidence pointers
and publishes a source-derived inventory. No new admission, no new
authority, no runtime/profile change, no W2 work.

Canonical sources: [register.v2.yaml](../../governance/register.v2.yaml),
[check.py](../../governance/check.py),
[promotion authorization](promotion-authorization-2026-10-14.md),
[source verification](source-verification-2026-10-13.md),
[test_arm_batch7.py](../../tests/test_arm_batch7.py),
[test_arm_batch8.py](../../tests/test_arm_batch8.py).
A missing recorded fact below stays `OPEN`; nothing is inferred.

## 1. Correction record (explicit, minimal)

The 2026-10-14 source-event records cited
`tests/test_synthetic_readers.py` as both `regression_case` and
`exercised_path` for the ten selected families. That file is absent from the verified public baseline and current tree:

- `ls tests/test_synthetic_readers.py` → no such file (verified 2026-10-18).
- The frozen anchor table in `governance/check.py`
  (`V2_AUTHORIZED_PROMOTIONS`) froze the same nonexistent string and
  `validate_register_v2` only string-compared it, so the missing file
  passed silently.

Preserved history: `decided_on: 2026-10-14`,
`reviewer: repository-operator`,
`implementation_revision: a8f595d8b9c9a03ea76b49f32b071b732cc85538`,
subject/contract digests, pins, permitted uses, and the dated authorization
document are unchanged. This document does not rewrite them.

Correction mechanism (smallest compatible): keep the dated decision intact
and correct only the two citation fields on the ten selected events plus
the frozen anchor table, with this dated correction record. The old
filename is retained here as the corrected citation
`tests/test_synthetic_readers.py` (missing in the verified public baseline) rather than
being silently rewritten as if the new files ran on 2026-10-14.

Corrected mapping (frozen in `V2_SELECTED_TEST_PATH`, mirrored in each
event's both fields):

| Source | Corrected file (both fields) | Source-specific test class |
|---|---|---|
| R02 AD-PathFinder | `tests/test_arm_batch8.py` | `TestR02AdPathfinder` |
| R08 GPOHound | `tests/test_arm_batch8.py` | `TestR08Gpohound` |
| R17 numasec | `tests/test_arm_batch8.py` | `TestR17Numasec` |
| R25 Claude-AD | `tests/test_arm_batch8.py` | `TestR25ClaudeAd` |
| R36 Rubeus | `tests/test_arm_batch8.py` | `TestR36Rubeus` |
| R03 SpecterOps skills | `tests/test_arm_batch7.py` | `TestR03SpecteropsSkills` |
| R33 Leonidas | `tests/test_arm_batch7.py` | `TestR33Leonidas` |
| R34 Detection in the Cloud | `tests/test_arm_batch7.py` | `TestR34DetectionInTheCloud` |
| R35 AgentSeal | `tests/test_arm_batch7.py` | `TestR35AgentSeal` |
| R42 pentestkit | `tests/test_arm_batch7.py` | `TestR42Pentestkit` |

R01/R43 admitted-slice regressions are unchanged:
R01 `tests/test_vulnify_lookup.py`, R43 `tests/test_reader_evidence.py`.
Related batch classes (`TestR01Vulnify`, `TestR43SecurityDetectionsMcp` in
`test_arm_batch7.py`) are additional coverage, not the admission evidence.

## 2. Newly verified vs historically declared

- Historically declared 2026-10-14: operator authorized 2 admitted
  (R01/R43) + 10 selected (above) + 2 refusals (R15/R38); pins and terms
  per [authorization](promotion-authorization-2026-10-14.md).
- Newly verified 2026-10-18 (this unit): each corrected file exists in
  this checkout; `validate_register_v2` now requires both event fields to
  resolve to bounded repo-contained real `tests/*.py` files (absolute,
  traversal, symlink-escape, directory, and missing paths fail with
  `invalid-regression-ref` / `invalid-exercised-path-ref`); the twelve
  events still bind their rows (digests unchanged) and the anchor table
  still gates every promotion. File existence is citation resolvability
  only — it does not prove the test ran, covered the source, or executed
  on 2026-10-14.
- No new admission or authority is described or claimed.

## 3. Reader inventory: 14 readers / 38 data actions (source-derived)

All 14 PR97 arms stay `research` tier at runtime; source selection does
not promote any action. Runtime reconciliation authority remains
`extension.invoke_profiles.INVOKE_PROFILES`.

| Arm (source) | Data actions (38 total, `list_tools` excluded) | Regression file |
|---|---|---|
| ad-pathfinder (R02) | `path`, `list_paths`, `list_datasources` | `tests/test_arm_batch8.py` |
| gpohound (R08) | `policy`, `list_policies`, `list_links` | `tests/test_arm_batch8.py` |
| claude-ad (R25) | `technique`, `list_techniques`, `list_prerequisites` | `tests/test_arm_batch8.py` |
| numasec (R17) | `finding`, `list_findings`, `list_transitions` | `tests/test_arm_batch8.py` |
| rubeus (R36) | `telemetry`, `list_telemetry`, `list_indicators` | `tests/test_arm_batch8.py` |
| m365pwned (R38) | `case_study`, `list_case_studies`, `list_permissions` | `tests/test_arm_batch8.py` |
| specterops-skills (R03) | `skill`, `list_skills` | `tests/test_arm_batch7.py` |
| leonidas (R33) | `technique`, `list_techniques` | `tests/test_arm_batch7.py` |
| detection-in-the-cloud (R34) | `playbook`, `list_playbooks`, `list_rules` | `tests/test_arm_batch7.py` |
| agentseal (R35) | `analyze`, `list_scenarios` | `tests/test_arm_batch7.py` |
| pentestkit (R42) | `result`, `list_results`, `summary` | `tests/test_arm_batch7.py` |
| vulnify (R01) | `lookup`, `list_vulns` | `tests/test_vulnify_lookup.py` (admitted slice; `TestR01Vulnify` also in batch7) |
| security-detections-mcp (R43) | `list_rules`, `search_rules`, `get_rule` | `tests/test_reader_evidence.py` (admitted slice; `TestR43SecurityDetectionsMcp` also in batch7) |
| collinear (R15) | `scenario`, `list_scenarios`, `verify` | `tests/test_arm_batch7.py` (`TestR15Collinear`; source refused, stays research) |

Counts: 14 readers, 14 `list_tools` + 38 data actions = 52 PR97 detailed
records; all 52 runtime rows are `research` tier (52/52), reconciled live
against `INVOKE_PROFILES` on every check.

## 4. Candidate dispositions: 42 R-register rows (complete, no sampling)

Totals: 2 admitted + 10 selected + 30 research = 42. Among research:
2 explicit refusals (R15/R38) + 28 still-research/link-only/`OPEN` = 30.
Every row: owner `specaudit-ctf-maintainers`; `replacement: null`;
currentness `2026-10-13 → 2027-01-11` (source cadence 90d);
evidence `docs/governance/source-verification-2026-10-13.md` per-row
anchor (or spine/supplemental anchor for unreviewed rows); next scheduled recurring review
`2027-01-11` (operation remains OPEN — see §6).
`retirement` is not a recorded register field; `replacement` is null for
all 42 rows below. Admission gates are separate from that scheduled review:
R01/R43 stay limited to their admitted synthetic slices; selected sources need
applicable action-level admission evidence before runtime promotion. R15/R38
retain refusals pending an authorized, evidence-backed rights decision. The
other 28 candidates still need verified revisions, code/data-rights review,
schema correspondence and bounded case/regression evidence; their research
proposals in `PROGRAM.md` do not satisfy those gates.

| ID | Name | Status | Pin (verified_revision / selected_revision) | Code license | Data rights (short; full text in register) |
|---|---|---|---|---|---|
| R01 | vulnify | admitted | tag `v2026.09.30` at `ba039dd1c902135796c14b12dbf2915eb5ca8514` | MIT (root LICENSE) | Code-only; aggregate DB redistribution OPEN; admitted DATA-01 slice only |
| R02 | AD-PathFinder | selected | tag `v1.2.0` at `110ce06aeb182dff11b51abd3047b0157f290a64` | BSD-3-Clause | sample_data/reports no license OPEN; selected import only |
| R03 | SpecterOps skills | selected | commit `e655f93ab694c446b76672efe6e71e62aac0b7b8` (no tags) | Apache-2.0 | Skill content Apache-2.0; third-party MCP refs OPEN |
| R04 | Awesome LLMs for Vulnerability Detection | research | OPEN (no verified revision) | OPEN | OPEN; reference-link-only |
| R05 | DFIR Dominican CTFs and Labs | research | OPEN | OPEN | OPEN; reference-link-only |
| R06 | NetDraw | research | OPEN | OPEN | OPEN; reference-link-only |
| R07 | AgentHound | research | OPEN | OPEN | OPEN; reference-link-only |
| R08 | GPOHound | selected | commit `096d0effbee28653c4705a9ea973266b24d6e2a5` (no tags) | GPL-3.0 (only-vs-or-later OPEN) | example.zip no license OPEN; selected import only |
| R09 | Open-Source Threat Intel Feeds | research | OPEN | OPEN | OPEN; reference-link-only |
| R11 | CyberStrike | research | OPEN | OPEN | OPEN; reference-link-only |
| R12 | AppSecSanta AI pentesting agents survey | research | OPEN | OPEN | OPEN; reference-link-only |
| R13 | pentest-harness | research | OPEN | OPEN | OPEN; reference-link-only |
| R14 | TrustedSec SpooNMAP update | research | OPEN | OPEN | OPEN; reference-link-only |
| R15 | Collinear simulated worlds | research (refused) | article 2026-08-25, no immutable revision | not-applicable (prose) | Site copyright only, no reuse terms OPEN; not adopted 2026-10-14 |
| R16 | Auto-research-red-teaming / AHA | research | OPEN | OPEN | OPEN; reference-link-only |
| R17 | numasec | selected | tag `v1.2.1` at `1237a2f3515aebbd5260383c7088aa0ea806b600` | AGPL-3.0-or-later + NOTICE branding | Finding-bundle terms OPEN; selected import only |
| R18 | SILENTCHAIN Community Edition | research | OPEN | OPEN | OPEN; reference-link-only |
| R19 | xalgorix | research | OPEN | OPEN | OPEN; reference-link-only |
| R20 | Pentest-Swarm-AI | research | OPEN | OPEN | OPEN; reference-link-only |
| R21 | Cybermes | research | OPEN | OPEN | OPEN; reference-link-only |
| R22 | Fire HD ownership retrospective | research | OPEN | OPEN | OPEN; reference-link-only |
| R23 | THOR Finding Triage Benchmark | research | OPEN | OPEN | OPEN; reference-link-only |
| R24 | cyberkimi-benchmarks | research | OPEN | OPEN | OPEN; reference-link-only |
| R25 | Claude-AD | selected | commit `73efec51207f6f740cb398e1c490e5edd60c1113` (no tags) | MIT | Curated-content rights OPEN; selected import only |
| R26 | Awesome Red Teaming | research | OPEN | OPEN | OPEN; reference-link-only |
| R27 | Blackstorm Security research | research | OPEN | OPEN | OPEN; reference-link-only |
| R28 | YesWeHack LLM series: Codex | research | OPEN | OPEN | OPEN; reference-link-only |
| R29 | deep-eye | research | OPEN | OPEN | OPEN; reference-link-only |
| R30 | exploitarium | research | OPEN | OPEN | OPEN; reference-link-only |
| R31 | METATRON | research | OPEN | OPEN | OPEN; reference-link-only |
| R32 | Virtual//Attack | research | OPEN | OPEN | OPEN; reference-link-only |
| R33 | Leonidas | selected | commit `77ec6bd17e65a111b30fc490476f28cb29308a0f` (no tags) | MIT | Generated Sigma/docs rights OPEN; selected import only |
| R34 | Detection in the Cloud | selected | generating commit `77ec6bd17e65a111b30fc490476f28cb29308a0f` + site snapshot 2026-10-13 | generating-repo MIT; site no notice | Corpus terms OPEN; selected import only |
| R35 | AgentSeal | selected | tag `v0.10.0` at `7c2a22891465ac4c00bd45f4a50c742aa4651275` | FSL-1.1-Apache-2.0 (converts to Apache-2.0) | Redistribution review OPEN; selected import only |
| R36 | Rubeus | selected | head `74215f68ea70bd6a66c008da91bf5fe21d20b154` (only tag 1.6.4 is 2021) | BSD-3-Clause | Inbound CC BY-NC/GPLv3 flags; example material OPEN; deweaponized telemetry import only |
| R37 | CVE MCP Server | research | OPEN | OPEN | OPEN; reference-link-only |
| R38 | M365Pwned | research (refused) | commit `15e68ab52341d7e5d9eaac3551a37b5c2d729cee` (no tags) | no-license-found (no root LICENSE) | No NOTICE/dataset terms OPEN; adoption refused 2026-10-14 pending license |
| R39 | AI-Pentest / Hacking Articles | research | OPEN | OPEN | OPEN; reference-link-only |
| R40 | Hetty | research | OPEN | OPEN | OPEN; reference-link-only |
| R41 | SANS AI-assisted investigations | research | OPEN | OPEN | OPEN; reference-link-only |
| R42 | pentestkit | selected | commit `ac492b2a8613c85acee4d7b6cdec1a7abd14ce7f` (no tags) | MIT | Third-party referenced material OPEN; selected import only |
| R43 | Security-Detections-MCP | admitted | tag `v3.3.0` at `54a588cad9cae3026279716a6dc8b75af43a4d0a` | claimed-not-deposited (states Apache-2.0, no text file) OPEN | Aggregated corpora keep own licenses OPEN; admitted DATA-02 slice only |

Schema/currentness detail for the 14 verified families (R01/R02/R03/R08/
R15/R17/R25/R33/R34/R35/R36/R38/R42/R43): `schema_correspondence`
(input formats, upstream interface, known losses, unknown semantics) and
per-trigger `trigger_checks` are recorded per row in
[register.v2.yaml](../../governance/register.v2.yaml) and evidenced in
[source verification](source-verification-2026-10-13.md); the 28
still-research rows carry `schema_correspondence: null`,
`verified_revision: null`, `code_license: OPEN`, `data_rights: OPEN`.
Full verbatim text is in the register; the table above shortens without
changing meaning.

## 5. Source selection is not runtime tier

Source `selected`/`admitted` never admits or promotes an action: all 52
PR97 runtime capabilities remain `research` tier, both admitted-slice
runtimes included. Runtime promotion evidence stays empty; any
nonempty runtime `promotion_evidence` or `shipped` module still fails
(`promotion-verifier-unimplemented` / `module-shipped-refused`). The live
`INVOKE_PROFILES` tier is reconciled on every check.

## 6. What stays OPEN (no closure claimed)

- Recurring review operation: source/runtime 90 days due `2027-01-11`,
  module 182 days due `2027-04-13`, from `2026-10-13`. Same-day repeated
  checks or advancing `--as-of` cannot prove recurring operation; this
  unit fixes current evidence/inventory only.
- All 24 campaign items, all 11 exit intents, and W1 acceptance stay
  OPEN. No W2, maintained promotion, source-corpus rights clearance,
  profile/runtime change, custody/grading, empirical SAFE, pack,
  product-workpaper, activation, or deployment work is claimed.
- Unknown rights cells stay `OPEN` inside the decision text (R01
  aggregate-DB, R43 corpora, per-row OPENs above).

## 7. Coverage limits

- Register rows verified: 29 modules / 109 sources / 227 runtime /
  26 relationships / 12 promotion events — byte-equal to the shipped
  register except the 20 corrected citation strings (10 events × 2 fields).
- Test-file existence is not execution proof; validator and tests assert
  resolvability and anchor equality only.
- Validation uses repository fixtures and synthetic test artifacts. The
  correction grants no source consumption, runtime execution or rights clearance.


## 8. Validation of this change

Validation uses the existing Python environment with one OpenBLAS/OMP/MKL
thread and `PYTHONDONTWRITEBYTECODE=1`; no dependency installation is needed.
The starting tree is merged PR #1, `a91fd037f19d7945620c55836c7f4e398b68721b`.

- `python3 -m pytest -q -ra -p no:cacheprovider tests/test_gov_promotions.py
  tests/test_governance_v2.py tests/test_arm_batch7.py tests/test_arm_batch8.py`:
  **693 passed in 28.04s**, exit 0, with this change.
- Causal baseline control: run the new
  `test_matching_nonexistent_anchor_and_event_fails_existence_guard` against
  an unchanged archive of `a91fd03`, copying only the new test file. It fails
  at `assert not report.integrity_ok` because the old checker accepts the
  matching nonexistent reference (one expected failure, exit 1). The same
  regression passes with the new guard. The assertion therefore distinguishes
  the original defect from an anchor-string mismatch.
- References are file-only. An unchecked pytest selector is rejected rather
  than presented as a resolved test; noncanonical dot/empty path segments also
  fail. The symlink regression uses an owned temporary directory and a
  synthetic external artifact, with an explicit skip where the host cannot
  create symlinks.

These outcomes prove the exercised local contracts. They do not prove a test
ran on the historical authorization date or establish recurring operation.
The PR binds the final revision and independent review; the correction and
population tables remain separate from admission or runtime promotion.
