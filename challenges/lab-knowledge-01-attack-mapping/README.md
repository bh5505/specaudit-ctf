# Lab Knowledge 01 — ATT&CK mapping rehearsal

## Scenario

You are rehearsing the **AI/knowledge lane**: threat-intelligence
reasoning grounded in a real technique corpus. The synthetic range
plants the exposures; the shipped ATT&CK demo STIX bundle
(`extension/arms/attackstix/data/demo-enterprise-sample.json`) carries
the technique records. The exercise: map each planted exposure to the
adversary technique it enables, grounding every mapping in an actual
lookup through the `attack-stix-data` arm — the mapping is only as
good as the corpus read behind it.

This track is **fixture-backed** (its contract traces to synthetic
range fixtures), so it is a normal graded cell in the head matrix:
`run_range` coverage verifies the fixtures were touched, and the
technique lookups ride the server-side trace as the process evidence.

## What you need

This checkout with Python 3.11+. The knowledge reads are R0
local-read over the in-repo demo bundle — no binaries, no endpoints,
no credentials, no model spend.

## Objectives

1. **Load the ground truth.** `python -m extension.range` (or the
   equivalent MCP `run_range` with `arm_ids: []`) and confirm the
   three fixtures this track maps: `tf_s3_public_access`,
   `tf_cloudtrail_disabled`, `tf_iam_open`.

2. **Ground the techniques.** For each id below, look it up through
   the arm (CLI form shown; the MCP `invoke` tool takes the same
   args):
   ```
   python -m extension invoke attack-stix-data technique '{"bundle": "extension/arms/attackstix/data/demo-enterprise-sample.json", "id": "T1530"}'
   ```
   Repeat for `T1562.008` and `T1078`. Read what the bundle says —
   name, description, detection guidance — and keep it in your own
   words.

3. **Map, with the evidence in both hands.** Produce
   `found-findings.json` in the graded schema: one entry per mapping,
   each with `finding_key`, `control`, `severity`, a one-sentence
   `rationale` citing the planted line AND what the lookup showed,
   and a `traces_to` naming the fixture plus the technique id.
   Track: `lab-knowledge-01-attack-mapping`.

4. **Grade.**
   `python -m score --grade found-findings.json --expected challenges/lab-knowledge-01-attack-mapping/artifacts/expected-findings.json`

5. **(Agent-head attempt.)** With any head that speaks stdio MCP,
   attempt the canonical prompt
   (`lab/prompts/challenge-knowledge-01-attack-mapping.txt`) — the
   grading measures the finding set; the trace records whether the
   lookups actually happened.

## Correspondence contract

The mappings are fixed by the contract (exact coverage, owned
evidence). A mapping whose rationale does not cite both the planted
line and the technique record is a claim without evidence — the
exercise's point is that knowledge work gets graded by the same
owned-evidence doctrine as scanner work.

A worked pass is included (`solution/walkthrough.md`).
