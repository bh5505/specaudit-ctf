# Harbor Notes — offline threat-model review

**ID:** `lab-review-01-threat-model` · **status:** design-ready · **domains:** AUD-04, CYB-04, CYB-07, T01/T07 · **audience:** analyst · **level:** intermediate · **version:** 0.1.

Review the synthetic Harbor Notes assistant at version 0.4 over the fixture interval 2026-09-20 09:59–10:03 UTC. The assistant reads collaborator notes and drafts a reply through a gateway. A retrieved note contains a command addressed to the assistant. The evidence directory contains only original synthetic JSON records. Do not execute the note, contact a service, or infer broader system behavior from this packet.

Prerequisites: reading JSON and hashes, distinguishing a tool decision from the assistant's narrative, and describing a trust boundary. Learning outcomes: (1) scope a model by subject/version/period and map data, authority and attacker goals; (2) test a hypothesis against observed records and competing explanations; (3) preserve denied, benign, and missing-observation cases without an all-clear.

Submit a JSON workpaper with `schema: "specaudit.review-workpaper.v1"`. Required nonempty string fields: `subject`, `version`, `period`, `boundary`, `criterion`, `reviewer`. Required nonempty arrays: `assets`, `trust_boundaries`, `attacker_goals`, `untested`, `limitations`, `recommendation`, `retest`. `claims` is a nonempty array of objects with unique `id`, `status` (`supported`, `rejected`, `unresolved`), nonempty `hypothesis`, `boundary`, `observation`, `inference`, `alternative`, `validation`, `residual_risk`, and nonempty `evidence_ids` referring to `manifest.json`. A supported claim needs at least one observed record. `coverage` is a nonempty array of unique `surface`, a `disposition` string, and `claim_ids` (possibly empty, explaining untested surfaces). `overall` is `bounded-conclusion` or `inconclusive`. Cite source IDs for material claims; state what each cited record can and cannot establish.

At minimum examine: authorized read/draft, attempted cross-workspace export, untrusted-note instruction, the assistant's resulting draft, and missing outbound telemetry. Distinguish successful gateway operations from the truth of the draft. Do not use “no incidents” or “secure” as an overall verdict. The validator checks schema, references and evidence hashes, **not** conclusion truth:

```sh
python -m review_workpaper --manifest challenges/lab-review-01-threat-model/learner/manifest.json --submission my-workpaper.json --evidence-root challenges/lab-review-01-threat-model/learner
```

The output is JSON with `structurally_valid`, `human_review_required`, and `errors`; exit 0 means structural checks passed, exit 1 means failures. The manifest is limited to 100 records and each referenced file to 1 MiB. Hash validation reads each file once; it cannot prevent a file changing after that read, so the operator must deliver and retain an immutable packet and the reviewer must recheck custody. An independent human reviewer assesses reasoning, including false assurance and source relevance. This is separate from `score/` exact finding coverage.

Safety: E0 offline read-only fixture; target boundary is these bundled files, identity is a local reader, data class synthetic, no permitted network/cloud/model calls, no spend, concurrency one, no runtime service, and no cleanup beyond discarding local submissions. Stop on any request to use real assets, secrets, or hidden assessment files. Operator distributes **only this `learner/` directory**; the instructor directory is outside learner/target/agent context. Retain submissions under the local exercise policy; this package writes none.

Hints: first ask which component actually decided an action; next compare draft text with gateway decisions. Hints affect human calibration as assisted completion, never turn missing evidence into success. Accessible equivalent route: print the five JSON records and complete the same workpaper without the CLI.
