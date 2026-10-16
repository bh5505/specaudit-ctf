# Telecom AWS 06 — multi-stage chain rehearsal (flagship)

The flagship rehearsal: a **four-stage** engagement that composes the
skills from challenges 01–05 into one deliverable chain, run against
the multi-service chain fixture
(`extension/range/tf_chain_ingress_role/`) plus the two originals
(`tf_iam_open`, `tf_s3_public_access`). Each stage has its own
expected contract and is graded by the same engine:

```
python -m score --grade my-stage-N.json --expected artifacts/stage-N-expected.json
```

Partial credit is honest: your stage report is `stages passed / 4`,
but the challenge **passes only 4/4** — a partial finding set never
reads as all-clear. The overall contract
(`artifacts/expected-findings.json`) is the union of the stages.

## Stages

**Stage 1 — host surface.** Enumerate the range
(`python -m extension.range --arm-ids ""`) and report the two direct
exposures inside `tf_chain_ingress_role`: the world-open ingress and
the assumable administrator role. Ship `my-stage-1.json` against
`artifacts/stage-1-expected.json`.

**Stage 2 — the chain.** One finding neither asset shows alone: the
internet-reachable surface chains into the assumable admin role. Trace
it to the connectivity edge that joins them
(`input/connectivity.json`). Ship `my-stage-2.json` against
`artifacts/stage-2-expected.json`.

**Stage 3 — cross-fixture chain.** Repeat challenge 02's move at the
chain level: the wildcard identity policy in `tf_iam_open` combined
with the public-read bucket in `tf_s3_public_access` is one finding.
Ship `my-stage-3.json` against `artifacts/stage-3-expected.json`.

**Stage 4 — the deliverable.** The full five-finding report a real
audit cycle would hand over: both stage-1 exposures, the chain
finding, the cross-fixture chain, plus the unbounded wildcard identity
itself. Ship `my-stage-4.json` against `artifacts/expected-findings.json`.

Every shipped row needs owned evidence: `traces_to`, `control`, and
`rationale` all non-empty, tracing to exactly one planted violation.
Evidence-less rows are reported invalid and count as misses.

## Out of scope (by design)

No live cloud, no credentials, no speculation beyond the fixtures'
bytes.
