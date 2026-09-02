# Telecom AWS 01 — walkthrough

Work the objectives first; read this to check your reasoning, not to
replace it.

## 1 — Catalog survey

`python -m extension list` prints the catalog JSON. The honest counts by
tier move only by evidence-gated decisions: today exactly one arm row
(`agent-wiz`) is `maintained`, a handful of arms are `held`, the rest of
the arm rows are `research`, and the methodology-only rows carry their
survey tiers. The point of the objective is the reading discipline:

- a row is *coverage information*, not a support promise;
- `curated: true` means an executable handler exists in this package —
  it still needs its external binary at run time;
- `maintained` was granted to exactly one read-only action through the
  public evidence gate, and no content exercise may create another.

## 2 — The capability surface before the result

`describe agent-wiz` prints the catalog row: `tier`, `curated`,
`protocols`, and the notes — the catalog layer, and the notes are where
the action surface is documented (`list_tools` is the maintained
read-tier action; `extract` / `visualize` are path-contained local
reads; `analyze` is egress-gated). The manifest golden covers the
maintained dispatch itself: `tests/goldens/capability-manifest/agent-wiz.list_tools.json` states the safety class, side effects,
budget, cleanup, and authorized scope for `list_tools`. Invoking
`invoke agent-wiz list_tools {}` returns a `complete`
envelope whose `artifacts` claim the tool enumeration the action
produces; with `--artifact-dir` the claimed bytes land as digest-named
(`sha256-<hex>`) files you can re-hash yourself. In
`manifest-vs-result.md` the interesting split is three-layered: the
catalog row tells you *what exists and at what tier*; the manifest
tells you *what dispatch is allowed to do*; the envelope tells you
*what actually happened* — attempt id, artifact digests, and the
outcome status exist only in the result, while budget/cleanup are
stated in the manifest and echoed in the report.

If you passed `--attempt-id` / `--artifact-dir` you also saw the Mode-A
handoff contract: fresh private directory, digest-named canonical
bytes, artifact claims the producer cannot fake.

## 3 — The honest range

The range reports `status: "degraded"` — on every host, including ones
with scanners installed. That is not a bug to fix but the documented
invariant (see `tests/goldens/transport-parity/matrix.json`): held
curated arms force at least one error row everywhere, and the range
dispatches an `observe` action that no curated arm currently admits, so
their rows carry action errors. On a scanner-less host you also see
`optional arm is not installed` limitations — those arms are *skipped*
rows. The range refuses to present an unachieved all-clear; `complete`
stays empty until an arm actually admits and completes the dispatched
action. Installing a curated arm's binary changes its row from a
not-installed skip to an `observe`-action error — honest, and still not
an all-clear.

Determinism: same host + same seed → byte-identical range-report
artifact digest; `--seed 456` changes the digest (the seed is hashed
into the artifact) while the planted fixture violations stay the same —
the seed controls synthesis, not the planted ground truth. Which arms
were attempted, their row reasons, and the limitations list vary with
the host's installed state; the fixture ground truth does not.

## 4 — Reading the planted exposure

In `tf_s3_public_access/input/main.tf` the planted violations are the
`acl = "public-read"` on `aws_s3_bucket.public_bucket`, the absence of
an `aws_s3_bucket_public_access_block` resource (nothing stops the ACL
or any future policy grant from making objects world-readable), and the
absence of a server-side encryption configuration. A defensible
`findings.json` has one entry per violation, each traced to exact lines
— for example:

```json
{
  "finding_key": "s3-public-read",
  "exposure": "The bucket ACL grants public read; every object is world-readable by default.",
  "traces_to": "main.tf, aws_s3_bucket.public_bucket, acl = \"public-read\""
}
```

The correspondence contract cuts both ways: an entry you cannot trace to
lines is manufactured, and a planted violation you skipped is a miss.
"Traces to an absence" is legitimate — name the missing resource and
why its absence is the violation.

## 5 — Deliverables

`report.json` binds the findings to the run: seed, schema id, and the
range artifact digest from objective 3. `report.sarif` is a SARIF 2.1.0
skeleton (`$schema`, `version`, one `results[]` entry per finding with
`ruleId` = finding_key). Same findings, same count, no extras — the
grader in a real cycle diffs these two views of the same truth.

## 6 — Agent-head attachment

Through the MCP server, `tools/list` returns the four advertised tools;
`run_range` returns the same envelope as the CLI modulo wall-clock
fields. If your client shows any drift beyond timestamps, that is a
parity bug worth reporting — not an artifact of the transport.
