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

## 2 — Manifest before result

`describe agent-wiz` shows the arm row: `list_tools` is the maintained
read-tier action; `extract` / `visualize` are path-contained local
reads; `analyze` is egress-gated. Invoking
`invoke agent-wiz list_tools {}` returns a `complete` envelope with an
`agentwiz-tools.json` artifact. In `manifest-vs-result.md` the interesting
split is: capability id, action, and side-effect class are claims you
verified from both sides; the attempt id, artifact digests, and the
budget/cleanup sections are observable *only* in the result envelope —
which is exactly why the manifest describes and the result reports.

If you passed `--attempt-id` / `--artifact-dir` you also saw the Mode-A
handoff contract: fresh private directory, digest-named canonical
bytes, artifact claims the producer cannot fake.

## 3 — The honest range

On a host with no optional tools installed the range reports
`status: "degraded"` with limitations like `optional arm is not
installed` / `arm status=error`, and the `coverage.complete` bucket is
empty. That is the contract working: the range refuses to present an
unachieved all-clear. Installing any curated arm's binary moves that
arm's row from `failed` to `complete`-eligible on the next run without
changing any fixture.

Determinism: identical seed → identical range-report artifact digest.
`--seed 456` changes the digest (the seed is hashed into the artifact)
while the planted fixture violations stay the same — the seed controls
synthesis, not the planted ground truth.

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
