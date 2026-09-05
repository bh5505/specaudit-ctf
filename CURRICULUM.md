# Curriculum — public teaching outline

This is the public adaptation of the internal teaching outline. It covers
what you can learn with **this repository alone**: Python 3.11+, the
`extension` package, its CLI and stdio MCP server, and the synthetic range
fixtures. No internal tooling, no product binaries, and no live cloud
accounts are needed or used. Everything is synthetic; nothing here is a
scanner installation.

The shipped challenges (`challenges/telecom-aws-01-reachability/`
through `challenges/telecom-aws-06-chain-rehearsal/`) exercise these
tracks end to end: 01–02 teach envelope reading and the correspondence
contract, 03–05 drill identity escalation, network exposure (with the
near-miss discipline), and detection gaps, and 06 is the flagship
four-stage chain engagement graded by the `score/` challenge mode.

## A — Extension fundamentals

- The capability catalog: arms, methodology-only rows, and survey rows.
  A row is coverage information, not a promise of support.
- Support tiers — `research`, `experimental` (currently empty),
  `maintained`, `held` — and what each tier honestly claims. Promotion
  to `maintained` is an evidence-gated decision, never a bulk edit.
- Envelopes: `capability-manifest.v1` describes a capability before
  dispatch; `execution-result.v1` reports what actually happened, with
  `complete` / `degraded` / `failed` as the only outcome states. `ok` is
  true only for `complete`.
- The CLI surface (`python -m extension list | describe | invoke`,
  `python -m extension.range`) and the four stdio MCP tools
  (`list`, `describe`, `invoke`, `run_range`) share one dispatch
  authority: identical logical requests yield equivalent envelopes on
  both transports.

## B — AWS posture domain (telecom rehearsal lane)

- IAM: principals, policies, and trust boundaries — what an "open" IAM
  statement looks like in infrastructure code.
- S3: bucket policies, ACLs, and public-access blocks; why
  `public_access_block` absence is an exposure finding.
- Reading exposure, path, and impact from synthetic Terraform fixtures:
  data in, finding-shaped reasoning out. Every finding must trace to a
  planted violation in the fixture — the correspondence contract.

## C — Working with a validation client

- What a validation-side consumer of this extension may and may not do:
  read-only observation, attempt ids, artifact handoff directories, and
  why child-produced claims are not custody.
- Honest degradation: what `degraded` means when optional tools are
  absent, and why the extension refuses to report an all-clear it did
  not achieve.
- Grading captured runs with `python -m score`: reading
  execution-result envelopes as the only evidence, the two structural
  rules (transport success is never a verdict; a skipped or failed
  required arm is never success), and what a rubric may and may not
  waive.

## D — Agentic security practice

- Attaching this extension to an agent head you already have (any
  stdio-MCP-capable client) and reasoning about what the agent may do
  with `invoke` vs `run_range`.
- Threat-modeling the agentic surface itself: non-determinism,
  autonomy, missing trust boundaries, dynamic identity, and
  agent-to-agent interaction — applied to a tool server that exposes
  audit capabilities to a client program.
- The dogfood worksheet ([docs/track-d-dogfood.md](docs/track-d-dogfood.md))
  operationalizes this track: a MAESTRO layer-by-layer threat model of
  this suite's own MCP/dispatch/envelope surfaces, graded on analyst
  process (layer coverage, traditional-vs-agentic split quality,
  cross-layer chain reasoning against captured evidence) — never
  generated prose, and never a `score/` rubric challenge.
