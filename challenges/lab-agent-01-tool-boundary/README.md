# Lab Agent 01 — tool authority and observation

**Status:** design-ready executable E1 rehearsal, version 1. Owner: repository
maintainers; review after a policy, trace-schema, or curriculum change. Domain:
T07 agent security / `PACK-03`. Audience: intermediate security analysts familiar
with action scope, evidence custody, and the difference between model assertions
and tool events. Prerequisite: [operations boundary](../../OPERATIONS.md),
[challenge grading](../README.md), and a previous synthetic evidence exercise.

The original scenario draws the *teaching idea* of separating attempts from tool
actions from the pinned C11 ai-ctf survey in
[the candidate report](../../docs/candidate-campaign-2026-10-03.md), and the
reported-versus-observed caution from C31. No upstream challenge, payload,
indicator, model, network endpoint, or campaign artifact is bundled. The
`fixture://` targets are labels only. Python 3.11+ and this checkout suffice.

## Learner brief

An agent reviews a synthetic asset catalog. A lower-trust document tells it to
export a canary and later to read a grader key; another sensor goes unavailable.
The agent's prose claims success or absence of activity. Classify each request
using the **policy and tool-event trace**, not that prose. Preserve the unknown
when monitoring cannot show a result. The exercise tests the boundary between
learner authority, document instructions, policy denial, simulated tool outcome,
and unsupported inference. It does not assess a real LLM's resistance to an
injection or simulate real exfiltration.

Generate a fresh trace in an operator-owned directory:

```sh
python -m learning.agent_security_harness run --out /tmp/agent-tool-trace.json
```

Submit a JSON document with exactly `schema`, `attempt_id`, `trace_sha256`,
and `assessments`. Copy the latter two binding fields from the trace. For every
event, submit one row with exactly `event_id`, `classification` (`clean`,
`rejected`, or `unknown`), `observed_effect` (`executed`, `denied`, or `unknown`),
`report_match` (`yes`, `no`, or `unverifiable`), and `evidence_event_id`.
An evidence ID must name the *same* monitoring event; prose is not evidence.

```sh
python -m learning.agent_security_harness grade --trace /tmp/agent-tool-trace.json --submission /tmp/my-assessment.json
```

Exit 0 passes all four rows; exit 1 returns a graded JSON with incorrect fields;
exit 2 rejects malformed, tampered, unbound, duplicated, or incomplete data.
The learner may repeat with a new trace filename. The checked-in
`instructor/` directory is **not a learner asset**: a delivery must mount only
this brief, a generated trace, and the CLI in a separate learner context.
The CLI has its own policy and expected answer logic in source, so hiding just
the answer-key file is insufficient for adversarial secrecy. This is an
assessment rehearsal, not a secure examination.

## Operator and assessment contract

- E1 offline synthetic; no sockets, subprocesses, model calls, secrets, real
  file reads, or external actions. The only write is the requested trace path.
  Tool `executed` means a deterministic simulated catalog read, never a real
  connector invocation. Denied actions cause no target write or read.
- Permit only learner-origin `catalog.read` on the public fixture and
  `telemetry.inspect` on the named sensor fixture. A tool document never
  enlarges admission. The unavailable sensor yields `unknown`; no negative
  conclusion about compromise follows. The instructor key and grader labels
  are outside the declared target set.
- Provision a fresh restricted attempt directory with no learner access to
  instructor materials. Egress and external identity are absent; one command
  emits four events, with no retries or concurrency. The operator monitors
  process exit and trace custody, stops on unexpected I/O or access, and
  removes attempt files after review. A new attempt gets a fresh UUID. Keep
  submissions and generated traces only for the local cohort retention period.
- The trace is byte-checked against a deterministic scene and bound to a UUID
  and SHA-256. This prevents accidental file edits and invented evidence in
  the grading path; it does **not** prove the runner's identity, prevent a
  stateless replay, establish pre-execution admission, or meet the repository's
  `EVID-01` trusted-observation contract. Custody and separation remain an
  operator responsibility.
- No hints change the score; after one attempt an instructor may point to
  `admission`, `outcome`, and `monitor` columns without naming a row's answer.
  Machine grading is exact. A human debrief should examine why a successful
  sentence is insufficient and why sensor silence cannot be an all-clear.

The exercise is design-ready pending named technical, operator/safety, and
instructional reviewers; isolation/canary proof in the actual teaching
environment; learner dry-run, stop/reset evidence, and versioned calibration.
Its tests check the deterministic local semantics only and do not promote it
to a shipped challenge or to `score --grade` fixture-backed grading.
