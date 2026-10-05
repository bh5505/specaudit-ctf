# Core pack analysis and validation handoff

Use the existing `extension invoke` interface to analyze pack findings and
associated evidence. The compatible arm ID remains `learning-operator`; its
`analyze_pack` action calls `extension.pipeline.prioritize_targets`, the same
core used by operator-side validation reports. It does not run a set of sample
exercises. It preserves findings and their risk scores, builds target-specific
analysis and identifies follow-up validation work.

## Analyze findings through the core CLI or an attached head

Create `analysis-args.json` containing a pack report and optional associated
evidence. The report comes from the existing pack runner, not a new finding
schema:

```json
{
  "report": {"run_id": "operator-run", "findings": []},
  "operator_evidence": {
    "schema": "specaudit.operator-evidence.v1",
    "items": []
  }
}
```

An empty finding set has no targets; use the actual `report.json` produced by
`tools/ctf_run_checks.py` or `extension.pipeline.pack_run`. The README shows how
to wrap that file without reconstructing its findings.

```sh
python -m extension invoke learning-operator analyze_pack \
  --args-file analysis-args.json --include-report
```

The opt-in presentation contains `execution` and `report`. The latter contains
`assessment.targets`, each target's finding identities, threat model, attack
chain, operational reviews and validation work. Reviews are retained as
`operational_reviews[kind]` lists of `{finding_id, review}` entries so two
findings on one host cannot overwrite each other. Cloud and other non-IP findings
remain present even when no ATT&CK network path can be inferred. Scope-gated
validation remains a separate invocation of the selected existing arm.

For retained Mode A artifacts, add a freshly minted attempt ID and a fresh empty
absolute artifact directory using the existing `--attempt-id` and
`--artifact-dir` flags. Default CLI output remains the execution-result v1
envelope when `--include-report` is absent. `--args-file` is a bounded local
operator read; it is never an MCP argument.

Attached heads call the existing `invoke` tool:

```json
{"id":"learning-operator","action":"analyze_pack","args":{"report":{"findings":[]}}}
```

For this action, successful MCP results include a second text content block
with the digest-checked analysis report. The first block and `structuredContent`
remain the normal execution envelope. The agent can therefore use target
analysis in its next tool decision. No additional MCP tool or report-path reader
is required.

## Associate evidence with the finding it can support

Every `operator_evidence.items` entry has these exact fields:

```json
{
  "finding": {"check_id":"the original check ID","record_locator":"the exact original locator"},
  "kind":"graph",
  "input": {}
}
```

Use the original finding's exact identity. Unknown, repeated or mismatched
bindings are rejected. The supported input contracts are:

| Kind | Input and binding | Effect on target analysis |
|---|---|---|
| `graph` | Exact `graph_ndjson`, `sha256`, `source`, `target`, optional `project`; graph destination must match the finding subject. | Distinguishes configured, blocked and unknown paths and selects permission/prerequisite validation work. |
| `k8s` | Exact `report_json` and `capture`; service account must match the finding locator. | Adds reported permission/path prerequisites to the target's validation work. |
| `workpaper` | `manifest`, `submission`, `evidence` filename-to-exact-text mapping; submission subject must equal the locator. | Carries claim review and structural/custody gaps into the target handoff. |
| `detection` | `packet` using `specaudit.operational-detection.v1`; target equals the locator and technique occurs in the target's attack chain. | Evaluates collection, rule firing, analyst response and retest for that target/technique. |
| `agent` | Operator-produced trace review bound to the finding; see the actual-attempt section below. | Carries observed tool behavior and unsupported claims into review without giving agent prose trace authority. |

The optional `operator_evidence.triage` object uses `candidates_json`,
`ranking_json` and `binding` from the [SiftRank capture contract](siftrank-triage.md).
Candidate IDs must cover the analysis's target IDs exactly. Each candidate's
`source` must equal `extension.operator_analysis.triage_source_ref(report["findings"])`,
which binds the complete current finding set. Changing that set invalidates a
stale capture. Preserve the input, ranking and independent capture binding as
described in the SiftRank contract. Import changes review
order while retaining all targets, original scores and evidence requirements.
A ranking does not substantiate a finding.

Operational detection packets contain `target`, `technique_id`, `prerequisite`,
`rule`, `events`, `alerts`, `actions` and `retests`. Their records must link by
identity through the chain. Unlike the earlier fixed T1078 worksheet, this path
accepts the operation's own technique, rule and event identities. Missing
telemetry, prevention and ineffective retests remain distinct outcomes.

Captured data remains source-declared until custody and independent validation
establish more. The analysis neither contacts an upstream collector/provider
nor arms a scanner. Installed binaries, target scope and approved actions remain
requirements of the individual arms; generated validation work cannot supply
that authority.

## Review actual attached-agent attempts

The existing head/attempt path records MCP calls server-side. Its operator-side
trace verifier checks the keyed chain and close record before assessing what
actually happened. `python -m exercise --attempt-dir ... --expected ...` now
includes an `agent_trace` assessment alongside the existing finding grade.
The trace key stays in `SPECAUDIT_CTF_MCP_TRACE_KEY` on the verification side;
never put it in an agent prompt or an `analyze_pack` argument.

Optionally pass `--agent-claims claims.json` to compare the agent's reported
outcomes with particular recorded calls:

```json
{
  "schema": "specaudit.ctf.agent-trace-claims.v1",
  "trace_sha256": "SHA256 of the exact retained trace file",
  "claims": [{"seq": 1, "tool": "invoke", "reported_outcome": "succeeded"}]
}
```

Allowed claimed outcomes are `succeeded`, `failed` and `denied`. Unbound,
unsupported or contradictory claims cannot pass as observed success. A tool
failure does not prove absence of side effects. This assessment does not infer
an agent's intent or certify resistance to every prompt-injection technique.

To associate the operator's assessment with a finding, use kind `agent` and
input `{"target":"exact finding locator","trace_review":{...}}`. An attached
caller can supply that JSON but cannot authenticate it: core analysis labels
it a declared review and retains the requirement for operator verification.

## Existing evaluator compatibility interfaces

The six individual evidence/exercise actions below remain available for direct
API consumers and assessment authors. Operators use `analyze_pack` to connect
results to the actual investigation. The fixed agent and detection examples
remain self-study inputs, not measurements of an operator's real attempt.

Discover the catalog entry and the local operator commands:

```sh
python -m extension describe learning-operator
python -m learning operator --help
python -m learning operator sample --help
```

Produce and run an editable synthetic request. Repeat with `graph_path`,
`k8s_review`, `workpaper_review`, `agent_grade`, `detection_review`, or
`triage_evaluate` in place of `graph_path`:

```sh
python -m learning operator sample graph_path --out /tmp/graph-request.json
mkdir /tmp/learning-attempt-artifacts
python -m learning operator run --request /tmp/graph-request.json \
  --attempt-id attempt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --artifact-dir /tmp/learning-attempt-artifacts
```

The admitted `list_tools` and `sample` capabilities are also available through
`extension invoke` and MCP; use Mode A and read their verified policy-report
artifact to inspect the keys or sample args. A bare Mode B `extension invoke`
call prints only an envelope and artifact digest. The local `sample` command
above writes an editable packet populated with the bundled teaching fixture.
The agent example includes completed answers **only for
self-study**; do not distribute it as an instructor-hidden assessment.

The local operator CLI reads a JSON request of exactly
`{"arm_id":"learning-operator","action":"graph_path","args":{...}}` from a
file or `--request -` (stdin), and calls `extension.dispatch.dispatch_invoke`.
It requires Mode A, verifies the digest-named `policy-report` in the fresh
artifact directory, then prints a local wrapper containing the unmodified
`execution` v1 envelope and the parsed `report` with the actual assessment.
The wrapper is an operator CLI presentation, not a new execution-result
schema. It exits nonzero on an evaluated failure. Request files must be
regular, non-symlink files that remain unchanged during a bounded read; FIFOs
are rejected without waiting for a writer. Stdin remains an explicit streaming
input via `--request -`. The CLI rejects oversized, duplicate-key, non-finite
number, over-nested and malformed requests; it does not allow arbitrary arm
IDs. These local file reads belong to the operator process; the attached MCP
`invoke` tool accepts
only inline JSON arguments and has no request-file or evidence-path parameter.
The CLI is convenient for captured packets that would be awkward as shell
arguments. The same request args can be passed to the ordinary extension CLI
or MCP if their framing limits permit.

Mode A artifact custody requires Unix descriptor-relative filesystem operations.
Create a new empty directory for each run, and provide a unique validator-minted
attempt ID. The execution envelope carries a digest-named `policy-report` artifact. The
operator must independently retain and verify that file and the source bytes;
the sample's literal attempt ID is illustrative and must be unique in a real
validator ledger. The lower-level `extension invoke` Mode B omits both flags
and emits no artifact files or assessment body, so use Mode A to inspect results.

| Action | Exact inline inputs | Assessment |
|---|---|---|
| `graph_path` | `graph_ndjson` exact UTF-8 bytes as text, `sha256`, `source`, `target`; optional boolean `project` | Configured, blocked and unknown graph paths with provenance and projection omissions. |
| `k8s_review` | `report_json` exact text and `capture` object with the raw hash, pinned revision and subject | Reported SSAR/path outcomes and missing prerequisites, never effective access. |
| `workpaper_review` | `manifest`, `submission`, and `evidence` mapping each manifest relative filename to exact UTF-8 file text | Structural issues and mandatory human conclusion review; no file opens in the arm. |
| `agent_grade` | Deterministic `trace` and bound `submission` | Simulated attempted actions and observed effects, separated from agent prose. |
| `detection_review` | Synthetic `packet`; optional `submission` | Five stage states and retest result, or submission differences. |
| `triage_evaluate` | `candidates_json`, `ranking_json`, `labels_json` exact text and `binding` object | Captured review-order recall@k versus lexical baseline; ranking is not finding evidence. |

The adapter enforces an encoded argument and result budget of 256,000 bytes,
under the MCP stdio 1 MiB message cap. Underlying parsers apply their own row,
format, digest and field limits. Captured raw JSON/NDJSON text is UTF-8 encoded
without parsing/reformatting before upstream hash checks. A successful result
contains `assessment`, `request_args_sha256` (canonical submitted argument JSON),
`source_class`, and explicit limitations. That new request hash is an input
binding, **not** source authentication or evidence custody. `transport_ok` and
process exit zero mean a completed evaluator call, not a positive security
conclusion. Rejected input shape or a parser-invalid packet produces a failed
envelope; a workpaper with structural errors produces a completed assessment
with `structurally_valid: false`. A valid but incorrect learner submission can
likewise return a completed envelope
with `passed: false` or `pass: false` inside the assessment.

`triage_evaluate` imports an existing captured ranking only. The separately
opt-in `python -m learning triage rank` provider execution is not admitted here.
A real k8scout/Thunderstorm run and Cloudflare/OpenAI audit source collection
likewise require distinct operator authority and custody outside this arm.

The checkout and installed Python wheel include the bundled samples and the
local operator runner. The separately locked Linux x86-64 validator runtime
has not been rebuilt or attested for this new arm; do not assume the currently
sealed runtime contains it. Its pinned runtime-input and source-closure checks
remain an independent release gate.
