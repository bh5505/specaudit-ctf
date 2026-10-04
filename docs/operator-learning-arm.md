# Offline learning operator arm

`learning-operator` is a research-tier, first-party operator adapter for six
PR4 evidence/exercise workflows. It calls the same bounded evaluators as the
original `python -m learning` commands, without starting k8scout,
Thunderstorm, SiftRank, a provider, an agent, or a target-side tool. It adds no
source admission, trusted observation, effective-access proof, workpaper
conclusion, or formal challenge grade. E1 host isolation, evidence rights and
custody are the operator's responsibility.

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
schema. It exits nonzero on an evaluated failure. It rejects oversized, duplicate-key and
malformed requests; it does not allow arbitrary arm IDs. These local file
reads belong to the operator process; the attached MCP `invoke` tool accepts
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
