# Evidence workflow API reference

Start new operations with the [unified operator console](operations-console.md).
This page documents the underlying compatibility API and its data contracts.

These importable Python workflows are bounded learning and evidence-review
pilots. Install with Python 3.11+ (`pip install -e '.[dev]'` for tests) and use
`python -m learning {graph|k8s|review|agent|detection|triage}`. The
`learning-operator` research arm additionally admits six offline inline-input
actions through `extension invoke` and the existing `invoke` MCP tool. It adds
no separate MCP tool, trusted observation, or finding-grader credit. Input
source records and model ranks remain
declarations until independent custody and validation establish more.

| Command | Working outcome | Contract and example |
|---|---|---|
| `graph` | Import a hash-pinned RAGE v0.1 NDJSON permission graph and distinguish configured, blocked and unknown path branches. | [Graph reader](../graph_evidence/README.md); `python -m learning graph --help`. |
| `k8s` | Normalize a hash-bound k8scout JSON report and review pod/service-account, RBAC and prerequisite paths. | [Kubernetes reader](../k8s_path_evidence/README.md); `python -m learning k8s --help`. |
| `review` | Check a threat-model workpaper's scope, hypothesis ledger, coverage links and bounded evidence hashes; preserve a human conclusion review. | [Learner packet](../challenges/lab-review-01-threat-model/learner/README.md); `python -m learning review --help`. |
| `agent` | Generate a deterministic tool-event trace and grade attempted actions separately from simulated effects and agent prose. | [Agent exercise](../challenges/lab-agent-01-tool-boundary/README.md); `python -m learning agent run --out /tmp/agent-trace.json`. |
| `detection` | Evaluate five linked stages from technique hypothesis to rule, collection, alert, analyst action and retest, plus retest effectiveness. | [Detection exercise](../challenges/lab-detect-01-technique-chain/README.md); `python -m learning detection --case missing-telemetry`. |
| `triage` | Import a captured SiftRank ranking, compare recall@k with a deterministic lexical baseline on held-out labels, or explicitly opt in to a hash-checked local SiftRank executable against a separately authorized provider. | [Triage contract](siftrank-triage.md); `python -m learning triage {import|evaluate|rank} --help`. |

The workpaper, agent, detection, and Kubernetes exercises are **implemented,
executable E1 self-study pilots**. Machine checks run now, but a formal
instructor-hidden assessment still needs named reviews, learner-context
separation, calibration, and operator dry-run under the
[challenge authoring contract](../challenges/README.md#authoring-contract-for-new-content).
Graph and triage readers are implemented research import surfaces with
intentionally narrow format and custody claims. They have no live cloud or
cluster collector. The
SiftRank synthetic ranking tests importer and metric wiring, not model quality;
no model/provider call was made in repository validation. An actual provider
experiment requires the operator's own scope, egress and spend enforcement.

The [operator procedure](operator-learning-arm.md) covers discovery, runnable
requests, artifact custody, and each action's inputs and limits. The local
`python -m learning operator` command reads an operator-held request file and
uses the same admitted dispatch. Attached MCP accepts inline JSON only.

The [source decisions](source-decisions-2026-10-03.md) record selected upstream
revisions and rights. The [candidate campaign](candidate-campaign-2026-10-03.md)
is the pre-implementation survey. Review the source-specific limits in each
workflow before supplying a captured export; a correctly shaped file or
matching self-selected hash does not authenticate its producer or give access
authority. The baseline `score --grade` fixture challenges and extension
dispatch gates remain separate.
