# Individual evidence evaluator APIs

For operator investigations, use [core pack analysis](operator-learning-arm.md)
through `extension invoke` or the attached head's `invoke` tool. It connects
these evaluators to findings, target identities and validation work.

The commands below remain compatibility interfaces for evaluating an individual
input or authoring an assessment. The fixed agent scene and fixed detection
worksheet are self-study contracts; they are not actual agent-attempt or target
telemetry evaluations. Core operation uses captured head traces and scoped
detection records instead.

| Command | Working outcome | Contract and example |
|---|---|---|
| `graph` | Import a hash-pinned RAGE v0.1 NDJSON permission graph and distinguish configured, blocked and unknown path branches. | [Graph reader](../graph_evidence/README.md); `python -m learning graph --help`. |
| `k8s` | Normalize a hash-bound k8scout JSON report and review pod/service-account, RBAC and prerequisite paths. | [Kubernetes reader](../k8s_path_evidence/README.md); `python -m learning k8s --help`. |
| `review` | Check a threat-model workpaper's scope, hypothesis ledger, coverage links and bounded evidence hashes; preserve a human conclusion review. | [Learner packet](../challenges/lab-review-01-threat-model/learner/README.md); `python -m learning review --help`. |
| `agent` | Generate a deterministic tool-event trace and grade attempted actions separately from simulated effects and agent prose. | [Agent exercise](../challenges/lab-agent-01-tool-boundary/README.md); `python -m learning agent run --out /tmp/agent-trace.json`. |
| `detection` | Evaluate five linked stages from technique hypothesis to rule, collection, alert, analyst action and retest, plus retest effectiveness. | [Detection exercise](../challenges/lab-detect-01-technique-chain/README.md); `python -m learning detection --case missing-telemetry`. |
| `triage` | Import a captured SiftRank ranking, compare recall@k with a deterministic lexical baseline on held-out labels, or run an operator-selected SiftRank executable against a configured provider. | [Triage contract](siftrank-triage.md); `python -m learning triage {import|evaluate|rank} --help`. |

These commands evaluate local supplied inputs. Use `python -m learning <command> --help` for the current arguments. The [operator CLI](operator-learning-arm.md) connects example assessments to the extension `invoke` surface. Each result describes its own input and computation; a shaped file or matching hash alone does not establish where its contents came from.
