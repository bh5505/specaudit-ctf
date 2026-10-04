# Synthetic-range operator console

`python -m exercise` is the operator entry point for inventory, planning,
execution, evidence verification, reporting, challenge packets and grading.
It runs from the installed wheel or a checkout. Lower-level CLIs remain
compatible implementation interfaces, rather than separate setup paths.

## Run the packaged operation

Use Python 3.11+ in a virtual environment and a Unix host for descriptor-bound
Mode A evidence custody. From the repository, install the package:

```sh
pip install .
python -m exercise inventory
python -m exercise plan --out operation-plan.json
python -m exercise run --plan operation-plan.json --out operation-001
python -m exercise status operation-001
python -m exercise report operation-001
```

Plan and run outputs must be fresh paths. No scanner, provider credentials,
cloud account or external lab is needed for the default operation. A plan
names the exact synthetic scenarios and their inputs. A run retains its plan,
per-step request identities, execution envelopes, staged sources and report artifacts. Status and report
read back and verify the retained evidence before presenting conclusions.

`inventory` accounts for the complete extension catalog and all 13 exact-grading
challenge contracts. It maps runnable scenarios to their actual adapter actions
and identifies missing operational recipes or external prerequisites. Static
`list_tools` availability is not counted as target execution. Methodology-only
entries remain references rather than invented executable adapters.

## Select and customize a scenario

List scenario IDs with `inventory`, then repeat `--scenario` to select a subset:

```sh
python -m exercise plan --scenario range --scenario graph-path --out selected-plan.json
python -m exercise run --plan selected-plan.json --out selected-operation
```

The six inline assessment scenarios accept edited evidence through their
plan `args`. Their existing schemas and size limits still apply. File-reader
recipes use the packaged fictional corpus; the console fixes their action and
source selection. Editing a plan cannot introduce another arm, a live target,
an arbitrary file path, a provider call or a model call.

The packaged scenarios include:

| Scenario family | What actually executes |
|---|---|
| Range lifecycle | The ten synthetic Terraform/identity/network fixtures, with explicit zero scanner arms. |
| Permission and Kubernetes paths | The graph and RBAC evaluators over supplied synthetic evidence, preserving blocked paths and missing prerequisites. |
| Workpaper review | Scope, hypothesis, coverage and evidence-reference validation. Human audit conclusions remain a separate decision. |
| Agent boundaries | Deterministic tool-event and submission comparison. A packaged reference trace does not mean a live agent was tested. |
| Technique-to-detection | The technique, rule, collection, alert, analyst-action and retest checks. Detection gaps remain visible. |
| Triage | Captured-rank evaluation against the lexical baseline. No ranking provider is contacted. |
| Reconnaissance and ATT&CK | Existing admitted adapters over fictional CT/DNS/registry records and the packaged STIX corpus. |
| Evidence readers | Fourteen admitted reader families over packaged fictional detections, methods, AD paths, policy, telemetry, experiments and identity evidence. |
| Optional HTTP target | The real HTTP probe adapter against a disposable loopback service, followed by verified cleanup. |

The scenario IDs and exact action mapping in the installed inventory are the
executable source of truth. Some fixture records intentionally contain gaps,
negative conditions or unresolved paths. Those are assessment results, not
failed operation setup.

## Exercise a local service target

The optional target requires an installed `curl` and a Unix host. Select it
explicitly:

```sh
python -m exercise run --scenario http-target --out http-operation
python -m exercise report http-operation
```

The console creates a short-lived HTTP listener bound only to `127.0.0.1`,
assigns an ephemeral port, and scopes the real `http-probe` adapter to that
exact endpoint. Curl configuration and proxy routing are disabled for this
invocation. The report binds the observed response to a synthetic canary,
records the request and retains cleanup state. The listener stops on exit,
and prior operator environment settings are restored. This is local target
operation; it neither provisions the WSL lab nor authorizes any other host.

## Read the results

Read three distinct outcomes:

1. **Operation and step status:** whether the selected work executed and its
   evidence was retained and verified. Missing, interrupted or failed steps
   do not become a completed run.
2. **Assessment:** what the retained adapter report says about the synthetic
   evidence. A successful call can identify a vulnerability or missing control.
3. **Submission grade:** whether a submitted finding set meets its existing
   exact comparison contract. This is produced by `grade`, not inferred from
   the operation completing.

`status` provides the run summary; `report` includes the assessments and full
retained adapter reports. Saved run directories can be moved and verified again. Retain
the whole run directory. Hash checks detect inconsistent retained files;
they do not authenticate the operator or prevent a party with write access
from replacing an entire run. Keep operator evidence under separate access
controls. The [operations policy](../OPERATIONS.md) covers custody and
containment beyond the command itself.

## Deliver and grade a challenge

The console prepares the seven fixture-backed challenge packets and grades
all 13 existing contracts:

```sh
python -m exercise prepare telecom-aws-01-reachability --out learner-01
cp learner-01/findings-template.json submission-01.json
# Fill submission-01.json with evidence-supported findings.
python -m exercise grade telecom-aws-01-reachability \
  --packet learner-01 --found submission-01.json --out grade-01
```

Only give participants the prepared packet. It includes observable fixture
inputs, an empty template and a shared candidate vocabulary; it excludes
answer contracts, solutions and operator reports. Keep the submission and
grade output outside the immutable packet. `--packet` verifies that the
packet still matches the packaged corpus.

The five live-service and one planted-code contracts can grade separately
collected submissions, but packet preparation does not deploy those targets.
Their target infrastructure is listed separately in the inventory. Exact
grading checks the track, finding keys and non-empty evidence fields; severity
differences are advisory. It does not establish evidence truth, execution
provenance, effective access or the quality of a human audit conclusion.

## External tools and existing integrations

The console unifies the available synthetic operation; it does not substitute
fake results for absent tools. The [lab reference](../lab/README.md) covers
WSL target provisioning and separately installed tools. Existing scanner,
network, MCP-server and real-agent integrations retain their installation,
endpoint and action-scope requirements. The inventory identifies their
admitted actions and operational coverage.

The extension catalog's maintenance tiers continue to describe upstream
integration support. Synthetic recipe availability is a separate, executable
property. This prevents a working parser scenario from being misrepresented
as a working upstream collector or scanner.

The following interfaces remain supported for existing integrations:

| Existing interface | Use |
|---|---|
| `exercise --flags` | Existing composed runner, battery and agent-head integrations. |
| `extension` and MCP | Exact admitted adapter and runtime contracts. |
| `learning` | Direct evidence-workflow APIs. |
| `exercise_operator` | Direct packet and grading APIs. |
| `score` | Envelope-rubric and exact finding-set comparison. |
| Governance and reader-safety checkers | Separate policy/integrity registers. |

Use the [extension CLI reference](extension-cli-reference.md) for those
contracts. The separately sealed Linux validator runtime is not the operator
wheel; its existing lock/rebuild requirements remain separate.
