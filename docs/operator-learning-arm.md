# Pack analysis with the learning-operator arm

`learning-operator.analyze_pack` accepts a pack report object with a `findings` array and returns a target-oriented analysis. It groups findings by target, keeps non-IP findings visible, and suggests follow-up checks. It does not run scanners or change targets. The human operator chooses any subsequent arm invocation.

Create an argument file from a report produced by the pack runner:

```json
{"report":{"run_id":"example","findings":[]}}
```

Run:

```sh
python -m extension invoke learning-operator analyze_pack --args-file analysis-args.json
```

The CLI returns a direct result with `ok`, `output`, and `error`. When `ok` is true, `output.assessment` contains the analysis. The same action is available through the MCP `invoke` tool with `id: "learning-operator"`, `action: "analyze_pack"`, and the argument object in `args`.

An optional `operator_evidence` object can attach observations to exact finding identities:

```json
{
  "report":{"findings":[]},
  "operator_evidence":{"schema":"specaudit.operator-evidence.v1","items":[]}
}
```

Each item names a finding by `check_id` and `record_locator`, plus a `kind` and `input`. Supported kinds include `graph`, `k8s`, `workpaper`, `detection`, and `agent`. The arm rejects mismatched or duplicate finding identities so observations are not attached to the wrong row. `learning-operator.list_tools` reports the action names and their argument keys.

The analysis records what the supplied report and evidence say; it cannot establish that an external source is authentic or that a finding remains true later. Its follow-up tasks are suggestions to the operator, not approvals or prerequisites for running an arm.
