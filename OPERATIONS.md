# Operating SpecAudit-CTF

The operator is accountable for choosing targets, credentials, tools, and conditions of use. SpecAudit-CTF reports actions and results; it does not decide permission or target eligibility. The packaged synthetic fixtures are the default CTF lane. If an operator configures a different host or endpoint, a concise warning may help them notice the change, but it must not block the action.

## Local setup

Install from the repository root with `pip install -e ".[dev]"`. Run `python -m extension list` to see catalog entries, `python -m extension availability` to see which handlers are configured, and `python -m extension describe ARM_ID` for an entry's current notes. Invoke a selected action with `python -m extension invoke ARM_ID ACTION '{"key":"value"}'`. `ok` reports whether the handler returned successfully; `output` and `error` carry the result.

Tool actions can read or change files, issue network requests, run subprocesses, or incur service cost. Check the selected adapter's arguments and the upstream tool's behavior when choosing an action. A missing binary, endpoint, credential, or required input is reported as an execution/configuration error. The tool does not infer permission from a catalog entry, a local IP address, or an environment variable.

## Run an exercise

`python -m extension.range` runs packaged synthetic fixtures. `python -m exercise --help` lists options for combining the range with challenge grading, selected arms, or an agent-head attempt. For example:

```sh
python -m exercise --found my-findings.json --expected challenges/telecom-aws-01-reachability/artifacts/expected-findings.json --out exercise-result.json
```

The optional `--battery` preset runs Checkov, Semgrep, and an ATT&CK demo lookup; Wapiti and Nmap also run when `LAB_TARGET_HOST` names a target. Missing tools or a missing target are recorded as skipped. A selected action that runs and fails is recorded as failed. Read each member's result rather than treating the combined status as proof of target coverage.

## After an attempt

Save the findings, exercise report, and useful tool output for review. Stop local services that were started for the challenge and reset any disposable files or accounts used by the selected tools. The [instructor guide](INSTRUCTOR_GUIDE.md) describes grading and feedback.
