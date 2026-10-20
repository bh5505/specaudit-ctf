# SpecAudit-CTF program

SpecAudit-CTF is a lab CTF toolkit. It ships synthetic range fixtures, challenge contracts, a findings grader, tool adapters, and a stdio MCP server. The operator chooses targets and actions and is accountable for using the tools. The software reports what it ran and what the handlers returned; it does not grant or judge permission to test a target.

## What is here

- [Challenges](challenges/README.md) contain learner briefs, planted fixtures or lab services, expected findings, and walkthroughs.
- [The range](extension/README.md#synthetic-range) evaluates local synthetic fixtures and reports exposure, paths, and impact.
- [The score command](README.md#synthetic-exercises-and-grading) compares submitted findings with an expected-findings contract.
- [The extension](extension/README.md) lists and invokes installed tool adapters through the CLI or MCP. An adapter can read files, contact an endpoint, run a scanner, write output, or incur service cost according to the selected action.
- [The exercise runner](OPERATIONS.md#run-an-exercise) composes range, grading, optional arms, and an optional agent-head attempt.

## Where to start

Install the package as described in the [README](README.md#install), run `python -m extension.range`, then work through [telecom-aws-01-reachability](challenges/telecom-aws-01-reachability/README.md). Use `python -m score --grade FOUND.json --expected CONTRACT.json` to check a submission. The [curriculum](CURRICULUM.md) lists a practical sequence; the [instructor guide](INSTRUCTOR_GUIDE.md) describes exercise setup and review.

An operator may use the tool adapters with a lab target or another target they select. A warning that a configured target differs from the intended lab lane is information for that operator, not an ignition interlock. [Operations](OPERATIONS.md) covers command setup, output, and cleanup without turning the software into a permission authority.
