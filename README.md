# SpecAudit-CTF

SpecAudit-CTF provides adapters for security tools, synthetic exercises,
challenge grading, and a stdio MCP interface. A competent operator chooses
the tool, action, inputs, and destination, and is accountable for using them
appropriately. The software reports the result of an invocation; it does not
decide whether a target is eligible or whether an operator has permission to
test it.

## Install

Python 3.11 or later is required.

```sh
pip install -e ".[dev]"
```

## Catalog and invocation

Run these commands from the repository root:

```sh
python -m extension list
python -m extension describe <arm-id>
python -m extension availability
python -m extension invoke <arm-id> <action> '{"key":"value"}'
```

`list` and `describe` show the catalog. `availability` reports which configured
arms can be reached on this host; it does not invoke them. `invoke` calls the
selected arm action with the supplied JSON object (omit it for `{}`). For
example:

```sh
python -m extension invoke agent-wiz list_tools
```

An invocation returns a JSON result with `ok`, `arm_id`, `action`, `output`,
and `error` fields. `ok` reports whether that action returned successfully; it
does not certify findings, prove what an upstream tool did beyond its returned
output, or make a target-eligibility decision. A nonzero command exit reports
an unsuccessful invocation. Unknown catalog entries, unsupported actions,
missing runtime configuration, and adapter-reported failures are returned as
errors. The action and adapter may have operational effects, including network
requests, local reads or writes, subprocesses, or service costs; inspect the
selected tool's own documentation and configuration before invoking it.

Argument files are also supported for local CLI use:

```sh
python -m extension invoke <arm-id> <action> --args-file request.json
```

The MCP server exposes `list`, `describe`, `invoke`, and `run_range`. Its
`invoke` tool returns the same action result in MCP tool content. Start it with:

```sh
python -m extension.mcp_server
```

The server uses stdio. Keep stdout reserved for MCP messages.

## Synthetic exercises and grading

`run_range` and `python -m extension.range` exercise shipped synthetic fixtures;
they do not contact live cloud environments. The `exercise` package composes
fixture runs, optional arm invocations, agent-head exercises, and challenge
grading into a report. See its command options with:

```sh
python -m exercise --help
python -m score --help
```

Challenge grading compares a submitted findings document with a challenge
contract. A grade is a result for that submission and contract, not evidence
that a live target was tested.

## Pack utilities

The scripts in [`tools/`](tools/README.md) operate on an explicitly supplied
external pack and evidence directory. They produce pack checks and analyses;
they do not select targets or establish an operator's authority.

## Package map

- [`extension/`](extension/README.md): adapter catalog, direct invocation, and
  MCP integration.
- `exercise/`, `exercise_operator/`, and `score/`: rehearsal and challenge
  grading.
- `extension/range/`: synthetic range fixtures and runner.
- `tools/`: pack evidence utilities.
