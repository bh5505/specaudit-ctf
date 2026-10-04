# specaudit-ctf

Operate synthetic security scenarios through **`python -m exercise`**. One
console inventories capabilities, prepares an operation, executes admitted
adapters against packaged synthetic inputs, retains evidence, and verifies
results. Challenge preparation and submission grading use the same console.

## Start an operation

Install with Python 3.11+ in a virtual environment:

```sh
pip install .
python -m exercise inventory
python -m exercise plan --out operation-plan.json
python -m exercise run --plan operation-plan.json --out operation-001
python -m exercise status operation-001
python -m exercise report operation-001
```

Use fresh plan/output paths. The default operation uses local synthetic range
inputs and does not require cloud credentials, a model provider, an external
scanner, or the WSL lab. Read the [operator console procedure](docs/operations-console.md)
for selecting scenarios, editing inputs, interpreting assessments, and retaining
or grading results. The inventory identifies capabilities that need separate
software or target infrastructure; selecting a supported local scenario does
not silently enable those dependencies.

## Operator workflow

| Task | Canonical interface |
|---|---|
| Discover available scenarios, adapters and challenge lanes | `python -m exercise inventory` |
| Inspect and save the intended operation | `python -m exercise plan` |
| Execute and retain per-step evidence | `python -m exercise run` |
| Verify a saved operation | `python -m exercise status` |
| Inspect verified assessments and failures | `python -m exercise report` |
| Export a challenge packet | `python -m exercise prepare` |
| Grade a submitted finding set | `python -m exercise grade` |

Execution completion, assessment findings, and a participant's grade are
separate results. A completed adapter can report a vulnerability, a blocked
path, or a detection gap. The operation report preserves those results rather
than treating successful execution as a clean security assessment.

## Overview

The underlying extension contains 49 adapters and 19 methodology-only catalog
entries. Its admission, scope and support-tier contracts continue to apply.
The console's synthetic execution coverage describes what can run now; a
catalog support tier describes the underlying integration's maintenance and
validation status. `inventory` makes these distinctions visible alongside the
runnable scenarios instead of requiring an operator to assemble several CLIs.
See [adapter contracts](extension/README.md) for lower-level integration details.

## Documentation map

- [Operator console](docs/operations-console.md): the executable synthetic-range procedure.
- [Operations policy](OPERATIONS.md): environment selection, authority, containment and custody.
- [Challenges](challenges/README.md): finding contracts and challenge-specific evidence.
- [Extension reference](extension/README.md): adapter actions, MCP and source limitations.
- [Lab reference](lab/README.md): optional WSL targets and separately installed upstream tools.

## Learning program

[Program](PROGRAM.md), [curriculum](CURRICULUM.md), and the
[instructor guide](INSTRUCTOR_GUIDE.md) describe learning objectives, assessment
roles and future coverage. They are reference material for designing exercises;
the operator console and its inventory define the executable workflow.
Historical candidate surveys and proposed modules do not add runtime capability.

## Install

`pip install .` installs the operator console and its packaged synthetic data.
For development, use `pip install -e ".[dev]"` or
`pip install -r requirements-dev.txt`. The established `extension`, `learning`,
`exercise_operator`, `score`, and legacy `exercise --flags` interfaces remain
available for compatibility and specialized integrations. New operator runs
start with the console above; the sections below document lower-level contracts.

## Integration reference

The low-level contracts live in the [extension CLI reference](docs/extension-cli-reference.md).
Existing section links below remain available for integrations.

## Validator runtime

See [Validator runtime](docs/extension-cli-reference.md#validator-runtime).

## CLI

See [CLI](docs/extension-cli-reference.md#cli).

## MCP

See [MCP](docs/extension-cli-reference.md#mcp).

## Heads

See [Heads](docs/extension-cli-reference.md#heads).

## Range

See [Range](docs/extension-cli-reference.md#range).

## Scoring runs

See [Scoring runs](docs/extension-cli-reference.md#scoring-runs).

## Web testing (DAST) role

See [Web testing (DAST) role](docs/extension-cli-reference.md#web-testing-dast-role).

## On Kali

See [On Kali](docs/extension-cli-reference.md#on-kali).

## Remote-read admission

See [Remote-read admission](docs/extension-cli-reference.md#remote-read-admission).

## Dispatch doctrine

See [Dispatch doctrine](docs/extension-cli-reference.md#dispatch-doctrine).

## Environment variables

See [Environment variables](docs/extension-cli-reference.md#environment-variables).

## Develop

See [Develop](docs/extension-cli-reference.md#develop).
