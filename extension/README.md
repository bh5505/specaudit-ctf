# Extension

The extension package connects catalogued arms to their configured command,
HTTP, or in-process handlers. It exposes direct CLI and stdio MCP invocation.
The operator chooses what to run and is accountable for the target and inputs.
The extension reports an action result; it does not grant permission, decide
target eligibility, or certify that an operation is authorized.

## Catalog and availability

From the repository root:

```sh
python -m extension list
python -m extension describe <arm-id>
python -m extension availability
```

The catalog includes invocable arms as well as descriptive entries. `describe`
shows the selected entry's notes. `availability` checks whether configured
handlers can be reached on the current host; it does not invoke them or assess
whether they are suitable for a particular target.

Rows with `kind: methodology-only` are references to external methodology,
never invocable: no handler is registered, and `invoke` refuses them with the
same generic non-arm failure as any other non-arm id. The catalog id `foundry`
names an open agentic-security evaluation specification; it is not the Foundry
Solidity toolchain referenced by Solidity challenges.

## Invoke an arm

Pass action arguments as a JSON object, either inline or in a local file:

```sh
python -m extension invoke <arm-id> <action> '{"key":"value"}'
python -m extension invoke <arm-id> <action> --args-file request.json
```

Omitting the arguments passes an empty object. A completed CLI invocation
prints a JSON result with this shape:

```json
{
  "action": "list_tools",
  "arm_id": "agent-wiz",
  "error": null,
  "ok": true,
  "output": {}
}
```

The actual `output` depends on the selected arm and action. `ok` reflects the
handler's reported outcome. A false value or nonzero process exit indicates
failure; a true value does not establish that an external system changed as
intended, that returned evidence is complete, or that the operator was
authorized. Unknown entries, entries that cannot be invoked, unsupported
actions, invalid arguments, missing configuration, and handler errors are
reported as failures rather than replaced with a different action.

An arm may have action-specific requirements such as a binary, endpoint,
credential, input file, or configuration value. Those requirements enable the
operation; they do not transfer responsibility for selecting or authorizing a
target to the software. Review the arm's implementation and upstream tool
documentation before use, especially when an action can make network requests,
write files, start subprocesses, or incur service costs.

The shared invocation contract is implemented in [`contract.py`](contract.py)
and [`dispatch.py`](dispatch.py). Individual adapters and their configuration
are under [`arms/`](arms/). The catalog is in [`coverage.yaml`](coverage.yaml).

## MCP

Start the stdio server from the repository root:

```sh
python -m extension.mcp_server
```

It exposes four tools: `list`, `describe`, `invoke`, and `run_range`. The
`invoke` tool takes an `id`, `action`, and optional object-valued `args`; its
content contains the direct action result shown above. MCP's `isError` flag is
a transport-level indication that the invocation returned an error. It does
not add an authorization or target-suitability decision.

For agent-head launch configuration, see the profiles under
[`heads/`](heads/). Keep the server's stdout reserved for MCP protocol
messages.

## Synthetic range

The range runner uses the fixtures in [`range/`](range/). Run it with:

```sh
python -m extension.range
```

These fixtures are synthetic and do not contact live cloud environments.
Range output summarizes fixture execution and any requested arm results; it
does not certify a live assessment.
