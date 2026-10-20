# Codex CLI

The CTF exposes four MCP tools: `list`, `describe`, `invoke`, and `run_range`.
The operator selects an arm, its inputs, and any target. From the checkout:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}']
```

Attach the MCP launcher to Codex through a project or user-level
`config.toml`. The launcher path and `cwd` must resolve to this checkout:

```toml
[mcp_servers.specaudit-ctf]
command = "python"
args = ["extension/heads/codex-cli/launch_mcp.py"]
cwd = "/absolute/path/to/this/checkout"
```

The exercise runner can launch an installed `codex` CLI when the operator
selects `--head codex-cli --head-execute` and supplies an attempt prompt,
attempt directory, and expected-findings file. `EXERCISE_HEAD_CODEX_CLI_CMD`
optionally names a different executable. Codex must forward the three
server-trace variables through its MCP configuration:

```toml
env_vars = [
  "SPECAUDIT_CTF_MCP_TRACE",
  "SPECAUDIT_CTF_MCP_TRACE_KEY",
  "SPECAUDIT_CTF_MCP_TRACE_ATTEMPT",
]
```

The runner provides fresh trace values to the Codex child, records the
server-side trace, and grades the `found.json` submission. It passes the
current process environment to the child after replacing stale CTF trace
variables. A manually run attempt uses the same trace variables and can be
graded with:

```text
python -m exercise --attempt-dir <dir> --expected <contract>
```

The [bundled plugin](codex-cli/) contains the launcher, MCP config, manifest,
and CTF skill. The skill describes the tools and the operator's
responsibility for their use.
