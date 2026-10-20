# Claude Code CLI

The CTF exposes four MCP tools: `list`, `describe`, `invoke`, and `run_range`.
The operator selects an arm, its inputs, and any target. From the checkout:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}']
```

To attach the MCP server to Claude Code from this checkout:

```text
claude mcp add --scope project --transport stdio specaudit-ctf -- python extension/heads/claude-code/launch_mcp.py
```

The [bundled plugin config](claude-code/.mcp.json) provides the same
launcher. If the launcher is copied outside the checkout, set
`SPECAUDIT_CTF_ROOT` to this checkout's absolute path.

The exercise runner can launch an installed `claude` CLI when the operator
selects `--head claude-code --head-execute` and supplies an attempt prompt,
attempt directory, and expected-findings file. `EXERCISE_HEAD_CLAUDE_CODE_CMD`
optionally names a different executable. The runner writes a temporary MCP
config, passes its own prompt trailer asking for `found.json`, records the
server-side trace, and grades the submission. It passes the current process
environment to the child after replacing stale CTF trace variables.

For a manual attempt, arrange for `SPECAUDIT_CTF_MCP_TRACE`,
`SPECAUDIT_CTF_MCP_TRACE_KEY`, and optionally
`SPECAUDIT_CTF_MCP_TRACE_ATTEMPT` to reach the MCP server process. Write
`found.json` in the attempt directory, then grade with:

```text
python -m exercise --attempt-dir <dir> --expected <contract>
```

The plugin layout is [claude-code/](claude-code/): its launcher, MCP config,
plugin manifest, and CTF skill. The skill describes these tool functions and
the operator's responsibility for their use.
