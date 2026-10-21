# Other agent CLIs

An agent CLI can use the same four MCP tools: `list`, `describe`, `invoke`,
and `run_range`. The operator selects the arm, inputs, and target. From this
checkout, the direct CLI has the same handlers:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}']
```

A CLI with MCP support can spawn
`extension/heads/claude-code/launch_mcp.py` as a stdio server. When the
launcher is outside this checkout, set `SPECAUDIT_CTF_ROOT` to this
checkout's absolute path. A CLI with its own tool runner can call the direct
CLI commands.

The exercise runner supports `claude-code`, `codex-cli`, and `qwen-code` as
real heads. Select one with `--head <name> --head-execute`; the corresponding
`EXERCISE_HEAD_*_CMD` variable is an optional executable override. For a
manual attempt, pass `SPECAUDIT_CTF_MCP_TRACE`,
`SPECAUDIT_CTF_MCP_TRACE_KEY`, and optionally
`SPECAUDIT_CTF_MCP_TRACE_ATTEMPT` to the MCP server process. Submit
`found.json` in the attempt directory and grade with:

```text
python -m exercise --attempt-dir <dir> --expected <contract>
```

The runner passes the current process environment to a launched head after
replacing stale CTF trace variables. The trace and grade describe what the
attempt did; they do not decide how the operator may use the tool.
