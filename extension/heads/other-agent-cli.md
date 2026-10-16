# Other agent CLI

Another agent CLI that already has its own tools can attach the same surface.
A validation client may do the same. The runner's real-head mode carries
three armed head profiles (claude-code, codex-cli, and — since the
2026-09-06 content-growth packet — qwen-code, the gemini-lineage CLI):
each spawns headless only when its `EXERCISE_HEAD_*_CMD` env names the
binary. A FOURTH CLI needs its own per-CLI wiring in `exercise/real_head.py`
before the runner can drive it; below is the manual attachment path that
requires no runner support at all.

Use the CLI:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}']
```

Or spawn the stdio MCP server and call only these tools. From another cwd use
a head launcher so import does not depend on cwd:

```text
python extension/heads/claude-code/launch_mcp.py
```

`python -m extension.mcp_server` is only safe when the process cwd is this
clone. A relocated launcher needs `SPECAUDIT_CTF_ROOT` set to the clone root.

- `list` — catalog rows (includes `tier`)
- `describe` — one row by `id` (includes `tier`)
- `invoke` — curated installed arm that is not held (`id`, `action`, `args`)
- `run_range` — synthetic fixtures (`seed`, optional `arm_ids`). Omit
  `arm_ids` to auto-discover (typically `degraded`); `arm_ids: []` may
  be `complete`

Do not add inventory, paging, or writeback tools on this process. If the other
CLI already speaks MCP, point it at the same command claude-code and qwen-code
are wired with (the shared `extension/heads/claude-code/launch_mcp.py` stdio
launcher); codex-cli is the exception that uses its host-config server block
instead. If it already has a tool runner, wrap the three CLI
subcommands plus `python -m extension.range`.

## Headless attempt (exercise head lane)

A validation client can play the same attempt game: set
`SPECAUDIT_CTF_MCP_TRACE`, `SPECAUDIT_CTF_MCP_TRACE_KEY` (64 hex), and
optionally `SPECAUDIT_CTF_MCP_TRACE_ATTEMPT` in the SERVER process's
environment, attempt a challenge over the four tools, and write your
findings to `<attempt-dir>/found.json`. The server writes the trace;
`python -m exercise --attempt-dir <dir> --expected <contract>` grades
the attempt from server-side evidence. The repo's own deterministic
client is `python -m exercise.fake_head` (personas `competent`,
`blind-zero`, `blind-irrelevant`) — use it as the reference for what a
gradable attempt looks like.
