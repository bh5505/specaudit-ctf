# Other agent CLI

Another agent CLI that already has its own tools can attach the same surface.
A validation client may do the same. This tree does not ship a third named
head profile.

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

Do not add inventory, paging, or writeback tools on this process. If the other
CLI already speaks MCP, point it at the same command used by Claude Code CLI
and Codex CLI. If it already has a tool runner, wrap the three CLI
subcommands.
