# Claude Code CLI

Attach this clone as arms and legs from Claude Code CLI.

The surface is `list`, `describe`, and `invoke` only. There is no inventory
server and no extra MCP tools.

## CLI

From the repository root:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}']
```

`invoke` is fail-closed: unknown ids, non-arms, held rows, non-curated
rows, and uninstalled curated arms are hard errors. `list` / `describe`
include `tier`.

## MCP

Prefer a project-scoped server in this clone. Spawn the launcher (it pins this
clone on `sys.path`; do not use `python -m extension.mcp_server` from another
cwd):

From the repository root:

```text
claude mcp add --scope project --transport stdio specaudit-ctf -- python extension/heads/claude-code/launch_mcp.py
```

Or put this in the clone’s project `.mcp.json`:

```json
{
  "mcpServers": {
    "specaudit-ctf": {
      "command": "python",
      "args": ["${CLAUDE_PROJECT_DIR}/extension/heads/claude-code/launch_mcp.py"]
    }
  }
}
```

The bundled [claude-code/.mcp.json](claude-code/.mcp.json) uses
`${CLAUDE_PLUGIN_ROOT}/launch_mcp.py` and sets `SPECAUDIT_CTF_ROOT` /
`PYTHONPATH` to `${CLAUDE_PROJECT_DIR}` so a plugin-dir or marketplace copy
still imports this clone when the project is the clone. If those files are
outside the clone, set `SPECAUDIT_CTF_ROOT` to the clone root.

## Plugin and skill

Bundled layout:

- [claude-code/.claude-plugin/plugin.json](claude-code/.claude-plugin/plugin.json)
- [claude-code/.mcp.json](claude-code/.mcp.json)
- [claude-code/launch_mcp.py](claude-code/launch_mcp.py)
- [claude-code/skills/specaudit-ctf/SKILL.md](claude-code/skills/specaudit-ctf/SKILL.md)

Install from this directory (`--plugin-dir extension/heads/claude-code`) or
treat the skill as a project skill. The skill tells the head to call only
`list`, `describe`, and `invoke`.
