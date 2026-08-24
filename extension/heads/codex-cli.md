# Codex CLI

Attach this clone as arms and legs from Codex CLI.

The surface is `list`, `describe`, and `invoke` only. There is no inventory
server and no extra MCP tools.

## CLI

From the repository root:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}']
```

`invoke` is fail-closed: unknown ids, non-arms, non-curated rows, and
uninstalled curated arms are hard errors.

## MCP

Prefer a trusted project `.codex/config.toml` in this clone. Spawn the launcher
(it pins this clone on `sys.path`; do not use `python -m extension.mcp_server`
from another cwd):

```toml
[mcp_servers.specaudit-ctf]
command = "python"
args = ["extension/heads/codex-cli/launch_mcp.py"]
cwd = "."
```

Clone-root resolution precedence (launcher `launch_mcp.py:14`): file location
→ `SPECAUDIT_CTF_ROOT` → `CLAUDE_PROJECT_DIR`. A marketplace or cache copy
outside the clone must set `SPECAUDIT_CTF_ROOT` to the clone root.

If you instead use user-global `~/.codex/config.toml`, `cwd` must be the
absolute path of this clone:

```toml
[mcp_servers.specaudit-ctf]
command = "python"
args = ["extension/heads/codex-cli/launch_mcp.py"]
cwd = "/absolute/path/to/this/clone"
```

When the launcher is copied outside the clone, `args` must be an absolute
path to it (the launcher resolves the clone from its own location, not
`cwd`).

The bundled [codex-cli/.mcp.json](codex-cli/.mcp.json) runs `launch_mcp.py`
from the plugin directory. A marketplace/cache copy that is not inside the
clone needs `SPECAUDIT_CTF_ROOT` set to the clone root.

## Plugin and skill

Bundled layout:

- [codex-cli/.codex-plugin/plugin.json](codex-cli/.codex-plugin/plugin.json)
- [codex-cli/.mcp.json](codex-cli/.mcp.json)
- [codex-cli/launch_mcp.py](codex-cli/launch_mcp.py)
- [codex-cli/skills/specaudit-ctf/SKILL.md](codex-cli/skills/specaudit-ctf/SKILL.md)

Point a Codex plugin marketplace entry at `extension/heads/codex-cli`, or copy
the skill under `skills/specaudit-ctf/`. The skill tells the head to call only
`list`, `describe`, and `invoke`.
