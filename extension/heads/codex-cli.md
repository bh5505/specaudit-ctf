# Codex CLI

Attach this clone as arms and legs from Codex CLI.

The surface is `list`, `describe`, `invoke`, and `run_range`. There is no
inventory server and no extra MCP tools.

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

## Headless attempt (exercise head lane)

Codex forwards parent env to stdio MCP servers only through an
allowlist, so the trace vars must be named in the server's config
block (user-global `~/.codex/config.toml` — project config cannot
define providers/env forwarding). Values come from the codex
process's own environment:

```toml
[mcp_servers.specaudit-ctf]
command = "python"
args = ["extension/heads/codex-cli/launch_mcp.py"]
cwd = "."
env_vars = [
  "SPECAUDIT_CTF_MCP_TRACE",
  "SPECAUDIT_CTF_MCP_TRACE_KEY",
  "SPECAUDIT_CTF_MCP_TRACE_ATTEMPT",
]
```

(Pin exact values instead with `[mcp_servers.specaudit-ctf.env]` —
but a pinned key readable from the clone config defeats the chain's
grading-side-only property; prefer the allowlist form with the key
exported only where codex runs.)

Run out-of-band, bounded:

```text
codex exec --sandbox read-only "<attempt prompt ending in: write your
found findings to <attempt-dir>/found.json>"
```

The trace is written by the MCP server; the head only writes
`found.json`. Grade with `python -m exercise --attempt-dir <dir>
--expected <contract>` (key in `SPECAUDIT_CTF_MCP_TRACE_KEY` on the
grading side).

## Plugin and skill

Bundled layout:

- [codex-cli/.codex-plugin/plugin.json](codex-cli/.codex-plugin/plugin.json)
- [codex-cli/.mcp.json](codex-cli/.mcp.json)
- [codex-cli/launch_mcp.py](codex-cli/launch_mcp.py)
- [codex-cli/skills/specaudit-ctf/SKILL.md](codex-cli/skills/specaudit-ctf/SKILL.md)

Point a Codex plugin marketplace entry at `extension/heads/codex-cli`, or copy
the skill under `skills/specaudit-ctf/`. The skill tells the head to call only
`list`, `describe`, `invoke`, and `run_range`.
