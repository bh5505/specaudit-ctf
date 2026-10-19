# Claude Code CLI

Attach this clone as arms and legs from Claude Code CLI.

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

## Headless attempt (exercise head lane)

The exercise runner can drive this head itself when the host is armed
(`EXERCISE_HEAD_CLAUDE_CODE_CMD` names the binary; see
`exercise/real_head.py` — the runner composes the incantation below,
including the private `--mcp-config`). To run it by hand, the three
trace env vars must reach the MCP server process this CLI spawns.
Parent-env inheritance is not a documented guarantee — inject
explicitly:

- pass `-e SPECAUDIT_CTF_MCP_TRACE=<path> -e SPECAUDIT_CTF_MCP_TRACE_KEY=<hex>`
  (and optionally `SPECAUDIT_CTF_MCP_TRACE_ATTEMPT`) on the `claude -p`
  command line, or set them in the server's `env` map in the
  project `.mcp.json` / `claude mcp add --env`;
- bound the run: `claude -p "<attempt prompt>" --output-format json
  --max-turns <n> --allowedTools "mcp__specaudit-ctf__*"` (allow
  wildcards need the fixed server name);
- the attempt prompt ends with the head writing its found findings to
  `<attempt-dir>/found.json`; the trace is written by the server;
- grade with `python -m exercise --attempt-dir <dir> --expected
  <contract>` (key in `SPECAUDIT_CTF_MCP_TRACE_KEY`).

### Runner child environment (bounded)

The runner does not copy its ambient environment into the head. It spawns
`claude` with an explicit allowlist: base names that locate the binary and
per-user CLI state (`PATH`, `HOME`/Windows profile names, config/temp/locale
names) plus this head's explicit auth/config names (`ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `CLAUDE_CODE_OAUTH_TOKEN`,
`CLAUDE_CONFIG_DIR`, and the `CLAUDE_CODE_USE_BEDROCK` /
`CLAUDE_CODE_USE_VERTEX` selectors). AWS credentials are copied only when
`CLAUDE_CODE_USE_BEDROCK` selects Bedrock; Google credentials only when
`CLAUDE_CODE_USE_VERTEX` selects Vertex. File-backed logins continue to work
through `HOME`/config names. Explicit operator opt-in below can also pass a
provider credential without a selector; the operator must ensure it is meant
for this head.

The minted trace facts travel in the private `--mcp-config` per-server `env`
map, never in the head's environment. Stale `SPECAUDIT_CTF_MCP_TRACE*`
values, `EXERCISE_HEAD_*` arming/control values, unrelated ambient
credentials, proxies, and loader/injection variables are not copied by default.

An operator may opt in additional credential/configuration env NAMES with
`EXERCISE_HEAD_EXTRA_ENV` (comma/whitespace separated; at most 64 names and
32 KiB of copied names/values; total child environment at most 128 KiB).
Trace, arming/control, loader/injection, base/head-auth, and arbitrary proxy
names are reserved. `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and `ALL_PROXY`
may be named explicitly for proxy-only hosts; lowercase spellings also work
when named and present with the same spelling on POSIX. Excess copies
fail before any spawn. Values are copied verbatim from the runner environment and are
never written into the argv, MCP, or attempt fields. The retained child
stderr tail (at most 400 characters, only on failure or a non-zero exit) is
scrubbed of copied secret values and credential-file paths. All opt-in
values are treated as sensitive, including proxy/configuration values. If any
copied sensitive value is shorter than 8 characters, the whole stderr tail is
suppressed.
The operator owns their authorization and custody, and a credential file
still needs separate containment.

This bounds the child's initial environment only. It is not an OS sandbox and
makes no file, network, cwd, descendant, or in-flight containment claim.

## Plugin and skill

Bundled layout:

- [claude-code/.claude-plugin/plugin.json](claude-code/.claude-plugin/plugin.json)
- [claude-code/.mcp.json](claude-code/.mcp.json)
- [claude-code/launch_mcp.py](claude-code/launch_mcp.py)
- [claude-code/skills/specaudit-ctf/SKILL.md](claude-code/skills/specaudit-ctf/SKILL.md)

Install from this directory (`--plugin-dir extension/heads/claude-code`) or
treat the skill as a project skill. The skill tells the head to call only
`list`, `describe`, `invoke`, and `run_range`.
