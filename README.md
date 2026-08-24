# specaudit-ctf

## Overview

- **Arms**: 26 specialized adapters. None are held. A specialized
  handler is required; curated arms never ride a generic transport.
- **Legs / methodologies**: 19 methodology-only catalog rows
  (curriculum, spec, teach-only). They are not adapters.
- **Heads**: attach profiles for Claude Code CLI, Codex CLI, and
  other agent CLIs.
- **Range**: synthetic fixtures (`live_aws: false`). No live cloud.

`extension/coverage.yaml` classifies the landscape survey (45 ids,
frozen order). It is a **survey map**, not a ship list: a row is not
a promise that an adapter exists. In this cut every arm row is
curated (26) and every methodology-only row stays uncurated (19).

Per-arm caveats (composite egress, exploitation, LLM spend, source
mutation): [extension/README.md](extension/README.md).

## Install

Python 3.11 or later.

```text
pip install -e ".[dev]"
```

or:

```text
pip install -r requirements-dev.txt
```

`requirements-dev.txt` mirrors `[project]` plus
`[project.optional-dependencies] dev` in `pyproject.toml`. There is
no console script; operators use `python -m extension`.

## CLI

From the repository root:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}']
```

Examples:

```text
python -m extension describe burp-mcp
python -m extension invoke burp-mcp list_tools
python -m extension invoke burp-mcp url_encode '{"content": "hello world"}'
```

- `list`: catalog entries
- `describe <id>`: one catalog row
- `invoke <id> <action> [args]`: fail-closed tool call (optional JSON object)

Unknown ids, methodology-only rows, heads, non-curated arms, and
uninstalled curated arms are hard errors. Do not invent a fallback.

`invoke <id> list_tools` returns static JSON (no binary spawn) on
MCP arms and the nine lifted CLIs. Pyrit scenario discovery is a
separate `list_scenarios` action, which runs `pyrit_scan
--list-scenarios`. Original fixed-argv CLIs (checkov, garak,
mitreattack-python, wapiti, commix, zdns, vuls, stratus-red-team,
osmedeus) have no `list_tools`; their actions are in `describe` and
[extension/README.md](extension/README.md).

## MCP

Stdio server, **four tools only**: `list`, `describe`, `invoke`,
`run_range`. Do not add inventory, paging, or writeback.

```text
python -m extension.mcp_server
```

That import is only safe when the process cwd is this clone. Heads
should spawn the launcher so import does not depend on cwd:

```text
python extension/heads/claude-code/launch_mcp.py
python extension/heads/codex-cli/launch_mcp.py
```

A relocated launcher needs `SPECAUDIT_CTF_ROOT` set to this clone
root.

The shipped cap is four tools, including `run_range`. `run_range` is
the named exception to the original three-tool / "no new tools"
doctrine: synthetic, seed-stable fixtures, no path arguments,
curated `arm_ids` only, no file writes over MCP (`--out` stays
CLI-only). Cite it as a boundary, not a precedent.

## Heads

Attach profiles:

- [extension/heads/claude-code.md](extension/heads/claude-code.md)
- [extension/heads/codex-cli.md](extension/heads/codex-cli.md)
- [extension/heads/other-agent-cli.md](extension/heads/other-agent-cli.md)

Claude Code CLI, from this clone:

```text
claude mcp add --scope project --transport stdio specaudit-ctf -- python extension/heads/claude-code/launch_mcp.py
```

Codex CLI, project `.codex/config.toml` in this clone:

```toml
[mcp_servers.specaudit-ctf]
command = "python"
args = ["extension/heads/codex-cli/launch_mcp.py"]
cwd = "."
```

Another agent CLI or a validation client can wrap the same three CLI
subcommands, `python -m extension.range`, or the same stdio MCP
process. This tree does not ship a third named head profile.

## Range

```text
python -m extension.range
python -m extension.range --out range-result.json --seed 123
```

Fixtures `tf_s3_public_access` and `tf_iam_open` are synthetic. The
runner stamps `live_aws: false`. A missing curated arm is skipped; it
does not fail the fixture. A transport error is recorded as `error`,
not skipped.

## Dispatch doctrine

Read-only (or unarmed-default) is the first tier. Dispatch-class
actions — exploit run, scan launch, detonate, live DNS, page fetch,
AI/process, source mutation — are refused until the operator sets
`<ARM>_DISPATCH_SCOPE` to **explicit** CIDRs, IPs, hostnames, or URI
prefixes.

- Blanket scopes (`*`, `0.0.0.0/0`, `::/0`, prefixlen-0) are refused.
- Every allowed dispatch writes `[dispatch] <iso> arm=… action=…
  scope=… target=…` to stderr and stamps the Result.
- Path-scoped arms (`deepsec`, `vvah`, `ai-deep-sast`, `agent-wiz`):
  set `FOO_DISPATCH_SCOPE=localhost` (any explicit non-blanket
  hostname/CIDR/URI). Containment is `FOO_SCAN_ROOT`. **Do not put a
  repo path in the scope env** — `parse_scope` refuses it as not a
  CIDR, IP, hostname, or URI.

Safe default is unarmed: shipping 26 handlers does not fire a packet
until `*_BIN` (or endpoint) **and** (for dispatch) `*_DISPATCH_SCOPE`
are set.

Shared gate: `extension/arms/dispatch.py`. Caveats:
[extension/README.md](extension/README.md).

## Environment variables

| Env | Arm | Role |
| --- | --- | --- |
| `SPECAUDIT_CTF_ROOT` | launchers | clone root when a head launcher is relocated |
| `BURP_MCP_ENDPOINT` | burp-mcp | HTTP+SSE MCP URL |
| `SEMGREP_MCP_ENDPOINT` | semgrep-mcp | streamable-HTTP MCP URL |
| `CHECKOV_BIN` / `CHECKOV_SCAN_ROOT` | checkov | binary (or PATH); scan root **inside** the packaged range |
| `PROWLER_MCP_ENDPOINT` | prowler-mcp | HTTP+SSE MCP URL; also needs `AWS_ACCESS_KEY_ID` or `AWS_PROFILE` |
| `GARAK_BIN` / `GARAK_TARGET` / `GARAK_REPORT_DIR` | garak | binary; required target binding; JSONL report dir |
| `ZAP_API_ENDPOINT` / `ZAP_API_KEY` / `ZAP_DISPATCH_SCOPE` | zaproxy | native API base URL; optional API key; host-scoped dispatch |
| `WAPITI_BIN` / `WAPITI_DISPATCH_SCOPE` | wapiti | binary; host-scoped dispatch |
| `COMMIX_BIN` / `COMMIX_DISPATCH_SCOPE` | commix | binary; host-scoped dispatch |
| `MITREATTACK_BIN` | mitreattack-python | `attack-to-excel` binary (or PATH) |
| `VULS_BIN` / `VULS_DISPATCH_SCOPE` | vuls | binary; scope-presence dispatch (`scan`) |
| `STRATUS_BIN` / `STRATUS_DISPATCH_SCOPE` | stratus-red-team | binary; technique-bound dispatch |
| `OSMEDEUS_BIN` / `OSMEDEUS_DISPATCH_SCOPE` | osmedeus | binary; host-scoped dispatch |
| `ZDNS_BIN` / `ZDNS_DISPATCH_SCOPE` | zdns | binary; host-scoped lookup |
| `PAGE_FETCH_BIN` / `PAGE_FETCH_DISPATCH_SCOPE` | page-fetch | binary; URI-scoped fetch |
| `CALDERA_ENDPOINT` / `CALDERA_API_KEY` / `CALDERA_DISPATCH_SCOPE` | caldera | REST base URL; API key; operation dispatch |
| `GTI_MCP_ENDPOINT` | google-mcp-security | GTI MCP URL (read-only lookups; no dispatch tier) |
| `METASPLOIT_MCP_ENDPOINT` / `METASPLOIT_DISPATCH_SCOPE` | metasploit-mcp | SSE MCP URL; host/session-scoped execution |
| `ROUTERSPLOIT_BIN` / `ROUTERSPLOIT_DISPATCH_SCOPE` | routersploit | binary; host-scoped `run` |
| `SNIPER_BIN` / `SNIPER_DISPATCH_SCOPE` | sniper | binary; host-scoped `scan` |
| `ZGRAB2_BIN` / `ZGRAB2_DISPATCH_SCOPE` | zgrab2 | binary; host-scoped stdin scan |
| `DARK_MOON_BIN` / `DARK_MOON_DISPATCH_SCOPE` | dark-moon | shell launcher; host-scoped `campaign`/`run` |
| `PYRIT_BIN` / `PYRIT_DISPATCH_SCOPE` | pyrit | `pyrit_scan`; host/URL-scoped `scan` |
| `DEEPSEC_BIN` / `DEEPSEC_SCAN_ROOT` / `DEEPSEC_DISPATCH_SCOPE` | deepsec | real `deepsec` binary (**not** npx/pnpm/npm/yarn); workspace dir with config (cwd); arm `DEEPSEC_DISPATCH_SCOPE=localhost` |
| `VVAH_BIN` / `VVAH_SCAN_ROOT` / `VVAH_DISPATCH_SCOPE` / `VVAH_ALLOW_REMEDIATE` | vvah | binary; path root (cwd); arm `VVAH_DISPATCH_SCOPE=localhost`; S10 extra gate `=1` |
| `AI_DEEP_SAST_BIN` / `AI_DEEP_SAST_DEEPSCAN_BIN` / `AI_DEEP_SAST_SCAN_ROOT` / `AI_DEEP_SAST_DISPATCH_SCOPE` / `AI_DEEP_SAST_SEMGREP_CONFIG` | ai-deep-sast | binaries; path root (cwd); local ruleset inside the root; arm `AI_DEEP_SAST_DISPATCH_SCOPE=localhost` |
| `AGENT_WIZ_BIN` / `AGENT_WIZ_SCAN_ROOT` / `AGENT_WIZ_DISPATCH_SCOPE` | agent-wiz | binary; path root (cwd); arm `AGENT_WIZ_DISPATCH_SCOPE=localhost` |
| `OPENAI_API_KEY` | agent-wiz | required for `analyze`; presence-checked, never logged |

Missing `*_BIN` **and** missing PATH → `installed()` is false. A
binary on PATH without `*_BIN` does install (checkov/wapiti pattern).
Path-scoped `*_DISPATCH_SCOPE` is a dummy explicit hostname
(`localhost`); putting a filesystem path there is refused.

## Develop

```text
python -m pip install -e ".[dev]"
python -m pytest tests/ -q
```

Tests are hermetic. They do not need a live scanner or a live cloud
account.

Operator detail: [extension/README.md](extension/README.md).
