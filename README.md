# specaudit-ctf

## Overview

- **Arms**: 27 specialized adapters. HTTP MCP rows are held; remaining
  arm rows are research except the agent-wiz read tier
  (`agent-wiz.list_tools`), the sole maintained capability (X5-PROMOTE).
  A specialized handler is
  required; curated arms never ride a generic transport. `curated` is a
  deprecated compatibility flag and does not mean maintained.
- **Legs / methodologies**: 19 methodology-only catalog rows
  (curriculum, spec, teach-only). They are not adapters.
- **Heads**: attach profiles for Claude Code CLI, Codex CLI, and
  other agent CLIs.
- **Range**: synthetic fixtures (`live_aws: false`). No live cloud.

`extension/coverage.yaml` classifies the landscape survey (45 ids,
frozen order). It is a **survey map**, not a ship list: a row is not
a promise that an adapter exists. Every row has a support tier
(`research` | `experimental` | `maintained` | `held`). In this cut
every arm row is curated (27 handlers) and every methodology-only
row stays uncurated (19). `curated` is not `maintained`.

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

## Validator runtime

The X3 runtime builder produces a real, relocatable Linux x86-64 GNU CPython
bundle for the validator-owned `agent-wiz.list_tools` path. Fetching locked
inputs is explicit; assembly, verification, archive round-trip, and Mode-A
smoke are offline. Generated runtimes are not committed. See
[runtime/README.md](runtime/README.md) for the lock, reproducibility,
installation, rotation, and rollback contract.

## CLI

From the repository root:

```text
python -m extension list
python -m extension describe <id>
python -m extension invoke <id> <action> ['{"k":"v"}'] [--attempt-id attempt-<hex>] [--artifact-dir ABSOLUTE_DIR]
```

Examples:

```text
python -m extension describe burp-mcp
python -m extension describe checkov
python -m extension invoke agent-wiz list_tools
```

- `list`: catalog entries (catalog JSON)
- `describe <id>`: one catalog row (catalog JSON)
- `invoke <id> <action> [args]`: fail-closed tool call (optional JSON object).
  Stdout is `specaudit.ctf.execution-result.v1`. Process exit 0 is not
  `complete`. `transport_ok` is informational: it means the tool
  invocation/response transport succeeded, not that artifact custody
  succeeded. Optional `--attempt-id attempt-<64 lowercase hex>` is echoed
  on every structurally valid result for that attempt. Optional
  `--artifact-dir ABSOLUTE_DIR` is a validator-owned response channel
  (not profile `local-write`): it requires a valid attempt id and a
  fresh empty per-attempt Unix directory that already exists and is not
  a symlink. The producer binds that directory before dispatch and writes
  claimed artifact bytes under a digest-derived name relative to the
  bound descriptor. Mode A artifact custody is Unix-only. Malformed
  attempt ids, invalid or non-empty artifact directories, and unsupported
  Mode-A platforms fail before execution and may report only on stderr
  (no result envelope). Omit both flags for Mode B (portable; no
  `attempt_id`, no artifact files).

X2-PUB admits the explicit in-process `list_tools` profiles for
`agent-wiz`, `ai-deep-sast`, `dark-moon`, `deepsec`, `pyrit`,
`routersploit`, `sniper`, `vvah`, `zgrab2`, and `nmap`. These profiles
read static policy metadata and do not spawn the upstream binary. Every
other CLI invoke action is refused before `Extension.invoke` until it has
authoritative per-action safety, scope, side-effect, budget, cleanup, and
tool-version metadata.

Dispatch-class admission (2026-09-01, continued 2026-09-02) adds exactly
nine scope-gated profiles — `nmap.scan`, `zaproxy.ascan_scan`,
`zaproxy.spider_scan`, `zgrab2.scan`, `wapiti.scan`, `zdns.lookup`,
`pyrit.scan`, `routersploit.run`, `osmedeus.scan` — carrying honest
manifest truth: safety class **R1**, declared side effects
(`subprocess`+`network-egress` for the CLI arms; `network-egress` for
the ZAP API), `default_off` with `approval_ref` naming the operator's
`*_DISPATCH_SCOPE` gate and `roe_ref` naming the dispatch doctrine, and
`synthetic_only: false` (the operator arms a real lab target).
Admission is metadata, not authority: each arm's own scope gate, audit
line, and stamp remain the enforcement point, and an unarmed or
out-of-scope dispatch is a typed evaluated failure — never an
all-clear. Three admitted actions deserve their caveats read aloud:
`pyrit.scan` spends model tokens on the operator-configured endpoints
(the manifest's `network-egress` names the transport, not the spend);
`routersploit.run` **always executes the module** upstream — there is
no check-only path; `osmedeus.scan` composes many external tools whose
egress is not bounded by the named target (the operator arming the
scope accepts that composite egress). `wapiti` and `zdns` have no
read-only mode upstream — their dispatch action is the arm's whole
surface; `sniper` stays deliberately unadmitted (root-only community
binary, phones home when armed, unbounded sub-tool egress).

Unknown ids, unmanifested actions, methodology-only rows, heads, held arms,
non-curated arms, and uninstalled curated arms are hard errors. Do not invent
a fallback. `list` / `describe` include `tier`.

`invoke <id> list_tools` returns static JSON (no binary spawn) on
non-held surfaces that implement it (the nine lifted CLIs). Catalog
`invoke` of held HTTP MCP rows (`burp-mcp`, `semgrep-mcp`,
`prowler-mcp`, `google-mcp-security`, `metasploit-mcp`) is refused
even if an endpoint is configured; handler-level `list_tools` is not
reachable through catalog/CLI/MCP invoke. Pyrit scenario discovery is a
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

X4-PUB transport contract:

- `invoke` and `run_range` return the same
  `specaudit.ctf.execution-result.v1` envelopes as the CLI JSON
  output for the same logical request (timestamps differ per run);
  both transports share one dispatch, and
  `tests/goldens/transport-parity/matrix.json` is the frozen parity
  matrix.
- `isError` on a tool result mirrors the CLI process exit code
  (nonzero exit = `isError: true`). It is a transport signal; the
  verdict vocabulary (`complete` / `degraded` / `failed`) lives in
  the envelope status only.
- Optional `attempt_id` / `artifact_dir` tool arguments carry the
  same Mode A contract as `--attempt-id` / `--artifact-dir`
  (invalid forms are JSON-RPC `-32602`, never an envelope).
- Framing is newline-delimited JSON per the MCP stdio transport
  (spec revision 2025-11-25); legacy Content-Length input is
  rejected as a parse error, messages are capped at 1 MiB, and the
  initialize handshake echoes a supported requested protocol version
  or answers with the latest supported one.

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
python -m extension.range --arm-ids "" --seed 7
python -m extension.range --attempt-id attempt-<hex> --artifact-dir ABSOLUTE_DIR
```

Fixtures `tf_s3_public_access` and `tf_iam_open` are synthetic. CLI
stdout and `--out` are `specaudit.ctf.execution-result.v1`. Mode A
(`--artifact-dir`) emits the envelope only on stdout: `--out` combined
with `--artifact-dir` is rejected before range execution and may report
only on stderr. The artifact directory must be a fresh empty private
per-attempt Unix directory; the producer binds it before dispatch.
Process exit 0 if and only if the outer envelope `status` is
`complete`; inner `ok` does not decide it. `transport_ok` is
informational: it means the tool invocation/response transport
succeeded, not that artifact custody succeeded. Library `run_range()`
still returns seed-stable `range.lifecycle.v2` with
`live_aws: false`. The inner lifecycle document is coverage input and
a `range-report` artifact digest, not a second all-clear: inner `ok`
is not the outer status. `--seed` applies to that inner run. Document
and fixture `status` is `complete`, `degraded`, or `failed`;
compatibility `ok` is true only when `status` is `complete`. A skipped
or erroring arm cannot be `complete`. Omit `arm_ids` (auto-discover) to
treat curated arms as optional (`degraded` on skip/error). Explicit
non-empty `arm_ids` are required (`failed` on skip/error). Explicit
empty `arm_ids=()` has no arms and may be `complete` when lifecycle
matches. Lifecycle `matched_expected` is independent — a match cannot
hide an arm skip/error. Default CLI omits `arm_ids` (auto-discover) and
may exit 1 with a valid degraded execution-result envelope. MCP
JSON-RPC success is transport-only; the MCP content document is still
`range.lifecycle.v2`.

## Web testing (DAST) role

The first-class web/DAST lane is the **zaproxy** arm: Zed Attack
Proxy's native JSON API is a first-party automation surface and the
free edition needs no license for it. Read tier covers the exact
`/JSON/*/view/` allowlist (`sites`, alerts, messages, spider and
active-scan status **and results**); `ascan_scan`/`spider_scan` are
dispatch-class and stay refused until `ZAP_DISPATCH_SCOPE` names the
target. Passive findings surface through `alerts`/`alerts_summary`
without any dispatch.

**Burp** (`burp-mcp`) is the curated-but-held row on this lane:
PortSwigger's official MCP Server BApp runs on Community Edition for
proxy history, request sending, Repeater, and codecs (scanner-issues
and Collaborator tools are Pro-gated), but this suite's HTTP MCP
client transport stays held pending the OAuth resource and audience-binding gate —
see the row notes in `extension/coverage.yaml`. Community Edition has
no usable built-in REST API and no project-file persistence, so the
honest CE automation story is the official BApp above; until the
transport gate lands, use `zaproxy` for driven web testing.

## On Kali

The suite is OS-agnostic Python; Kali contributes **binaries and
endpoints**, and `python -m extension availability` is the one-command
answer to "what lights up on this host":

```text
python -m extension availability
```

It prints a read-only report — host profile (Kali is detected via the
canonical `/etc/os-release` `ID=kali`), the `*_DISPATCH_SCOPE` env vars
currently armed, and one row per curated arm: tier, held flag, and
whether the arm's own install probe resolves a binary/endpoint. Nothing
is invoked.

Install on Kali (PEP 668 blocks system pip; use a venv or pipx):

```text
sudo apt update && sudo apt install -y python3-venv nmap
python3 -m venv ~/.venvs/ctf && ~/.venvs/ctf/bin/pip install -e .
~/.venvs/ctf/bin/python -m extension availability
```

What Kali gives you out of the box (default amd64 image):
`nmap` ships in `kali-linux-headless` (every default image) and
`burpsuite` (Community-grade) ships in `kali-tools-top10`. For the
first-class DAST lane install `zaproxy` (`sudo apt install zaproxy`)
and start ZAP with its API enabled, then point `ZAP_API_ENDPOINT` at
it. `zgrab2` is not packaged by Kali — install it separately or leave
the row dark. Among the dispatch-admitted CLI arms, `wapiti` and
`routersploit` ship in Kali's tool metapackages; `zdns` and `osmedeus`
are not packaged (install separately). One naming trap: Kali once
shipped an unrelated WPA-PSK cracker also called `pyrit` — the AI
red-team framework here is Microsoft's PyRIT (`pyrit_scan`, installed
as a Python package), not that tool. Every dispatch-class action still
requires its explicit `*_DISPATCH_SCOPE`; installing a binary never
arms anything by itself.

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
| `NMAP_BIN` / `NMAP_DISPATCH_SCOPE` | nmap | binary; single-host `scan` (closed flags, XML on stdout) |
| `DARK_MOON_BIN` / `DARK_MOON_DISPATCH_SCOPE` | dark-moon | shell launcher; host-scoped `campaign`/`run` |
| `PYRIT_BIN` / `PYRIT_DISPATCH_SCOPE` | pyrit | `pyrit_scan`; host/URL-scoped `scan` |
| `DEEPSEC_BIN` / `DEEPSEC_SCAN_ROOT` / `DEEPSEC_DISPATCH_SCOPE` | deepsec | real `deepsec` binary (**not** npx/pnpm/npm/yarn); workspace dir with config (cwd); arm `DEEPSEC_DISPATCH_SCOPE=localhost` |
| `VVAH_BIN` / `VVAH_SCAN_ROOT` / `VVAH_DISPATCH_SCOPE` / `VVAH_ALLOW_REMEDIATE` | vvah | binary; path root (cwd); arm `VVAH_DISPATCH_SCOPE=localhost`; S10 extra gate `=1` |
| `AI_DEEP_SAST_BIN` / `AI_DEEP_SAST_DEEPSCAN_BIN` / `AI_DEEP_SAST_SCAN_ROOT` / `AI_DEEP_SAST_DISPATCH_SCOPE` / `AI_DEEP_SAST_SEMGREP_CONFIG` | ai-deep-sast | binaries; path root (cwd); local ruleset inside the root; arm `AI_DEEP_SAST_DISPATCH_SCOPE=localhost` |
| `AGENT_WIZ_BIN` / `AGENT_WIZ_SCAN_ROOT` / `AGENT_WIZ_DISPATCH_SCOPE` | agent-wiz | binary; path root (cwd); arm `AGENT_WIZ_DISPATCH_SCOPE=localhost` |
| `OPENAI_API_KEY` | agent-wiz | required for `analyze`; presence-checked, never logged |

Missing `*_BIN` **and** missing PATH → executable actions are unavailable.
For `agent-wiz`, the bundled metadata-only `list_tools` exception remains
available while `extract`, `visualize`, and `analyze` raise `NotInstalled` at
the arm/Extension layer. A binary on PATH without `*_BIN` installs executable
actions where that arm supports the checkov/wapiti pattern.
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
