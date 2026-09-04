# Extension

Arms, legs, and alternative-head surface for the specaudit-ctf
collaboration cut.

This tree is the public attach surface:

- `coverage.yaml` — classified survey map (not a ship list)
- `contract.py` — fail-closed `list` / `describe` / `invoke`
- `arms/` — 26 specialized handlers (families below)
- `heads/` — Claude Code CLI, Codex CLI, and other-agent-CLI profiles
- `range/` — synthetic fixtures only
- `mcp_server.py` — stdio MCP for four tools (`list`, `describe`,
  `invoke`, `run_range`)
- `arms/dispatch.py` — two-tier scope gate

A validation client may attach the same CLI or MCP surface later.

## Coverage catalog

`coverage.yaml` classifies each surveyed product as:

- `head` — alternative agent or CLI head
- `arm` — invocable tool, scanner, MCP, or CLI adapter
- `methodology-only` — specification, curriculum, or teach-only knowledge

Every row has a support `tier`: `research` | `experimental` |
`maintained` | `held`. `curated: true` is a **deprecated**
compatibility flag meaning a specialized handler exists in this cut;
it is **not** `tier: maintained`. **26 arms are curated; HTTP MCP
arms are held; exactly one capability is maintained — the agent-wiz
read tier `agent-wiz.list_tools` (X5-PROMOTE, doc 13 evidence gate).**
Methodology-only rows are never curated and never maintained. `held` is never invocable and carries
`held_reason`. research/experimental presence is not a validator
support promise. A row on the map is not a promise that an adapter is
implemented; in this cut every arm row has a specialized handler.

Schema: [schema/coverage.schema.json](schema/coverage.schema.json).

### Curated arms by family

**MCP** (`tier: held` on this public cut; catalog invoke refused;
handlers preserved; specialized session, not a generic transport):

- `burp-mcp` — research; HTTP+SSE on the hardened transport; literal
  loopback endpoints only (`127.0.0.1`/`[::1]`, http or https);
  allowlisted reads/utilities; Community edition
  refused
- `semgrep-mcp` — held; streamable HTTP; scan/findings/AST reads; inline
  rule pack required (no registry `p/` or URL rules)
- `prowler-mcp` — held; HTTP+SSE; read-only `prowler_` / `prowler_docs_` /
  `prowler_hub_` prefixes; `prowler_cloud_*` blocked; credential-gated
- `google-mcp-security` — held; GTI lookups; all 11 tools are reads; no
  dispatch tier
- `metasploit-mcp` — held; SSE; module/session listings read; execution
  tools gated by `METASPLOIT_DISPATCH_SCOPE`

**CLI read** (no dispatch tier):

- `checkov` — fixed-argv terraform scan; `--skip-download`;
  `CHECKOV_SCAN_ROOT` must stay inside the packaged range
- `garak` — `list_probes` / `list_detectors` / local `report`;
  target-bound install; open-ended probe dispatch blocked
- `mitreattack-python` — local STIX-to-Excel; network downloader on
  no tier

**CLI dispatch-only** (no meaningful read surface):

- `wapiti` — `WAPITI_DISPATCH_SCOPE`
- `commix` — `COMMIX_DISPATCH_SCOPE`
- `zdns` — `ZDNS_DISPATCH_SCOPE`
- `page-fetch` — `PAGE_FETCH_DISPATCH_SCOPE`

**CLI / native two-tier** (reads unarmed; dispatch scope-gated):

- `zaproxy` — native JSON API views; scans gated by
  `ZAP_DISPATCH_SCOPE`
- `vuls` — local `report`/`summary`; `scan` is scope-presence
  (`VULS_DISPATCH_SCOPE`)
- `stratus-red-team` — local technique list; warmup/detonate/revert
  gated by `STRATUS_DISPATCH_SCOPE`
- `osmedeus` — local asset reads; scan gated by
  `OSMEDEUS_DISPATCH_SCOPE`
- `caldera` — allowlisted v2 GET reads (incl. per-operation
  chain); `schedule_operation` gated by `CALDERA_DISPATCH_SCOPE`
  (path provisional upstream)
- `routersploit` — dispatch-only `run`
- `sniper` — dispatch-only `scan`
- `zgrab2` — `list_modules` read; stdin `scan`
- `dark-moon` — `log` read; `campaign`/`run` dispatch (CLI launcher;
  MCP names unbound)
- `pyrit` — `list_scenarios` read; `scan` dispatch (`pyrit_scan` only)
- `deepsec` — unarmed `scan` (matcher; mutates workspace); `process`
  dispatch; path-scoped
- `vvah` — `estimate` is a free read; `doctor` live-probes backends
  (may spend tokens); `scan`/`remediate` dispatch; path-scoped
- `ai-deep-sast` — `--skip-llm` `scan` and `dry_run` reads; `ai_scan`
  dispatch; path-scoped
- `agent-wiz` — `extract`/`visualize` reads; `analyze` dispatch;
  path-scoped

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

`invoke` is fail-closed: unknown ids, non-arms, methodology-only rows,
held arms, non-curated arms, and uninstalled curated arms are hard
errors. Do not invent a fallback card. `list` / `describe` include
`tier` and stay catalog JSON. `invoke` stdout is
`specaudit.ctf.execution-result.v1`. Process exit 0 is not `complete`.
`transport_ok` is informational: it means the tool invocation/response
transport succeeded, not that artifact custody succeeded. Optional
`--attempt-id` / `--artifact-dir` are Mode A. `--artifact-dir` must be
an absolute, existing, real, empty per-attempt Unix directory; the
producer binds it before dispatch. Malformed attempt ids, invalid or
non-empty artifact directories, and unsupported Mode-A platforms fail
before execution and may report only on stderr (no result envelope).
Omit both flags for portable Mode B.

The X2-PUB CLI manifest admits the in-process `list_tools` policy reads
for `agent-wiz`, `ai-deep-sast`, `dark-moon`, `deepsec`, `nmap`,
`pyrit`, `routersploit`, `sniper`, `vvah`, and `zgrab2`, plus — since
the 2026-09-01/02 dispatch-class admissions — the scope-gated R1
profiles (`nmap.scan`, `zaproxy.ascan_scan`, `zaproxy.spider_scan`,
`zgrab2.scan`, `wapiti.scan`, `zdns.lookup`, `pyrit.scan`,
`routersploit.run`, `osmedeus.scan`, `page-fetch.fetch`) with honest
manifest truth: default-off behind the arm's `*_DISPATCH_SCOPE`,
`synthetic_only: false`, declared side effects (`subprocess`+
`network-egress` for the CLI arms; `network-egress` only for the ZAP
API profiles). Any action without an admitted profile is still refused before
`Extension.invoke`; nothing may borrow fabricated R0/local-read
metadata. Since X4-PUB the stdio MCP
`invoke` tool enforces the same registry through the shared
`extension.dispatch` and returns the same `execution-result.v1`
envelope as the CLI (timestamps differ per run); the direct library
surface keeps its existing gates.

Catalog `invoke` of held HTTP MCP arms (`semgrep-mcp`,
`prowler-mcp`, `google-mcp-security`, `metasploit-mcp`) is refused
even when an endpoint is configured. `burp-mcp` is research on the
hardened transport (per the authorizing dossier): handler-level
`list_tools` / `tools/list` go through the shared client, while CLI
and MCP `invoke` still require a registered capability profile.
Burp is not installed unless
`BURP_MCP_ENDPOINT` is set to a literal-loopback (`127.0.0.1` or
`[::1]`) HTTP+SSE MCP URL; a configured endpoint that is unreachable fails the handler
with an error. Community edition is refused for tool calls. Only
allowlisted read or utility actions run once un-held. SSE endpoint
with CR/LF is refused, oversized SSE frames are rejected, and error
payloads redact credential substrings.

Semgrep (`semgrep-mcp`) is installed only when `SEMGREP_MCP_ENDPOINT`
names a streamable-HTTP MCP URL. Only scan and findings/AST/language
reads are allowlisted; `semgrep_scan` additionally requires an inline
rule pack in `args.config` — registry refs (`auto`, `p/...`) and URLs
are refused so scans never egress for rules.

Checkov is installed when `CHECKOV_BIN` (or `checkov` on PATH) exists.
Only `scan` runs, with a fully fixed argv and `--skip-download`; the
scan root is contained to the packaged synthetic range
(`CHECKOV_SCAN_ROOT` inside that tree only).

Prowler (`prowler-mcp`) is installed only when BOTH
`PROWLER_MCP_ENDPOINT` and cloud credentials (`AWS_ACCESS_KEY_ID` or
`AWS_PROFILE`) are present. Read-only namespaces only
(`prowler_`, `prowler_docs_`, `prowler_hub_`); the
`prowler_cloud_*` scan-orchestration namespace and any
mutation-named tool are blocked. Upstream tool names are not yet
pinned in public docs, so the allowlist is prefix-based; tighten it
when upstream documents exact names.

Garak is installed only when a binary (`GARAK_BIN` or PATH) AND an
explicit `GARAK_TARGET` binding exist. Only `list_probes`,
`list_detectors` (fixed argv) and `report` (reads the newest JSONL
from `GARAK_REPORT_DIR` locally) run; open-ended probe dispatch is
blocked.

## Two-tier dispatch

Read-only surfaces are the default tier: listings, findings reads,
report reads, path-contained local scans. Dispatch-class actions —
exploit run, scan launch, detonate, live DNS resolution, page fetch,
AI process, source mutation — are refused by default with a message
naming the arming env var. Arming is scope-binding:
`<ARM>_DISPATCH_SCOPE` must name explicit CIDRs, IPs, hostnames, or
URI prefixes (`*`, `0.0.0.0/0`, `::/0` are refused at parse, including
prefixlen-0 canonicalization). Host targets are matched exactly or by
CIDR containment; session- or technique-bound actions authorize on
scope presence and audit `session:<id>` / the technique id. Every
allowed dispatch writes a `[dispatch]` stderr audit line and stamps
its Result with scope and target.

**Host-scoped** (hostname/URL into `authorize`): `zaproxy`
(`ZAP_DISPATCH_SCOPE`), `wapiti` (`WAPITI_DISPATCH_SCOPE`), `commix`
(`COMMIX_DISPATCH_SCOPE`), `osmedeus` (`OSMEDEUS_DISPATCH_SCOPE`),
`zdns` (`ZDNS_DISPATCH_SCOPE`), `page-fetch`
(`PAGE_FETCH_DISPATCH_SCOPE`), `routersploit`
(`ROUTERSPLOIT_DISPATCH_SCOPE`), `sniper` (`SNIPER_DISPATCH_SCOPE`),
`zgrab2` (`ZGRAB2_DISPATCH_SCOPE`), `dark-moon`
(`DARK_MOON_DISPATCH_SCOPE`), `pyrit` (`PYRIT_DISPATCH_SCOPE`).
`metasploit-mcp` `run_exploit` / `run_auxiliary_module` host-match
RHOSTS/RHOST.

**Scope-presence** (no host match; audit a synthetic or unknown
target): `vuls` (`VULS_DISPATCH_SCOPE`), `stratus-red-team`
(`STRATUS_DISPATCH_SCOPE`), `caldera` (`CALDERA_DISPATCH_SCOPE`).
`metasploit-mcp` `run_post_module`, `generate_payload`,
`send_session_command`, `terminate_session`, `start_listener`, and
`stop_job` authorize on scope presence only — a session command
cannot prove which host that session is on.

**Path-scoped** (authorize on scope presence, contain the filesystem
separately): `deepsec` (`DEEPSEC_DISPATCH_SCOPE`), `vvah`
(`VVAH_DISPATCH_SCOPE`), `ai-deep-sast`
(`AI_DEEP_SAST_DISPATCH_SCOPE`), `agent-wiz`
(`AGENT_WIZ_DISPATCH_SCOPE`). Set `FOO_DISPATCH_SCOPE=localhost`
(any explicit non-blanket item). Containment is `FOO_SCAN_ROOT`, and
every spawn pins `cwd` to that root (deepsec: the workspace that
holds `deepsec.config.ts`). **Do not put a repo path in the scope
env.**

Env table (all 26): [root README](../README.md#environment-variables).

Caveats are now the operator contract (`policy.CAVEATS`, catalog
`notes`, `list_tools`, unarmed `Result.error`, CLI stderr). GUI-only
remains the only skip class. Default unarmed dispatch is refused until
scope is set (support-tier `held` is separate: catalog invoke is
refused).

## Per-arm caveats

One-liners. Full notes live on the catalog row (`describe <id>`).

- `burp-mcp` — Community edition refused; only allowlisted reads/utilities.
- `semgrep-mcp` — scans need an inline rule pack; no registry/URL rules.
- `checkov` — scan root must stay inside the packaged range; offline bundle.
- `prowler-mcp` — prefix allowlist pending exact upstream names; no cloud orchestration.
- `garak` — listing and local report only; no probe dispatch.
- `zaproxy` — view reads unarmed; scan launch is scope-gated.
- `wapiti` / `commix` — no read-only mode; every scan is dispatch.
- `mitreattack-python` — local conversion only; no STIX download.
- `vuls` — report/summary local; `fetch` is on no tier.
- `stratus-red-team` — detonate/warmup/revert are dispatch.
- `osmedeus` — recon scan is dispatch.
- `zdns` — live resolution is the whole surface.
- `page-fetch` — http(s) URL with a hostname, then host-scope via
  `PAGE_FETCH_DISPATCH_SCOPE`. Private, metadata, and localhost hosts
  are allowed if in scope; only the initial URL is scope-checked —
  redirects, name resolution at fetch time, and rendering subresources
  are not re-checked (treat the scope as reachable from anything its
  hosts redirect or reference to, including metadata IPs), and the
  fetcher may write browser state in its default location.
- `caldera` — v2 GET reads unarmed (per-operation chain for
  post-run inspection); scheduling an operation is dispatch (path
  provisional upstream).
- `google-mcp-security` — lookups only.
- `metasploit-mcp` — execution tools are dispatch; session commands cannot prove the session host.
- `routersploit` — non-interactive `run` **always executes the module** (not check). Default unarmed.
- `sniper` — scoping `-t` does **not** bound 90+ sub-tools; community binary is root-only and phones home when armed. Composite egress.
- `zgrab2` — L7 handshake scanner; one host on stdin; closed modules plus optional `--port`.
- `dark-moon` — autonomous multi-agent pentest; MCP gateway still launches Nuclei/sqlmap/NetExec inside Docker (composite egress). CLI only.
- `pyrit` — first-party `pyrit_scan` only; requires operator PyRIT config (`~/.pyrit`); scan spends model tokens on the operator-configured endpoints. CoPyRIT GUI is out of scope.
- `deepsec` — operator runs init out of band; cwd is the `.deepsec` workspace; unarmed `scan` writes matcher state; `process` is agentic and can cost thousands of dollars. Binary must not be npx/pnpm/npm/yarn.
- `vvah` — 11-stage agentic pipeline; `doctor` live-probes configured
  backends (may spend tokens); `estimate` spends nothing; `scan` is
  `--stop-after s9` (no source edit); `remediate` needs
  `VVAH_ALLOW_REMEDIATE=1` **and** dispatch scope; `validate` is not
  exposed.
- `ai-deep-sast` — `--skip-llm` is the safe default and needs a local
  `AI_DEEP_SAST_SEMGREP_CONFIG` inside the scan root (no registry
  `p/` default). `ai_scan` runs local Foundation-Sec via
  llama-completion; frontier deepscan.py is not exposed beyond
  `dry_run --dry-run`.
- `agent-wiz` — extract/visualize are local AST/HTML (cwd-contained); `analyze` egresses to OpenAI and needs the OpenAI credential env.

## MCP

From this clone (cwd must be the clone root):

```text
python -m extension.mcp_server
```

That process exposes only `list`, `describe`, `invoke`, and `run_range`.
Do not add inventory, paging, or writeback tools on this process.

`run_range` is the single boundary case to the "no new tools" doctrine:
it runs the synthetic, seed-stable fixtures (`live_aws: false`), takes
no path arguments, accepts only curated `arm_ids`, never writes files
over MCP (`--out` stays CLI-only), and caps its response size. It is an
exception named here so it is cited as a boundary, not a precedent.

Heads should spawn `heads/<head>/launch_mcp.py` so import does not
depend on cwd:

```text
python extension/heads/claude-code/launch_mcp.py
python extension/heads/codex-cli/launch_mcp.py
```

A relocated launcher needs `SPECAUDIT_CTF_ROOT` set to the clone root.

## Heads

Attach profiles:

- [heads/claude-code.md](heads/claude-code.md)
- [heads/codex-cli.md](heads/codex-cli.md)
- [heads/other-agent-cli.md](heads/other-agent-cli.md)

Claude Code CLI, from this clone:

```text
claude mcp add --scope project --transport stdio specaudit-ctf -- python extension/heads/claude-code/launch_mcp.py
```

Or put a project `.mcp.json` in the clone (keep
`${CLAUDE_PROJECT_DIR}` inside that JSON; it is a client
substitution, not a shell variable). See the Claude profile.

Codex CLI, prefer a project `.codex/config.toml` in this clone:

```toml
[mcp_servers.specaudit-ctf]
command = "python"
args = ["extension/heads/codex-cli/launch_mcp.py"]
cwd = "."
```

User-global `~/.codex/config.toml` must set `cwd` to the absolute
path of this clone.

Another agent CLI that already has tools can attach the same three
CLI subcommands, `python -m extension.range`, or the same stdio MCP
process. A validation client may do the same. This tree does not ship
a third named head profile.

Bundled skill and plugin files live next to each launcher under
`heads/claude-code/` and `heads/codex-cli/`. The skill tells the head
to call only `list`, `describe`, `invoke`, and `run_range`.

## Range

`range/` holds synthetic fixtures `tf_s3_public_access` and
`tf_iam_open`. Inputs are fixture asset / connectivity / SAST-like
JSON plus a tiny Terraform sample. There is no live cloud.

```text
python -m extension.range
python -m extension.range --out range-result.json --seed 123
python -m extension.range --arm-ids "" --seed 7
python -m extension.range --attempt-id attempt-<hex> --artifact-dir ABSOLUTE_DIR
```

CLI stdout and `--out` are `specaudit.ctf.execution-result.v1`. Mode A
(`--artifact-dir`) emits the envelope only on stdout; `--out` combined
with `--artifact-dir` is rejected before range execution and may report
only on stderr. The artifact directory must be a fresh empty private
per-attempt Unix directory bound before dispatch. Process exit 0 if and
only if the outer envelope `status` is `complete`; inner `ok` does not
decide it. `transport_ok` is informational: it means the tool
invocation/response transport succeeded, not that artifact custody
succeeded. Library `run_range()` still emits a seed-stable
`range.lifecycle.v2` document
with `live_aws: false`, `fixtures[].exposure|path|impact`, and coverage
lists of attempted / complete / skipped / error arm ids. The inner
lifecycle document is coverage input and a `range-report` artifact
digest, not a second all-clear: inner `ok` is not the outer status.
`--seed` applies to that inner run. Document and fixture `status` is
`complete`, `degraded`, or `failed`; compatibility `ok` is true only
when `status` is `complete`. A missing arm is still recorded as
`skipped` (transport errors as `error`); that row is never `complete`.
Omitted `arm_ids` (`None`) auto-discovers curated arms as optional
(`degraded` on skip/error). Explicit non-empty `arm_ids` are required
(`failed` on skip/error). Explicit empty `arm_ids=()` has no arms and
may be `complete` when lifecycle matches. `matched_expected` stays
independent: a mismatch is `failed`, and a match cannot hide an arm
skip/error. Default CLI auto-discovers curated arms and may exit 1 with
a valid degraded execution-result envelope. MCP JSON-RPC success is
transport-only; the MCP content document is still `range.lifecycle.v2`.
The new nine do not implement `observe`; if a binary is accidentally
installed, range records `Result.ok=False` as `status=error`.

## Tests

From the repository root:

```text
python -m pip install -e ".[dev]"
python -m pytest tests/ -q
```

`pip install -r requirements-dev.txt` is the equivalent dependency
set without an editable install.
