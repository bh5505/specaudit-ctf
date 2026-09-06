# Operator-gated validation results

Standing record for the three catalog capabilities whose validating
assets only the operator holds. These blocks are **fillable**: an
operator who runs a validation fills one in and commits the result —
everything machine-specific stays in the operator's own environment.

Rules this record inherits from `lab/README.md`:

- The lab never spends operator credentials. Nothing here may be
  filled from a lab run; a block records an **operator-run**
  validation from the operator's own host.
- Record outcomes as measured: the envelope status the operator saw,
  the commands exactly as run, artifacts produced. A `failed` or
  `degraded` outcome recorded honestly is a valid entry; an
  unfilled block stays awaiting-operator rather than guessing.

Status legend: `awaiting-operator` (never validated from this repo's
perspective) · `validated` (operator-recorded outcome below).

Probe note 2026-09-06 (operator-authorized lab check,launcher A2):
all three host classes were probed for staged validating assets —
`GTI_MCP_ENDPOINT` / `PROWLER_MCP_ENDPOINT` / `BURP_MCP_ENDPOINT` in
the lab shells' environments, and a Burp MCP listener on
`127.0.0.1:9876` on every host. Nothing was staged: no endpoint env,
no listener. The three blocks below remain `awaiting-operator`
unchanged — probed-and-awaiting, never simulated.

---

## burp-mcp — loopback reads over the official BApp

Status: **awaiting-operator**

Runbook: `lab/README.md` → "Operator-gated rows".

| Field | Value |
|---|---|
| Date | _(unfilled)_ |
| Env vars armed | `BURP_MCP_ENDPOINT=http://127.0.0.1:9876` (literal loopback only; hostname endpoints refused) |
| Invoke commands as run | `python -m extension invoke burp-mcp list_tools` · `python -m extension invoke burp-mcp url_encode '{"content": "a b"}'` · `python -m extension invoke burp-mcp get_proxy_http_history '{}'` |
| Envelope status | _(fill: complete / degraded / failed per action)_ |
| Artifacts | _(fill: attempt ids, artifact dirs, notable outputs — e.g. detected Burp edition from list_tools)_ |
| Operator note | _(optional: BApp version, Burp edition, anything surprising)_ |

---

## google-mcp-security — GTI remote reads

Status: **awaiting-operator**

Runbook: `lab/README.md` → "Operator-gated rows". The operator runs
the official server (google/mcp-security `server/gti`, PyPI `gti-mcp`
0.1.3, 2026-08-27) where its sole credential lives; this client's
environment never carries it. Verified from source 2026-09-06:

- The server reads exactly one credential env, **`VT_APIKEY`**
  (`api_key = os.getenv("VT_APIKEY")`; a per-request client factory
  raises `ValueError("VT_APIKEY environment variable is required")`).
  No Google application-default credential is involved.
- The first-party entrypoint is **stdio-only**
  (`server.run(transport='stdio')` in `main()`; the `STATELESS=1` env
  toggles FastMCP's stateless-http constructor flag only). No
  first-party HTTP-serving command exists as of 2026-09-06, so the
  operator-fronted https endpoint this arm targets is the operator's
  own fronting (documented stdio recipe below); a first-party HTTP
  flag would supersede this note per the doc-21 drift rule.
- Documented local run (README): `uv run --directory
  /path/to/mcp-security/server/gti/gti_mcp server.py` with
  `VT_APIKEY` in the environment (env file or export).
- Tool inventory re-verified the same day: 36 tools; 32 read-only
  lookups admitted (the original 11 plus threat-profile reads and
  collection reads), 4 mutating exactly blocked — the three
  collection writers and `analyse_file` (upstream docstring:
  "Upload and analyse the file in VirusTotal... shared with the
  community").

| Field | Value |
|---|---|
| Date | _(unfilled)_ |
| Env vars armed | `GTI_MCP_ENDPOINT=https://<operator-fronted-gti-endpoint>` (https only; loopback refused) |
| Invoke commands as run | `python -m extension invoke google-mcp-security list_tools` · `python -m extension invoke google-mcp-security get_domain_report '{"domain": "<domain>"}'` · `python -m extension invoke google-mcp-security search_threat_actors '{"query": "<actor>"}'` |
| Envelope status | _(fill: expect complete with R1 / network-egress / approval_ref operator://endpoint/GTI_MCP_ENDPOINT)_ |
| Artifacts | _(fill: attempt ids, artifact dirs, report documents returned)_ |
| Operator note | _(optional: gti-mcp version, fronting shape, VT key tier)_ |

---

## prowler-mcp — exact-name reads over the first-party OSS server

Status: **awaiting-operator**

Runbook: `lab/README.md` → "Operator-gated rows". There is **no**
client-side API-key environment variable and no hosted-endpoint
default. Staging paths, pinned from first-party source 2026-09-06
(prowler-cloud/prowler `mcp_server/`, fastmcp 3.4.5):

**Easiest — first-party local server (literal loopback):**

```
docker pull prowlercloud/prowler-mcp
docker run --rm -p 127.0.0.1:8000:8000 prowlercloud/prowler-mcp \
  --transport http --host 127.0.0.1 --port 8000
# (source-run alternative, from a prowler checkout:
#   cd mcp_server && uv run prowler-mcp --transport http \
#     --host 127.0.0.1 --port 8000)
export PROWLER_MCP_ENDPOINT='http://127.0.0.1:8000/mcp'
python -m extension invoke prowler-mcp list_tools
```

The endpoint URL must include the `/mcp` path (the server serves
streamable HTTP there; the client POSTs to the URL as given). The
`prowler_hub_*` (10 tools) and `prowler_docs_*` (2 tools) namespaces
need **no** server-side authentication. The 31 tenant `prowler_*`
reads additionally need a Prowler API key in the SERVER's `.env`
(`PROWLER_API_KEY`, talking to `api.prowler.com`) — never in this
client's environment. Local is not offline: with the tenant key set,
the server egresses to `api.prowler.com` on tenant reads.

**Remote — self-hosted server behind the operator's TLS front:** run
the same server with `--transport http --host 0.0.0.0 --port 8000`
(the README's documented self-hosted HTTP shape) on a host fronted by
a TLS terminator whose certificate the client host trusts, then arm
`PROWLER_MCP_ENDPOINT=https://<that-host>/mcp` (https required for
non-loopback endpoints; loopback names such as `localhost` are
refused — literal IPs only).

The arm admits exactly 43 read lookups by name; the 18 mutating tools
(scan triggers, mutelist/integration/provider writers, role setting)
and the hosted-only `prowler_cloud_` namespace are refused even when
the server lists them.

| Field | Value |
|---|---|
| Date | _(unfilled)_ |
| Env vars armed | `PROWLER_MCP_ENDPOINT=http://127.0.0.1:8000/mcp` (local first-party server) or `https://<operator-fronted-host>/mcp` (self-hosted remote) — the union policy; no client credential exists for this arm |
| Invoke commands as run | `python -m extension invoke prowler-mcp list_tools` · `python -m extension invoke prowler-mcp prowler_hub_list_checks '{}'` · `python -m extension invoke prowler-mcp prowler_docs_search '{"term": "s3 public"}'` |
| Envelope status | _(fill: expect complete from the hardened streamable-HTTP client — union policy: https remote or literal-loopback http)_ |
| Artifacts | _(fill: attempt ids, endpoint tool-inventory rows)_ |
| Operator note | _(optional: prowler-mcp server version — CHANGELOG 0.12.0 pairs with prowler v5.41.0 at time of writing — docker image digest, tenant-key presence)_ |

---

## claude-code real-head lane (kali + Ubuntu) — upstream credit exhaustion

Status: **awaiting-operator** (dated probe 2026-09-06)

During the first variance sweep the claude-code heads began failing in
~1.7 s with zero tool calls. Direct probe of the CLI on BOTH WSL hosts
reproduces:

```
API Error: 402 litellm.APIError: OpenrouterException - {"error":{"message":
"This request requires more credits ... can only afford 18983 tokens" ...}}
Received Model Group=claude-sonnet-4-5-20250929
```

The tier router's OpenRouter key (same key on both hosts) exhausted
its credit limit; every claude request fails until the key is topped
up. This is an operator-asset outage, not a harness or grading
defect — affected attempts are kept verbatim in
`lab/records/matrix-variance-2026-09-06/`. Lane re-enters measurement
after the top-up; codex-cli lanes were unaffected and completed the
slice.

## qwen-code real-head lane (Windows) — wired, awaiting quota reset

Status: **awaiting-operator** (dated probe 2026-09-06)

The third armed head (`EXERCISE_HEAD_QWEN_CODE_CMD`) is wired,
test-pinned, and smoke-spawned on the operator-staged Windows install
(qwen-code 0.23.0). The smoke reached the provider and was refused by
the account, not the wiring:

```
Quota exhausted: Your token-plan 1-week quota has been exhausted.
The quota will reset at 09-07 01:53:00 UTC.
```

First graded cells land after the reset (or on another operator-named
key); the head's arming discipline and custody are unchanged.
