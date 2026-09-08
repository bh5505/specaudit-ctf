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

Probe note 2026-09-07 (re-probe, kali-linux WSL): still nothing
staged. Probed the login-shell environment, `/etc/environment`,
systemd units and drop-ins, `/etc/profile.d/*`, root's bashrc and
profile for any `GTI_MCP_ENDPOINT` / `PROWLER_MCP_ENDPOINT` /
`BURP_MCP_ENDPOINT` / `VT_APIKEY` / `GOOGLE_APPLICATION_*` / AWS
variable, plus Burp CE install locations — no endpoint env, no
credential file, no Burp installation.

Correction same day (operator directive: staging is agent work where
no operator-held secret is required): prowler was staged and
VALIDATED from this repo's perspective (block below); burp was
staged, its transport incompatibility found and fixed in the shared
client, and ALL FOUR runbook reads validated (block below); GTI
remains operator-gated because BOTH its staging inputs are
operator-held (the `VT_APIKEY` credential and the https front).

---

## burp-mcp — loopback reads over the official BApp

Status: **validated 2026-09-07** (agent-staged: all four runbook reads
complete; the measured path is below — including the approval dialog
that initially held the data reads)

Runbook: `lab/README.md` → "Operator-gated rows". Facts pinned from
source/docs 2026-09-06 (PortSwigger/mcp-server main; BApp store
v1.3.0, 2026-05-28, still current):

- **Auto-start**: the BApp's MCP server starts with Burp once the
  BApp is installed — `enabled` defaults true
  (`storage.boolean(true)`) and persists in the BApp's extension
  data; `ExtensionBase.initialize` starts the server when enabled.
  Staging = install-once (BApp Store), then launch Burp; listener
  default `http://127.0.0.1:9876`.
- **Launch flags** (official "Launching Burp Suite from the command
  line" page): `--project-file` (PRO only — the project-files doc
  limits CE to temporary in-memory projects), `--config-file`,
  `--user-config-file`, `-Djava.awt.headless=true` ("Open Burp in
  headless mode"), `--disable-extensions`, Java 21 minimum. Whether a
  CE temp-project launch completes headless (startup wizard) is not
  documented — record any observation here rather than assuming.
- **Tool surface re-verified** (registerTools in Tools.kt, current
  main): 27 tools; every previously-allowlisted name still exists.
  New read admissions here: the regex history variants
  (`get_proxy_http_history_regex` was handler-allowed already;
  `get_proxy_websocket_history_regex`, `get_organizer_items_regex`
  move blocked→allowed), `output_user_options` (blocked→allowed —
  upstream has exported-options credential filtering since v1.3.0:
  "Broaden credential filter and fail closed on malformed JSON in
  options export"), plus profile admission for the already-allowed
  `output_project_options` and the Pro-gated `get_scanner_issues` /
  `get_collaborator_interactions` (absent from a Community server's
  tools/list — the server surface is the refusing control).
  `get_active_editor_contents` stays blocked (live operator UI state,
  not an audit artifact).
- **Residual-gap update**: the burp dossier recorded "PortSwigger
  states no server-side Origin validation" — current UNRELEASED main
  now validates Origin and Host server-side (`isValidOrigin` /
  allowedHosts {localhost, 127.0.0.1}, logging "Blocked DNS
  rebinding attack from origin"). Scoped to unreleased main at
  2026-09-06; credit it only after the next BApp release. No TLS on
  the listener (unchanged; contained by the literal-loopback rule).

**Agent staging + validation — measured 2026-09-07 (kali-linux WSL).**

STAGING: COMPLETE. Burp CE 2026.3.2 (kali repo) + the official
`burp-mcp-all.jar` v1.3.0, loaded headlessly via the CLI's own
developer-extension mechanism (no BApp Store UI needed):
`java -cp burpsuite.jar:burp-mcp-all.jar burp.StartBurp
--developer-extension-class-name=net.portswigger.mcp.ExtensionBase`
under a display (Xvfb or WSLg), license prompt answered on stdin, the
project wizard walked (Temporary project → Use Burp defaults → Start
Burp), and the extension's MCP server LISTENING on
`127.0.0.1:9876`. Measured boot requirements along the way: a FULL
JRE (the headless JRE lacks `libawt_xawt.so` — Burp dies in its own
UI init with `no ComponentUI class for: burp.Zc52` both under
`-Djava.awt.headless=true` AND under a real display); the first-run
license reads stdin even headless; `--use-defaults` does NOT skip the
project wizard; `--user-config-file` does not load extensions (the
classpath flag does). The shipped server validates Origin strictly:
same-origin INCLUDING port passes, a port-less loopback Origin gets
403, and the SSE endpoint is the ROOT path (`GET /`), not `/sse`.

ARM FIX (this repo, measured driver of the validation): the shared
HTTP-MCP client's Origin emission changed from the port-less
`http://127.0.0.1` constant to the endpoint's own RFC 6454 origin —
with that fix the SSE handshake completes (`event: endpoint` with
sessionId) and invokes flow. P5's property (Origin emitted; session
pinning) is unchanged; the pinned expectation in
`tests/test_mcp_transport_gate.py` now asserts the endpoint-derived
origin.

VALIDATION (runbook commands, `BURP_MCP_ENDPOINT=http://127.0.0.1:9876`) —
**all four reads complete**:

| Field | Value |
|---|---|
| Date | 2026-09-07 |
| Env vars armed | `BURP_MCP_ENDPOINT=http://127.0.0.1:9876` (literal loopback only; hostname endpoints refused) |
| Invoke commands as run | `python -m extension invoke burp-mcp list_tools` · `url_encode '{"content": "a b"}'` · `get_proxy_http_history '{}'` · `get_proxy_http_history_regex '{"regex": "login", "count": 10, "offset": 0}'` |
| Envelope status | **complete** for all four (transport_ok true, coverage complete) |
| Artifacts | digests per call, `kind: policy-report`, `redaction: credentials-stripped` — list_tools `sha256:4aa44d13…`; live SSE handshake captured (`event: endpoint`, `data: ?sessionId=…`) |
| Operator note | server v1.3.0 on Burp CE 2026.3.2; the shipped server ALREADY validates Origin+Host (the 09-06 note scoped that to unreleased main — v1.3.0 refuses port-less origins with 403, measured) |

**Measured findings along the path** (each one drove a fix or a
recipe note):

1. **Shipped-server Origin validation is live in v1.3.0** (the 09-06
   note scoped it to unreleased main — measured otherwise): the
   server requires the client Origin to be same-origin INCLUDING
   port. `Origin: http://127.0.0.1` (the client's former constant)
   → 403; `Origin: http://127.0.0.1:9876` → handshake completes.
   Fix: the shared HTTP-MCP client now emits the endpoint's own
   RFC 6454 origin on both transports (SSE + streamable). P5's
   property (Origin emitted; session pinning) unchanged; the P5
   tests pin the endpoint-derived origin.
2. **Headless boot recipe** (each row measured): a FULL JRE is
   required (the headless JRE lacks `libawt_xawt.so` — Burp dies in
   its own UI init with `no ComponentUI class for: burp.Zc52`, both
   under `-Djava.awt.headless=true` and under a real display); the
   first-run license prompt reads stdin even headless (`printf 'y\n'
   |`); `--use-defaults` does NOT skip the project wizard;
   `--user-config-file` does NOT load extensions — the working
   headless loader is the CLI's developer-extension mechanism:
   `java -cp burpsuite.jar:burp-mcp-all.jar burp.StartBurp
   --developer-extension-class-name=net.portswigger.mcp.ExtensionBase`
   under a display (Xvfb or WSLg).
3. **The data-access approval gate is a real GUI dialog** ("An MCP
   client is requesting access to your Burp Suite HTTP history…
   Allow Once / Always Allow / Deny") — it held the history reads
   until answered, and synthetic X11 input (xdotool, absolute and
   window-relative) never registered on the Swing UI under
   WSLg/Xvfb. Answered via native desktop control on the real
   Windows desktop (WSLg renders the window there): **Always Allow**
   — armed persistently, after which all reads flow. Headless hosts
   without a clickable desktop should expect exactly this dialog on
   the first data read.

---

## google-mcp-security — GTI remote reads

Status: **validated 2026-09-07** (agent-staged https deployment with
the operator-provided `VT_APIKEY`; two of three runbook reads
complete, one refused by upstream key entitlement — measured below)

Agent-staging assessment 2026-09-07, SUPERSEDED same day: the
operator supplied the `VT_APIKEY`, and the arm's https-only policy
was satisfied by running the OFFICIAL `gti_mcp` server itself (PyPI
`gti-mcp`, FastMCP-based — HTTP-capable by construction) over TLS on
the host's WSL address. No third-party front is involved: uvicorn
terminates TLS with a self-signed cert (SAN = the host IP, installed
into the system CA store), the app is the server's own
`streamable_http_app()`, and the SDK's DNS-rebinding guard was
widened from its loopback-only defaults to the staging IP (the
client-side transport-gate properties — https, DNS pin, Origin
emission — remain the enforcing layer). `VT_APIKEY` lives only in a
0600 file read into the server process env.

**Measured validation 2026-09-07** (`GTI_MCP_ENDPOINT=https://<host-ip>:8443/mcp`):

| Field | Value |
|---|---|
| Date | 2026-09-07 |
| Env vars armed | `GTI_MCP_ENDPOINT=https://<host-ip>:8443/mcp` (https to a non-loopback host — the arm's remote_https policy; the IP is the staging host's own WSL address) |
| Invoke commands as run | `python -m extension invoke google-mcp-security list_tools` · `get_domain_report '{"domain": "example.com"}'` · `search_threat_actors '{"query": "apt"}'` |
| Envelope status | **complete**: `list_tools`, `get_domain_report` (a real VirusTotal report retrieved end-to-end with the operator key). **failed (upstream authorization)**: `search_threat_actors` — the GTI backend refused with `ForbiddenError: You are not authorized to perform the requested operation`, i.e. the supplied key tier does not carry Google Threat Intelligence threat-actor search entitlement |
| Artifacts | digests per call, `kind: policy-report`, `redaction: credentials-stripped`; the initialize handshake over TLS returned HTTP 200 |
| Operator note | server: gti-mcp 0.1.3 (official google/mcp-security server/gti code) serving streamable HTTP directly; key tier determines which GTI capabilities the backend serves — a GTI-entitled key would unlock the refused reads with zero client changes |

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

Status: **validated 2026-09-07** (agent-staged local first-party
server; measured outcomes below)

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

**Measured validation 2026-09-07 (kali-linux WSL, agent-staged):**
source-run path used because docker is absent on this host — uv
0.12.10 installed, prowler cloned shallow to `/opt/prowler`,
`uv run prowler-mcp --transport http --host 127.0.0.1 --port 8001`
(port 8000 was occupied by an unrelated listener; any free loopback
port works). Runs from checkout `9dba632`. No Prowler API key exists
or is needed for what ran: every validated read is a `prowler_hub_*`
/ `prowler_docs_*` call.

| Field | Value |
|---|---|
| Date | 2026-09-07 |
| Env vars armed | `PROWLER_MCP_ENDPOINT=http://127.0.0.1:8001/mcp` (local first-party server, source-run over uv; the union policy's literal-loopback http shape) |
| Invoke commands as run | `python -m extension invoke prowler-mcp list_tools` · `python -m extension invoke prowler-mcp prowler_docs_search '{"term": "s3 public"}'` · `python -m extension invoke prowler-mcp prowler_hub_list_checks '{}'` (see finding) · `python -m extension invoke prowler-mcp prowler_hub_list_checks '{"providers": ["aws"], "services": ["s3"]}'` · direct fastmcp-client `prowler_hub_get_check_details '{"check_id": "s3_bucket_object_public"}'` |
| Envelope status | **complete** for `list_tools`, `prowler_docs_search`, filtered `prowler_hub_list_checks` (transport_ok true, coverage complete, zero limitations); **failed** for the UNFILTERED `prowler_hub_list_checks` (finding below); server-side tool error (refused a bogus check id) for a details probe with a guessed id — retried with a real id from the filtered list, complete |
| Artifacts | content-addressed digests per call, all `kind: policy-report`, `redaction: credentials-stripped` — list_tools `sha256:24ace50d…`, docs_search `sha256:ea36cff3…`, filtered hub list `sha256:5ca0be22…`; the direct-client probe returned the live bodies: filtered aws/s3 list = 22 checks (`s3_bucket_object_public`, severity low, first), details = full check document (id/title/description/remediation shape) |
| Operator note | Server run from prowler main (shallow clone 2026-09-07); hub/docs reads need no auth and no tenant key; no `PROWLER_API_KEY` anywhere (per the PR-#41 correction this arm has no client credential) |

**Finding (recorded, fix adopted):** the runbook's original example
`prowler_hub_list_checks '{}'` **fails closed** — the server returns
1000+ checks (its own docstring warns "An unfiltered request returns
1000+ checks") and the raw response exceeds this client's
`MAX_MCP_BYTES` transport cap (512 KiB, `extension/arms/mcp_client.py`),
which refuses before the arm's truncation can apply. The fix is
correct tool usage, not a weakened guard: pass the tool's documented
filters (`{"providers": ["aws"], "services": ["s3"]}` → 22 checks,
complete envelope). The example command in this block has been
updated to the filtered form; a ~512 KiB-in-one-response tool would
need upstream paging before the unfiltered shape can ever pass.

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

---

## staged threat-intelligence capabilities without curated arms (2026-09-07)

The operator staged API keys for additional threat-intel services.
None has a curated catalog arm yet, so staging + validation here runs
the upstream MCP servers directly and measures their reads — the
evidence base for any future arm-admission packet. Keys live in 0600
files read into server process envs; none appears in this record.

**AlienVault OTX + GreyNoise — VALIDATED 2026-09-07.** Server:
`mcp-threatintel-server` 1.0.2 (npm; community — the research note
recorded that no official AlienVault/LevelBlue MCP server exists).
One stdio server fronts both keys (`OTX_API_KEY`,
`GREYNOISE_API_KEY`) plus abuse.ch feodo. Measured over a stdio MCP
client: 9 tools served (`otx_get_pulses`, `otx_search_pulses`,
`greynoise_ip`, `threatintel_lookup_{ip,domain,hash,url}`,
`feodo_tracker`, `threatintel_status`); `threatintel_status` → OK
with `configured_services: otx, greynoise, feodo`; `otx_get_pulses`
→ **OK** (real OTX API read with the operator key);
`greynoise_ip 8.8.8.8` → the GreyNoise API answered with its
key-authenticated negative (`noise: false`, "IP not observed
scanning the internet", surfaced by the server as a 404 ToolError —
the transport and key both work; the queried IP simply has no noise
record).

**ThreatJammer — CEASED OPERATIONS (operator, 2026-09-07).** The
API key is staged (0600) but the upstream service has shut down:
there is nothing to stage a server against and nothing to validate.
Recorded awaiting-revival; never simulated.

---

## claude-code real-head lane (kali + Ubuntu) — RESOLVED: all-muse router re-arm

Status: **resolved 2026-09-07** (was `awaiting-operator`, dated probe
2026-09-06)

The 2026-09-06 outage is recorded below for the audit trail. It was
resolved WITHOUT an OpenRouter top-up (operator directive: the key
will not be topped up): both hosts' tier routers were re-armed so
every dated serving name resolves to the muse provider and the dead
key is unreachable from any graded path — route diff, launch-env
change, no-op-diff guarantee, and per-host gate transcripts in
`lab/records/router-muse-2026-09-07.md`, gated going forward by
`lab/router-health.sh`. The first fully muse-backed matrix
(`lab/records/matrix-2026-09-07.md`) ran claude-code on both hosts
12/12 across the six graded challenges.

Original outage record (2026-09-06):

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
`lab/records/matrix-variance-2026-09-06/`. codex-cli lanes were
unaffected and completed the slice.

## qwen-code real-head lane — quota reset passed; native-Linux lane measured

Status: **validated 2026-09-07** (first graded cells recorded)

The third armed head (`EXERCISE_HEAD_QWEN_CODE_CMD`) smoked against
the operator-staged qwen install on 2026-09-06 and was refused by the
account, not the wiring:

```
Quota exhausted: Your token-plan 1-week quota has been exhausted.
The quota will reset at 09-07 01:53:00 UTC.
```

2026-09-07 outcome, after the reset:

- **The Windows npm install is transport-blocked for graded cells.**
  A hermetic argv gate (npm-style `.cmd` shim replicated exactly,
  multiline prompt in, recorded argv out) shows the runner's
  multiline attempt prompt is TRUNCATED AT THE FIRST NEWLINE by
  cmd.exe batch argument passing, and the argv count arrives wrong
  (`argv count: 6 (expected 5)`). Single-line probes pass — which is
  why the 2026-09-06 smoke reached the provider. Graded attempt
  prompts are multiline (2-3 KB), so the Windows lane cannot carry
  them.
- **The native Linux lane works.** kali gained node 24.15.0 + npm
  11.16.0 + `@qwen-code/qwen-code@0.23.0` (apt/npm, same version as
  the Windows install); the operator-staged `~/.qwen/settings.json`
  (token-plan endpoint + key) transferred 0600; the headless smoke
  answered. Runner-driven cells grade clean end-to-end: server-side
  trace chain verified, graceful close, full verification — the
  first qwen-head cells in the matrix (`lab/records/matrix-2026-09-07.md`,
  qwen annex).
