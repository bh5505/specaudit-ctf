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
the official server where their Google application-default
credentials live; this client's environment never carries them.

| Field | Value |
|---|---|
| Date | _(unfilled)_ |
| Env vars armed | `GTI_MCP_ENDPOINT=https://<operator-fronted-gti-endpoint>` (https only) |
| Invoke commands as run | `python -m extension invoke google-mcp-security list_tools` · `python -m extension invoke google-mcp-security get_domain_report '{"domain": "<domain>"}'` |
| Envelope status | _(fill: expect complete with R1 / network-egress / approval_ref operator://endpoint/GTI_MCP_ENDPOINT)_ |
| Artifacts | _(fill: attempt ids, artifact dirs, report documents returned)_ |
| Operator note | _(optional)_ |

---

## prowler-mcp — discovery over the operator-configured https endpoint

Status: **awaiting-operator**

Runbook: `lab/README.md` → "Operator-gated rows". There is **no**
API-key environment variable and no hosted-endpoint default; the
Prowler install itself is gated on cloud credentials present in the
operator's environment (`AWS_ACCESS_KEY_ID` or `AWS_PROFILE`).

| Field | Value |
|---|---|
| Date | _(unfilled)_ |
| Env vars armed | `PROWLER_MCP_ENDPOINT=https://<operator-configured-endpoint>` (+ operator-side cloud credentials; never in this client env) |
| Invoke commands as run | `python -m extension invoke prowler-mcp list_tools` |
| Envelope status | _(fill: expect complete from the hardened SSE client — remote-https policy, loopback/plain-http refused)_ |
| Artifacts | _(fill: attempt ids, endpoint tool-inventory rows)_ |
| Operator note | _(optional: Prowler version, endpoint shape)_ |
