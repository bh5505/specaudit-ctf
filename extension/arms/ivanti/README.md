# Ivanti (RiskSense) VM API arm — `ivanti`

First-party, **stdlib-only** extractor for the Ivanti VM platform API. This is
the governed way to pull host (assets), hostFinding (findings),
`vulnerability`, and `tag` data straight from the sponsor estate's Ivanti VM
instance — no `requests`/`pandas`/`duckdb`, so the sealed specaudit-ctf runtime
can execute it hermetically.

The upstream platform is the RiskSense/Neurons Ivanti VM API:

```text
{url}{api_ver}/client/{client_id}/{subject}/search     POST (x-api-key auth)
{url}{api_ver}/client/{client_id}/{subject}/export     POST (server-side CSV)
```

## Actions

| action | purpose |
| --- | --- |
| `search` | Paged pull of `host`/`hostFinding`/`vulnerability`/`tag` records, flattened to a JSON-safe shape; `save` writes a CSV. `extract_host` lifts `host.hostId`/`host.ipAddress` to `host_id`/`host_ip` for findings. |
| `export` | Create a server-side UI-identical CSV and poll until the download is ready (`save` persists it). |
| `filters` | Offline discovery of the API's valid filter names for an endpoint. |
| `fields` | Offline discovery of the API's exportable field names for an endpoint. |
| `list_tools` | Arm summary: allowed actions, endpoints, arming state, arg keys. |

## Arming

Config is read from an INI (same shape as the operator's `Ivanti_config.ini`,
see `Ivanti_config.ini.example`) at `$IVANTI_CONFIG` or beside the arm, with
live-secret env overrides so no credential file is needed:

```text
IVANTI_URL        e.g. https://platform4.risksense.com
IVANTI_API_VER    e.g. /api/v1
IVANTI_CLIENT_ID  e.g. 1550
IVANTI_API_KEY    live credential (overrides [secrets] api_key)
```

Live pulls need these set; `filters`/`fields` discovery are offline and need no
scope grant. Output is the flattened JSON-safe shape the `ext_telecom_asmvm`
pack consumes as its Ivanti bronze (`assets`/`findings` rows), so a downstream
`pack_run` can fold the pulled assets/findings into the pack's evidence model.
