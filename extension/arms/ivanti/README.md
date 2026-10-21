# Ivanti (RiskSense) VM API arm — `ivanti`

First-party, **stdlib-only** extractor for host (assets), hostFinding (findings),
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
| `filters` | Platform discovery of the API's valid filter names for an endpoint. |
| `fields` | Platform discovery of the API's exportable field names for an endpoint. |
| `list_tools` | Arm summary: actions, endpoints, and argument keys. |

## Connection configuration

Config is read from an INI (same shape as the operator's `Ivanti_config.ini`,
see `Ivanti_config.ini.example`) at `$IVANTI_CONFIG` or beside the arm, with
live-secret env overrides so no credential file is needed:

```text
IVANTI_URL        e.g. https://platform.example.com
IVANTI_API_VER    e.g. /api/v1
IVANTI_CLIENT_ID  e.g. 1550
IVANTI_API_KEY    live credential (overrides [secrets] api_key)
```

Live pulls need the connection details and credentials above. Output is the flattened JSON-safe shape the
pack evidence ingestion consumes as Ivanti bronze (`assets`/`findings`
rows), so a downstream `pack_run` can fold the pulled assets/findings into the
pack's evidence model.
