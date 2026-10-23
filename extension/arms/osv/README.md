# osv arm: offline snapshot reader + bounded live API client

The `osv` arm is an advisory-context source. It has two strictly separated
layers behind one interface, and neither layer ever grades code, asserts a
finding, or scores a challenge:

- **Snapshot layer** (`reader.py`) — offline, deterministic reads over a
  caller-supplied local snapshot file. This module never imports the live
  client and never touches the network.
- **Live layer** (`api.py`) — bounded, read-only queries against the fixed
  official OSV v1 query endpoint. stdlib `urllib` only; the opener is built
  per call.

Actions (exact allowlist, per `policy.py`):

| action | args | layer |
|---|---|---|
| `list_tools` | none | interface listing, no coverage claim |
| `read_snapshot` | `snapshot` | offline read of every record |
| `get_advisory` | `snapshot`, `id` | offline exact OSV id lookup |
| `query_package` | `ecosystem`+`name`+`version`, or `purl`+`version` (unversioned purl), or versioned `purl` alone | live |
| `query_commit` | `commit` (40-hex) | live |

Any other argument name, or an unsupported combination (`purl` mixed with
`ecosystem`/`name`, `version` with a versioned purl, an unversioned purl
without `version`, `commit` with anything else), is a plain failure. Invalid
input is always a plain failure (`ok=false`, no status object).

## Snapshot file format

The snapshot is a single versioned JSON object. The only accepted container
version is the `snapshot_schema` string below; any other value — past or
future — is refused, not best-effort parsed.

```json
{
  "snapshot_schema": "specaudit-ctf.osv-snapshot/1",
  "snapshot_time": "2026-10-23T00:00:00Z",
  "packages": {
    "PyPI:demo-package": [ { "id": "...", "modified": "...", "affected": [ ... ] } ]
  }
}
```

Container rules:

- `snapshot_schema` must equal `"specaudit-ctf.osv-snapshot/1"`.
- `snapshot_time` is a non-empty bounded string (ISO-8601 recommended).
- `packages` maps full package coordinates (`"<ecosystem>:<name>"`, no
  whitespace, no `:` in either half) to non-empty lists of OSV-shaped
  records. Other coordinate shapes (purl keys, commit keys) are unsupported
  and refused.
- The file must be strict UTF-8 JSON: duplicate mapping keys, non-finite
  numbers, and unbounded structure are parse failures, not warnings.

Record rules (each entry in a `packages` list):

- OSV `id` and `modified` are required, non-empty strings. `id` is the
  record identity and must be unique across the whole snapshot; duplicates
  are rejected.
- `affected` is required: it is the evidence tying the record to the
  coordinate it is filed under. A record whose `affected` packages never
  name its coordinate key is rejected.
- Optional OSV fields (`schema_version`, `aliases`, `related`, `upstream`,
  `summary`, `details`, `published`, `withdrawn`, `severity`, `references`,
  `affected`, `database_specific`) are structurally validated: range types
  must be `SEMVER`/`ECOSYSTEM`/`GIT`, GIT ranges need `repo`, each range
  event carries exactly one of `introduced`/`fixed`/`last_affected`/`limit`,
  and unknown fields are refused.
- All records that carry a `schema_version` must agree; disagreement inside
  one snapshot is rejected as mixed versions.
- A record larger than 256 KiB (serialized) is rejected; the file itself is
  capped at 8 MiB and 10,000 records.

Coordinate/version matching is deliberately narrow: a version matches a
record only through explicit evidence (a `versions` list hit, or a
`SEMVER`/`ECOSYSTEM` range hit on dotted-numeric versions). GIT ranges never
match a package version. A package-level `affected` entry without version
data never claims a version match.

## Snapshot result envelope

Both snapshot actions return a normalized envelope:

```json
{
  "status": "complete",
  "query": { "kind": "snapshot | advisory", "...": "..." },
  "records": [ ... ],
  "source": { "path": "...", "sha256": "sha256:...", "bytes": 1234,
              "snapshot_time": "..." },
  "limitations": [ "..." ]
}
```

`read_snapshot` returns every record (sorted by id; records are unique by id, so this is a total order);
`get_advisory` returns the one record with the exact OSV id, or zero
records. Empty `records` is meaningful only with `status: complete`: an
offline snapshot is read in full, so a missing id is a proven zero-match
(never an unknown). A live upstream `modified` value newer than
`snapshot_time` is surfaced by `reader.staleness_note` as a limitation, not
silently ignored.

## Live client rules (`api.py`)

- Fixed endpoint `https://api.osv.dev/v1/query`, POST, JSON body. Nothing
  about scheme, host, or path is caller-selectable.
- stdlib `urllib.request` only; no module-level sockets or openers. The
  opener is built per call with a TLS-verifying default context and
  `ProxyHandler({})`, so environment proxies cannot reroute the request.
- Redirects are refused: any 3xx (via the redirect handler or a returned
  status) is an error carrying the HTTP code. No response ever triggers a
  retry — one query, one attempt.
- The transport is injectable: `OsvArm(transport=...)` and
  `api.run_query(..., transport=...)` accept a callable
  `(urllib.request.Request, float) -> response` with `.status`/`.code`,
  `.headers`, and `.read(n)`. Tests inject fakes and never open sockets.
- Request validation matches the OSV query grammar: `package` with
  `ecosystem`+`name`+`version`, an unversioned `purl` plus `version`, a
  versioned `purl` alone, or `commit`. Never purl mixed with
  name/ecosystem, never version inside a versioned purl, never version with
  a commit.
- Caps (design contract): 10 seconds overall deadline for the whole
  paginated query, 10 pages, 100 records, 2 MiB per response. Response
  bodies are read in bounded increments — the body is never slurped before
  the cap check.
- Pagination: every `next_page_token` is followed, including token-only
  zero-vuln pages; a repeated token is an error; seen-token tracking bounds
  the loop.

## Live result envelope and status model

```json
{
  "status": "complete | partial | unknown | error",
  "query": { "...": "echoed request body" },
  "records": [ { "id", "aliases", "modified", "summary", "affected",
                 "source_link", "withdrawn" } ],
  "source": { "host", "endpoint", "fetched_at", "pages", "page_outcomes": [
                { "page", "request_sha256", "response_sha256",
                  "response_bytes", "http_status", ... } ] },
  "limitations": [ "..." ],
  "reason": "machine-readable cause or null",
  "evidence": [ { "kind": "...", "...": "bounded detail" } ]
}
```

- `complete`: HTTP 200, every page token consumed, caps respected — including
  a complete zero-match (absent or empty `vulns`, no token). This is the only
  status with `ok=true` (CLI exit 0, MCP `isError=false`).
- `partial`: a client-side cap ended collection mid-stream (page cap, record
  cap, or per-response byte cap). `ok=false` with bounded non-empty evidence,
  a reason, and whatever bounded records were retained.
- `unknown`: a 200 response parsed as JSON but is not a recognizable query
  response (missing record identity, wrong shape). `ok=false`.
- `error`: transport failure, timeout, HTTP 4xx/5xx/3xx, malformed JSON, or a
  pagination-loop failure. `ok=false`. 400-class bodies are truncated to 512
  bytes, redacted, and recorded as evidence; `Retry-After` is recorded but
  never honored (there are no retries).

Records are normalized projections, not verbatim upstream documents: `id`,
`aliases` (plain strings — aliases including CVE ids are never identity),
`modified`, `summary`, projected `affected`, a `source_link`, and the
`withdrawn` timestamp. A withdrawn record stays flagged as withdrawn; it is
never flattened into an unqualified advisory.

## Fixture rights and attribution

All shipped snapshot data under `data/` is CTF-owned **synthetic** OSV-shaped
content: package names, ids, aliases, summaries, and timestamps are invented
for the demo and correspond to no real advisory, package, or vendor.

OSV aggregates records from many upstream databases, each with its own
license and attribution requirements. This repository therefore retains **no
verbatim upstream OSV records**: the snapshot container exists so demos and
grades stay reproducible offline with synthetic data, and live query results
are returned to the caller as contextual projections without being persisted
into the repo. If a real record is ever retained, its upstream source license
and required attribution must be documented here first.
