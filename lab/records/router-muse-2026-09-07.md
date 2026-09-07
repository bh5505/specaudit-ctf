# Tier router re-arm: every claude-code route muse-backed (2026-09-07)

The shared OpenRouter key behind the router's sonnet and haiku routes
exhausted its credit (402 on every request; the operator directive is
that it will NOT be topped up). The router on both WSL hosts was
re-armed so **every served route resolves to the working muse
provider**, the three dated serving names are byte-identical to
before, and the dead key is unreachable from any graded path. A
reusable gate (`lab/router-health.sh`) now runs before any graded
claude-code sweep.

## What changed (both hosts, identical)

`/opt/litellm/config.yaml` route table (no key material in the file —
every `api_key` is an `os.environ/` reference):

| serving name (unchanged) | was | now |
|---|---|---|
| `claude-opus-4-1-20250805` | `anthropic/muse-spark-1.3-contributor` @ `api.meta.ai` | unchanged |
| `claude-sonnet-4-5-20250929` | `openrouter/google/gemini-2.5-flash` | `anthropic/muse-spark-1.3-contributor` @ `api.meta.ai` |
| `claude-haiku-4-5-20251001` | `openrouter/openrouter/auto` | `anthropic/muse-spark-1.3-contributor` @ `api.meta.ai` |

`/etc/profile.d/claude-router.sh`: the litellm launch env dropped
`OPENROUTER_API_KEY` — the router process now receives only
`META_API_KEY` and `LITELLM_MASTER_KEY` (verified live from
`/proc/<pid>/environ` on both hosts: exactly those two names, no
openrouter variable). The tier envs and the three dated serving names
are untouched, so claude-code sees zero drift (no
`unrecognized_model` warnings).

Pre-change backups on each host:
`/opt/litellm/config.yaml.pre-muse-2026-09-07`,
`/etc/profile.d/claude-router.sh.pre-muse-2026-09-07`.

## No-op-diff guarantee on the served names

Served set immediately before the change (GET `/v1/models` via the
master key, both hosts):

```
claude-haiku-4-5-20251001
claude-opus-4-1-20250805
claude-sonnet-4-5-20250929
```

Served set after: identical (asserted by the gate's first check).

## Probe transcript (gate output, both hosts)

The gate asserts, in order: exact served-name set; structural YAML
read of the live config (no openrouter reference in any route's
model/api_base/api_key, every route muse-backed); a direct
`POST /v1/chat/completions` per dated id (HTTP 200, non-empty
content at `max_tokens=1024`); a `claude -p` smoke per dated id with
fail-closed warning scan (the muse deprecation banner for the dated
opus id prints on stdout and is informational).

kali-linux:

```
[router-health] served names ok: 3 dated ids, unchanged
config ok: 3 routes, all muse-backed, zero openrouter references
[router-health] route ok: claude-opus-4-1-20250805
[router-health] route ok: claude-sonnet-4-5-20250929
[router-health] route ok: claude-haiku-4-5-20251001
[router-health] smoke ok: claude-opus-4-1-20250805
[router-health] smoke ok: claude-sonnet-4-5-20250929
[router-health] smoke ok: claude-haiku-4-5-20251001
[router-health] ALL GREEN on this host: 3 muse-backed routes, smokes clean
```

Ubuntu: identical — all seven lines green, same ids in the same
order.

## Why the gate is structural

A `grep openrouter` on the config would also match comments and env
names, and name-stability alone would pass a router that still
routes to the dead key. The gate parses the live YAML and fails on
any route whose model/api_base/api_key values reference openrouter,
then proves each route end-to-end with a real completion and a real
claude-code smoke. A quota-exhausted muse (which answers 404 "Model
not found or access denied" for every id) fails the gate.
