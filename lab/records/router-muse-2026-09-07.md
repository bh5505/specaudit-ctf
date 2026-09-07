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

The gate asserts, in order: exact served-name set from
`GET /v1/models` (bounded retry for a just-restarted router); a
structural YAML read of the live config that must yield EXACTLY the
three dated route names, pin every route to the exact muse model +
api_base, and find zero openrouter references in ANY
`litellm_params` value (a grep would also match comments and env-var
names); a direct `POST /v1/chat/completions` per dated id (HTTP 200,
non-whitespace-EMPTY content at `max_tokens=1024`); a `claude -p`
smoke per dated id with a fail-closed scan for unrecognized_model,
not-found / access-denied, and dead-credential signals (402,
credit/quota/unauthorized) — the muse deprecation banner for the
dated opus id prints on stdout and is informational. The master key
travels in a 0600 curl config file (never in argv, where /proc would
publish it) read from a key file whose group/other permission bits
the gate asserts zero.

kali-linux:

```
[router-health] served names ok: 3 dated ids, unchanged
[router-health] config ok: 3 routes, exact muse pin, zero openrouter references
[router-health] route ok: claude-opus-4-1-20250805
[router-health] route ok: claude-sonnet-4-5-20250929
[router-health] route ok: claude-haiku-4-5-20251001
[router-health] smoke ok: claude-opus-4-1-20250805
[router-health] smoke ok: claude-sonnet-4-5-20250929
[router-health] smoke ok: claude-haiku-4-5-20251001
[router-health] ALL GREEN on this host: 3 muse-backed routes, smokes clean
```

Ubuntu: identical — the same nine lines, same ids, same order.

## Why the gate is structural

A `grep openrouter` on the config would also match comments and env
names, and name-stability alone would pass a router that still
routes to the dead key. The gate parses the live YAML and fails
unless the route table is EXACTLY the three dated names, every
route pins the exact muse model and api_base, and no
`litellm_params` value on any route mentions openrouter — then it
proves each route end-to-end with a real completion and a real
claude-code smoke. A quota-exhausted muse (which answers 404 "Model
not found or access denied" for every id) fails the gate. The
guarantee is deliberately narrow about one thing: an api_key that
indirects through a RENAMED env var holding the dead key would pass
the structural scan — the live per-id completions are the check
that catches a dead upstream at gate time.
