---
name: specaudit-ctf
description: Attach specaudit-ctf as arms and legs via list, describe, invoke, and run_range.
---

Use only the specaudit-ctf MCP tools `list`, `describe`, `invoke`, and
`run_range`, or the matching CLI
(`python -m extension list|describe|invoke`, `python -m extension.range`).

- `list` — return catalog entries including `tier`. Do not invent rows.
- `describe` — take `id`. Return that row including `tier`.
- `invoke` — take `id`, `action`, and optional `args` object. Only a curated,
  installed, non-held arm succeeds. Unknown ids, methodology-only rows,
  heads, held arms, and non-curated arms are refusals; do not invent a
  fallback card. `curated` does not mean maintained.

- `run_range` — run the synthetic range fixtures. Optional integer `seed`
  and `arm_ids` (curated arms only). Omit `arm_ids` to auto-discover
  curated arms (skip/error → `degraded`; typical without tools). Pass
  `arm_ids: []` for lifecycle-only (may be `complete`). Non-empty
  `arm_ids` are required (skip/error → `failed`). Returns the
  seed-stable `range.lifecycle.v2` document (`status`:
  complete|degraded|failed; `ok` is true only when complete). JSON-RPC
  success is transport-only. No live cloud, no file writes.

Do not call other MCP tools on this server. Do not treat the catalog as a
ship list of adapters.
