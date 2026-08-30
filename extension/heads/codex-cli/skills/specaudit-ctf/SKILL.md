---
name: specaudit-ctf
description: Attach specaudit-ctf as arms and legs via list, describe, invoke, and run_range.
---

Use only the specaudit-ctf MCP tools `list`, `describe`, `invoke`, and
`run_range`, or the matching CLI
(`python -m extension list|describe|invoke`, `python -m extension.range`).

- `list` — return catalog entries including `tier`. Do not invent rows.
- `describe` — take `id`. Return that row including `tier`.
- `invoke` — take `id`, `action`, and optional `args` object. Only the
  bounded X2-PUB read-only action registry succeeds (in-process
  `list_tools` policy reads). Unknown ids, methodology-only rows,
  heads, held arms, non-curated arms, and unmanifested actions are
  refusals; do not invent a fallback card. `curated` does not mean
  maintained. The tool result content is an
  `specaudit.ctf.execution-result.v1` envelope identical to CLI JSON
  output (timestamps differ per run). `isError` mirrors the CLI
  nonzero exit — a transport signal, not a verdict; read `status`
  (complete|degraded|failed) in the envelope.

- `run_range` — run the synthetic range fixtures. Optional integer `seed`
  and `arm_ids` (curated arms only). Omit `arm_ids` to auto-discover
  curated arms (skip/error → `degraded`; typical without tools). Pass
  `arm_ids: []` for lifecycle-only (may be `complete`). Non-empty
  `arm_ids` are required (skip/error → `failed`). Returns the same
  execution-result.v1 envelope as `python -m extension.range` — the
  seed-stable `range.lifecycle.v2` document is inside the
  range-report artifact digest; its `status` and `ok` are inner
  fields. JSON-RPC success is transport-only. No live cloud, no file
  writes.

Do not call other MCP tools on this server. Do not treat the catalog as a
ship list of adapters.
