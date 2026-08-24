---
name: specaudit-ctf
description: Attach specaudit-ctf as arms and legs via list, describe, and invoke.
---

Use only the specaudit-ctf MCP tools `list`, `describe`, `invoke`, and
`run_range`, or the matching CLI
(`python -m extension list|describe|invoke`, `python -m extension.range`).

- `list` — return catalog entries. Do not invent rows.
- `describe` — take `id`. Return that row.
- `invoke` — take `id`, `action`, and optional `args` object. Only a curated,
  installed arm succeeds. Unknown ids, methodology-only rows, heads, and
  non-curated arms are refusals; do not invent a fallback card.

- `run_range` — run the synthetic range fixtures. Optional integer `seed`
  and optional `arm_ids` (curated arms only). Returns the seed-stable
  lifecycle document; no live cloud, no file writes.

Do not call other MCP tools on this server. Do not treat the catalog as a
ship list of adapters.
