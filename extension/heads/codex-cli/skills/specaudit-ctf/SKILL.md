---
name: specaudit-ctf
description: Use the SpecAudit-CTF catalog, arms, and synthetic range through MCP.
---

SpecAudit-CTF exposes four MCP tools:

- `list` returns catalog entries and their supported protocols.
- `describe` returns the catalog entry for an `id`.
- `invoke` calls an arm with `id`, `action`, and an optional `args` object. Use the arm's `list_tools` action to discover its available actions and required inputs. Read the returned `ok`, `output`, and `error` fields.
- `run_range` runs synthetic range fixtures. It accepts an optional integer `seed` and optional `arm_ids`; an empty `arm_ids` list runs the range without additional arms. Read the returned range report for fixture results and errors.

The matching CLI is `python -m extension list|describe|invoke` and `python -m extension.range`. The human operator chooses targets and is accountable for tool use. Report actual results and errors; do not infer success from a tool being present in the catalog.
