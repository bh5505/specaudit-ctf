# Governed MCP-surface pipeline

The end-to-end recon→threat-model→prioritize loop is exposed through the
**MCP surface**, not through ad-hoc scripts. Python `tools/*.py` are backend
wiring only; the six MCP tools on `extension/mcp_server.py` are the governed
capabilities:

| MCP tool | step | purpose |
| --- | --- | --- |
| `invoke` | 1 | run a recon/data arm (e.g. `assetrecon`, `ivanti`, `gti`) |
| `pack_run` | 2 | evidence dir → pack `report.json` (`ctf_run_checks` backend) |
| `prioritize_targets` | 3 | report → prioritized targets + threat models + **attack chains** + human-validation markdown |
| `list` / `describe` / `run_range` | — | surface introspection / range fixture dispatch |

## The governed 4-step path

1. **`invoke <recon arm>`** — gather intel through a first-party arm
   (assetrecon discovery, `ivanti` assets+findings pull, `gti` domain/VT intel).
   The `ivanti` arm is the governed Ivanti VM extractor; its flattened output is
   the pack's Ivanti bronze shape.
2. **`pack_run`** — fold evidence into a pack (`ext_telecom_asmvm`) and produce
   a deterministic `report.json` (the pack's ASM/VM findings, incl. T1190
   initial-access convergence).
3. **`prioritize_targets`** — from the report, build a **prioritized target list
   with threat models and attack chains** that is passed to **human red-team
   analysts for validation** before any agentic exploitability validation. Each
   target carries `validation_status = "awaiting human red-team analyst
   validation"` and the summary declares the
   `human_validation_gate = "REQUIRED before any agentic exploitability
   validation"`.
4. **`invoke <scan arm>`** — after human validation, exercise the converged
   initial-access hypothesis with a live scan/probe arm.

The human-validation-gate markdown is the durable deliverable: recon/intel →
threat model → scan → exploit → document, with the analyst deciding the
exploitability step in between.

## Discoverability

- Arm catalog: `extension/coverage.yaml` (curated `ivanti` and `assetrecon`
  entries) and per-arm `README.md` under `extension/arms/`.
- Backend wiring: `extension/pipeline.py` imports the `tools/*.py` durable
  cores (`ctf_run_checks`, `demo_target_analysis`, `demo_rollup_hosts`,
  `demo_rank_hosts`, `render_provenance_header`).
- Pack role: `packs/ext_telecom_asmvm/docs/IVANTI_ARM_BRIDGE.md` documents how
  the `ivanti` arm feeds the pack bronze.
