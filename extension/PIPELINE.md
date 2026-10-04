# Operator pipeline

The recon→threat-model→prioritize loop uses admitted MCP `invoke` arms for
recon and probes. Pack execution and target prioritization run on the operator
side, where an operator can approve local evidence, custody, and output paths.
The attached MCP surface contains exactly four tools:

| Interface | step | purpose |
| --- | --- | --- |
| MCP `invoke` | 1, 4 | run an admitted recon or scan arm |
| Operator `extension.pipeline.pack_run` | 2 | approved evidence dir → pack `report.json` |
| Operator `extension.pipeline.prioritize_targets` | 3 | approved report → targets, threat models, **attack chains**, validation markdown |
| MCP `list` / `describe` / `run_range` | — | surface introspection / synthetic range |

## The governed 4-step path

1. **`invoke <recon arm>`** — gather intel through a first-party arm
   (assetrecon discovery, `ivanti` assets+findings pull, `gti` domain/VT intel).
   The `ivanti` arm is the governed Ivanti VM extractor; its flattened output is
   the pack's Ivanti bronze shape.
2. **Operator `pack_run`** — fold approved evidence into the `ext_telecom_offsec` pack and produce
   a deterministic `report.json` (the pack's ASM/VM findings, incl. T1190
   initial-access convergence).
3. **Operator `prioritize_targets`** — from the report, build a **prioritized target list
   with threat models and attack chains** that is passed to **human red-team
   analysts for validation** before any agentic exploitability validation. Each
   target carries `validation_status = "awaiting human red-team analyst
   validation"` and the summary declares the
   `human_validation_gate = "REQUIRED before any agentic exploitability
   validation"`.
4. **`invoke <scan arm>`** — after human validation, exercise the converged
   initial-access hypothesis with a live scan/probe arm.

For example, after reviewing the evidence directory and choosing a report
destination, an operator can call the Python API:

```python
from extension.pipeline import pack_run, prioritize_targets

packed = pack_run("packs/ext_telecom_offsec", approved_evidence_dir,
                  out_dir=approved_report_dir)
prioritized = prioritize_targets(report_path=packed["report_path"],
                                  out_path=approved_validation_report_path)
```

These local paths are trusted operator inputs; do not relay attached-agent path
arguments into the API. `tools/ctf_run_checks.py` and the `tools/demo_*` commands
remain available for operator workflows. Calls to `pack_run` or
`prioritize_targets` through MCP return an unknown-tool error before filesystem
access.

The human-validation-gate markdown is the durable deliverable: recon/intel →
threat model → scan → exploit → document, with the analyst deciding the
exploitability step in between.

## Discoverability

- Arm catalog: `extension/coverage.yaml` (curated `ivanti` and `assetrecon`
  entries) and per-arm `README.md` under `extension/arms/`.
- Operator pipeline: `extension/pipeline.py` imports the `tools/*.py` durable
  cores (`ctf_run_checks`, `demo_target_analysis`, `demo_rollup_hosts`,
  `demo_rank_hosts`, `render_provenance_header`).
- Pack input: `tools/asmvm_evidence_builder.py` prepares rehearsal evidence;
  `packs/ext_telecom_offsec/synthetic/mapping_spec.yaml` declares the CSV inputs
  accepted by the unified pack.
