# Operator pipeline

The CTF combines arm observations, optional pack findings, target ranking,
and threat-model hypotheses. The operator chooses the inputs and decides
which tool actions to run. The pipeline output is analysis, not a decision
about what the operator may do.

| Interface | Purpose |
| --- | --- |
| MCP `invoke` | Run a selected recon or scan arm. |
| `extension.pipeline.pack_run` | Run an externally supplied pack over a selected evidence directory. |
| `extension.pipeline.prioritize_targets` | Rank pack findings and describe possible attack chains. |
| MCP `list` / `describe` / `run_range` | Explore tools and the synthetic range. |

For example:

```python
from extension.pipeline import pack_run, prioritize_targets

packed = pack_run("<external-pack-root>", "<evidence-dir>",
                  out_dir="<report-dir>")
prioritized = prioritize_targets(report_path=packed["report_path"],
                                 out_path="<target-report.md>")
```

The operator-side pack and report paths are normal inputs to those Python
functions. `pack_run` and `prioritize_targets` are not MCP tools. The
generated report links hypotheses to supplied findings and suggests checks;
it does not certify the findings or restrict subsequent arm calls.

The arm catalog is `extension/coverage.yaml`. Per-arm input and output
details live under `extension/arms/`; the pack mapping comes from the
external pack's `mapping_spec.yaml`.
