# tools/ - ASM/VM evidence tooling

Scripts that build, repair and verify the evidence a pack runs on, plus two
instruments for the runner itself. They are used *around* `ctf_run_checks.py`;
none of them changes a check or a migration.

Run them from a directory that has no private paths baked in - every default
that used to point at somebody's laptop has been replaced by a required
argument (`--pack`, `--evidence-dir`, `--seif-src`, `--dns-name`, ...).

```bash
python tools/ctf_run_checks.py --pack ../packs/ext_telecom_asmvm \
    --evidence-dir <evidence> --out-dir out/run --db duckdb --fast-csv \
    --limit 500000 --run-id <run_id>
```

The pack's evidence CSVs carry a `run_id` column that the runner overwrites with
`--run-id` at load time ("accept lineage"), unless the pack's mapping declares
`run_id` as a mapped source. Keep that in mind when reading a run: the run_id in
the report is the run, not the file.

## Verification instruments

| script | what it is for |
| --- | --- |
| `csv_type_preflight.py` | Per table, per column: what does DuckDB's `read_csv` actually infer from the whole file, and from the *head* of it, versus what the migrations declare, versus what the mapping's value_map can emit. Reports (a) columns whose sample-window type differs from the whole-file type - `--fast-csv` samples by default, so a file whose early rows look numeric and later rows do not can load with a different type on a different day - and (b) columns whose sniffed type contradicts the DDL. A column that only the DDL declares (a generated column, or one the product's accept path derives) is reported as `ddl_only_column`, not as breakage. |
| `check_probe.py` | Runs one check with a wall-clock budget and, given `--candidate`, compares the rewritten SQL's result set to the original's row-for-row. This is how the t7 backlog check's rewrite was validated (see "The t7 rewrite" below). |

Both instruments exist because of concrete failures, and each one's docstring
says which. Read them before changing behaviour.

## Builders / converters

| script | what it is for |
| --- | --- |
| `build_asmvm_evidence.py`, `rebuild_evidence_asmvm.py` | Generate the pack's evidence CSVs (exporters, and the `ext_telecom_asmvm_asm_vm_surface` patch that rewrites asset-keyed rows onto real IP rows). |
| `capture_livefire.py` | Read-only verification of the pack's exposure claims against lab addresses: TCP banner grab and `openssl s_client` certificate capture, plus one DNS lookup. Nothing is mutated on the target; the host set is restricted to loopback/RFC1918 and the DNS name defaults to a `.local` name (`--dns-name`, `GLASSWING_DNS_PROBE_NAME`) so a stray lookup does not disclose anything. |
| `build_target_list.py` | Derives the live-fire target list from the pack's own reproduction queue (which endpoints the checks say are exposed), so the live-fire set is derived rather than invented. |
| `build_livefire_overlay.py` | Applies live observations to the evidence and re-runs the checks. The overlay is a delta: it patches existing rows (a host observed listening moves `has_active_service`/`is_exposed`), it does not invent new findings. |
| `replay_seif_asmvm.py`, `seif_ivanti_roundtrip.py`, `seif_roundtrip_export.py`, `seif_variant_c.py`, `seif_ivanti_asset_id_variant.py`, `make_seif_evidence_dir.py` | SEIF (asset/finding interchange) round trip: export evidence, read it back through the pack's own projection code, and report per column what survived. See the report for what does not survive. |
| `compare_reports.py` | Diff two run reports per check id. |

## The t7 rewrite, and what the two instruments have to say about it

`ext_telecom_asmvm_t7_asmvm_candidate_backlog.sql` builds its eligible
population as a non-aggregate CTE and then tests it with a correlated `EXISTS`.
SQLite cannot flatten that shape, so it re-evaluates the whole eligibility chain
per candidate row: on a 240k-finding corpus it ran **over two hours** where
DuckDB needed 0.09 s. Rewriting each eligibility branch as a *scalar aggregate*
subquery (one row per producer, uncorrelated) gives SQLite a constant to bind:
**SQLite 2.6-3.3 s, DuckDB 0.10 s, row-for-row identical on both engines**
(`check_probe.py --engine sqlite --budget 45` reports the original as
`TIMEOUT_INCOMPLETE` - note `progress_handler: armed`, which is what makes that
a real timeout rather than a slow run).

A first attempt that only materialised the aggregates (still a non-aggregate
`eligible` CTE) was still over 600 s on SQLite: what fixes it is removing the
correlation, not pre-aggregating.

`csv_type_preflight.py` caught the related ingest risk: the SEIF round trip's
first variant put Ivanti asset ids into `ip` (alias order prefers `Asset ID`),
and because those ids are all digits, DuckDB sniffed `vm_finding.ip` as
`BIGINT`. The pack's checks join `asm_vm_surface.ip = vm_finding.ip`, and
`asm_vm_surface.ip` is `VARCHAR`, so the DuckDB run died with

```
Conversion Error: Could not convert string '72.31.66.105' to INT64
LINE 42:     ON s.ip = f.ip
```

The preflight reported exactly that column (`declared VARCHAR`, `sniffed BIGINT`)
before the run was attempted.

## Engine notes (measured, not assumed)

- `--fast-csv` is required on DuckDB. The row-by-row loader inserts CSV values as
  text; SQLite's dynamic typing lets a check's `severity >= 9.0` through, DuckDB
  refuses to bind a DECIMAL against a VARCHAR. `tests/test_asmvm_tools_smoke.py`
  pins this.
- `--fast-csv` refuses a CSV whose headers name columns the migrations do not
  declare (mapping aliases are not applied on that path). Also pinned by a test.
- `check_probe.py`'s DuckDB path stamps run_id the same way the runner's fast
  path does. Without that, `WHERE run_id = ?1` silently matches nothing whenever
  the evidence files carry a different run id than `--run-id`, and a probe
  reports "ok rows=0" instead of "the evidence I loaded is not the evidence the
  check will look at".
- SQLite load of the 240k-row corpus takes ~31 s vs ~4.5 s on DuckDB; the whole
  pack run is ~4 min vs ~13 s. If a check looks pathological on one engine only,
  suspect join order and CTE inlining, not the data.
