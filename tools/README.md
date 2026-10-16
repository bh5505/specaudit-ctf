# tools/ - pack evidence tooling

Scripts that prepare, run and verify pack check executions, plus the demo-arc
analyses built on a run's durable output. They are used *around*
`ctf_run_checks.py`; none of them changes a check or a migration.

This repository ships no pack: every pack is an explicit, operator-supplied
path. Run the tools from a directory that has no private paths baked in - every
default that used to point at somebody's laptop has been replaced by a required
argument (`--pack`, `--evidence-dir`, `--dns-name`, ...).

```bash
python tools/ctf_run_checks.py --pack <external-pack-root> \
    --evidence-dir <evidence> --out-dir out/run --db duckdb --fast-csv \
    --limit 500000 --run-id <run_id>
```

In the joint-run environment the `<external-pack-root>` is supplied by the
external pack checkout itself (the path to that checkout's pack root); the
invocation is identical - the runner only ever sees the explicit `--pack`
path.

`--db sqlite` runs the pack's check SQL on Python's built-in `sqlite3`. A
pack whose SQL needs newer SQLite features (for example ordered
`string_agg`, SQLite 3.44+) fails at that check with sqlite's own error on
an older build; use `--db duckdb` for such packs. The runner itself sets
no SQLite version floor.

The runner stamps `--run-id` into each pack table's `run_id` column at load time
("accept lineage"). When a mapping declares `source_run_id`, it copies the
CSV's original run identifier there. The report's `run_id` names the check run,
while `source_run_id` names the source evidence run.

The evidence directory must contain one CSV for every table in the pack
manifest's `input_contract.required_tables`. A header-only CSV represents a
present, empty source. The runner refuses missing sources before issuing any
report.

## Demo-arc analyses (durable pack-output consumers)

These compose into the operator pipeline (`extension/pipeline.py`): pack
report -> rollup -> ranking -> target analysis. Each has a pure-stdlib core the
pipeline imports, plus a CLI. They are check-id agnostic: technique context is
recognized by `technique=`/`tactic=` markers in finding details, and tiers
derive from finding severity and locator shape.

| script | what it is for |
| --- | --- |
| `demo_rollup_hosts.py` | Build the host rollup (`tiers`, `rollup_top_risk`, `hosts_ranked`) from a report.json. Default tiers are content-derived (`technique_context`, `critical_flagship`, `port_corroborated`); an operator-supplied check-id -> tier mapping overrides the derivation verbatim for the check ids present. |
| `demo_rank_hosts.py` | Rank the technique-contexted hosts: 100 for the port-corroborated tier, plus dominant provenance, row/stage counts and max report risk. Deterministic tie-breaks. |
| `demo_target_analysis.py` | Per-IP technique/port/tier/risk rollup, curated CVE->technique cross-reference, initial-access convergence, and a grounded multi-step ATT&CK attack-path markdown deliverable. |
| `demo_alert_pairings.py` | Per-alert technique pair extraction over the silver CSVs (DuckDB in-memory). The base tables (`--tables a,b,c`) and the join predicate (`--predicate-file`, may reference `{placeholders}` for the focus-IP parameters) are operator-supplied joint-run configuration; with no tables configured pairing is unavailable and the result is empty. |

## Verification instruments

| script | what it is for |
| --- | --- |
| `csv_type_preflight.py` | Per table, per column: what does DuckDB's `read_csv` actually infer from the whole file, and from the *head* of it, versus what the migrations declare, versus what the mapping's value_map can emit. Reports (a) columns whose sample-window type differs from the whole-file type - `--fast-csv` samples by default, so a file whose early rows look numeric and later rows do not can load with a different type on a different day - and (b) columns whose sniffed type contradicts the DDL. A column that only the DDL declares (a generated column, or one the accept path derives) is reported as `ddl_only_column`, not as breakage. |
| `check_probe.py` | Runs one check standalone with a wall-clock budget and, given `--candidate`, compares the rewritten SQL's result set to the original's row-for-row. The dogfood runner has no `--only-check`, so this is how a single slow check is timed, explained or A/B-tested without loading the whole pack. |
| `report_diff.py` | Diff two pack report.json files per check id: same check set, same per-check counts, same finding_alias sets. |
| `livefire_capture.py` | Read-only verification of exposure claims against lab addresses: TCP banner grab and `openssl s_client` certificate capture, plus one DNS lookup. Nothing is mutated on the target; the host set is restricted to loopback/RFC1918/CGNAT and the DNS name defaults to a `.local` name (`--dns-name`, `LAB_DNS_PROBE_NAME`) so a stray lookup does not disclose anything. |
| `validator_technology_harness.py` | Exercise the Rust technology probe path with synthetic provider replies (fixture cases under `tests/fixtures/technology_validator/`); never starts a provider process. |

Each instrument exists because of a concrete failure; the docstrings say which.
Read them before changing behaviour.

## Where column types come from (this one changed results, not just speed)

The loader used to create its tables from what the first chunk of CSV rows
looked like. Pack migrations declare every column, and the two disagreed in
ways that changed findings:

- **SQLite.** A column full of numeric-looking text keeps TEXT affinity, and in
  SQLite any TEXT sorts above any REAL. So `MAX(severity) >= 9.8` was true for
  the text `'9.64'`, and `CAST('true' AS BOOLEAN)` is 0. Same SQL, same
  evidence, different answer than the typed load.
- **DuckDB.** `read_csv` sniffed an `ip` column whose values happened to be all
  digits (an export that put asset ids in `ip`) as BIGINT, and an
  `surface.ip = finding.ip` join then died:
  `Conversion Error: Could not convert string '72.31.66.105' to INT64`.

`create_table` now takes its types from the pack's `schema/migrations`, and the
DuckDB fast path passes the same declared types to `read_csv(types=...)`. A
cell that does not fit its declared type is still loaded - as text, so a check
can see it - and is counted and printed (`WARNING <table>: N value(s) do not
fit declared type DOUBLE (first: 'not-a-number'); loaded as text`) instead of
failing the run. After the change DuckDB and SQLite produce identical findings
field for field.
`tests/test_runner_tools_smoke.py` pins both halves: the declared type wins,
and the inference path demonstrably produces the wrong score.

## Engine notes (measured, not assumed)

- `--fast-csv` is the fast path, and typing columns from the pack's migrations
  makes it a parity path too: DuckDB with and without `--fast-csv` produces the
  same findings (`tests/test_runner_tools_smoke.py` pins the equality - it used
  to pin the opposite asymmetry, which was the bug).
- `--fast-csv` refuses a CSV whose headers name columns the migrations do not
  declare (mapping aliases are not applied on that path). Also pinned by a test.
- `check_probe.py`'s DuckDB path stamps run_id the same way the runner's fast
  path does. Without that, `WHERE run_id = ?1` silently matches nothing whenever
  the evidence files carry a different run id than `--run-id`, and a probe
  reports "ok rows=0" instead of "the evidence I loaded is not the evidence the
  check will look at".
- SQLite gets **join indexes derived from the pack's own checks**
  (`sqlite_join_indexes`): evidence arrives from CSV with no indexes at all, and
  a correlated aggregate across two large tables is a nested-loop scan. The
  run_id-scoped indexes are built from the checks' JOIN clauses; DuckDB is
  skipped, because it builds hash joins itself and creating the same indexes
  there is work for nothing.
- If a check looks pathological on one engine only, suspect join order and CTE
  inlining, then missing indexes - not the data.
- Detail text is rendered so the two engines agree: booleans through
  `CASE WHEN b THEN 'true' ELSE 'false' END` (DuckDB renders `true`, SQLite `1`)
  and timestamps through `SUBSTR(CAST(ts AS VARCHAR), 1, 19)` (microsecond text
  differs). `details` is what reaches the workpaper and the SARIF artifact, so
  this is a correctness property, not cosmetics; there is a test for the
  rendering difference itself.
