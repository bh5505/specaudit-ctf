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
| `capture_livefire.py` | Read-only verification of the pack's exposure claims against lab addresses: TCP banner grab and `openssl s_client` certificate capture, plus one DNS lookup. Nothing is mutated on the target; the host set is restricted to loopback/RFC1918 and the DNS name defaults to a `.local` name (`--dns-name`, `ASMVM_DNS_PROBE_NAME`) so a stray lookup does not disclose anything. |
| `build_target_list.py` | Derives the live-fire target list from the pack's own reproduction queue (which endpoints the checks say are exposed), so the live-fire set is derived rather than invented. |
| `build_livefire_overlay.py` | Applies live observations to the evidence and re-runs the checks. The overlay is a delta: it patches existing rows (a host observed listening moves `has_active_service`/`is_exposed`), it does not invent new findings. |
| `replay_seif_asmvm.py`, `seif_ivanti_roundtrip.py`, `seif_roundtrip_export.py`, `seif_variant_c.py`, `seif_ivanti_asset_id_variant.py`, `make_seif_evidence_dir.py` | SEIF (asset/finding interchange) round trip: export evidence, read it back through the pack's own projection code, and report per column what survived. See the report for what does not survive. |
| `compare_reports.py` | Diff two run reports per check id. |

## Where column types come from (this one changed results, not just speed)

The loader used to create its tables from what the first chunk of CSV rows
looked like. The pack's migrations declare every column, and the two
disagreed in ways that changed findings:

- **SQLite.** A column full of numeric-looking text keeps TEXT affinity, and in
  SQLite any TEXT sorts above any REAL. So `MAX(severity) >= 9.8` was true for
  the text `'9.64'`, and `CAST('true' AS BOOLEAN)` is 0. On the corpus that was
  **3,998 findings scored 60 where the data said 58**, and credentialed-scan
  evidence turning into `false`. DuckDB typed the same column DOUBLE and got it
  right. Same SQL, same evidence, different answer.
- **DuckDB.** `read_csv` sniffed an `ip` column whose values happened to be all
  digits (an export that put Ivanti asset ids in `ip`) as BIGINT, and the
  `asm_vm_surface.ip = vm_finding.ip` join then died:
  `Conversion Error: Could not convert string '72.31.66.105' to INT64`. Two of
  three SEIF round-trip variants were unloadable for that reason alone.

`create_table` now takes its types from `schema/migrations`, and the DuckDB fast
path passes the same declared types to `read_csv(types=...)`. A cell that does
not fit its declared type is still loaded - as text, so a check can see it - and
is counted and printed (`WARNING <table>: N value(s) do not fit declared type
DOUBLE (first: 'not-a-number'); loaded as text`) instead of failing the run.
After the change DuckDB and SQLite produce 10,761 findings on the corpus and
**every finding agrees field for field**; before it 5,998 of 10,761 differed.
`tests/test_asmvm_tools_smoke.py` pins both halves: the declared type wins, and
the inference path demonstrably produces the wrong score.

## The t7 rewrite, and what the two instruments have to say about it

`ext_telecom_asmvm_t7_asmvm_candidate_backlog.sql` builds its eligible
population as a non-aggregate CTE and then tests it with a correlated `EXISTS`.
SQLite cannot flatten that shape, so it re-evaluates the whole eligibility chain
per candidate row: on a 240k-finding corpus it ran **over two hours** where
DuckDB needed 0.09 s. Rewriting each eligibility branch as a *scalar aggregate*
subquery (one row per producer, uncorrelated) gives SQLite a constant to bind:
row-for-row identical on both engines (`check_probe.py --engine sqlite --budget
45` reports the original as `TIMEOUT_INCOMPLETE` - note `progress_handler:
armed`, which is what makes that a real timeout rather than a slow run).

The rewrite's timings here were first measured on a **mistyped load** and read
2.6-3.3 s on SQLite; that number was an artifact. Once the loader typed the
columns as declared, the predicates had real work to do and SQLite needed over
**240 s** for that check even in the rewritten form, until the runner started
building join indexes (next section). Typed and indexed: **13.4 s**.

`sql/t7_asmvm_candidate_backlog.scalar_eligible.sql` is that rewrite, verified with
`check_probe.py` against the real corpus on both engines. `sql/t7_asmvm_candidate_backlog.materialised.sql`
is the first attempt - aggregates pre-computed but `eligible` still a
non-aggregate CTE - kept as the negative control: DuckDB 0.121 s and row-identical,
SQLite still `TIMEOUT_INCOMPLETE` at a 600 s budget (and ~18 min inside a full pack
run, which is where that run was killed). What fixes SQLite is removing the
correlation, not pre-aggregating.

It is a candidate, not a replacement: the pack's own check file is unchanged, and
swapping it in is the owner's call. Whoever swaps it should re-run
`check_probe.py --check <pack check> --candidate sql/t7_asmvm_candidate_backlog.scalar_eligible.sql`
on both engines against a corpus, and both full pack runs; the row sets were
identical when this was measured, on a corpus, not in the abstract.

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
before the run was attempted, and the loader fix is what actually prevents it:
`read_csv` is now given `types={...}` from the migrations, so a column the pack
declares `VARCHAR` stays `VARCHAR` no matter what the first rows look like. The
preflight is still worth running before a big ingest - it tells you the mapping
is putting asset ids where the pack expects addresses, which is a finding about
the mapping, long before a join fails.

## Engine notes (measured, not assumed)

- `--fast-csv` is the path production uses, but it is no longer a correctness
  option: both load paths type columns from the pack's migrations, so DuckDB
  with and without `--fast-csv` produces the same findings (`tests/test_asmvm_
  tools_smoke.py` pins the equality - it used to pin the opposite asymmetry,
  which was the bug).
- `--fast-csv` refuses a CSV whose headers name columns the migrations do not
  declare (mapping aliases are not applied on that path). Also pinned by a test.
- `check_probe.py`'s DuckDB path stamps run_id the same way the runner's fast
  path does. Without that, `WHERE run_id = ?1` silently matches nothing whenever
  the evidence files carry a different run id than `--run-id`, and a probe
  reports "ok rows=0" instead of "the evidence I loaded is not the evidence the
  check will look at".
- SQLite gets **join indexes derived from the pack's own checks**
  (`sqlite_join_indexes`): evidence arrives from CSV with no indexes at all, and
  a correlated aggregate across two 400k-row tables is a nested-loop scan. Twelve
  run_id-scoped indexes built in ~3 s took the candidate-backlog check from
  `>240 s` to `13.4 s`. DuckDB is skipped: it builds hash joins itself, and
  creating the same indexes there is work for nothing.
- Whole pack run on the 240k-row corpus, typed load, 2026-09-09: DuckDB ~1 min,
  SQLite ~2 min wall, 10,761 findings each. If a check looks pathological on one
  engine only, suspect join order and CTE inlining, then missing indexes - not
  the data.
- Detail text is rendered so the two engines agree: booleans through
  `CASE WHEN b THEN 'true' ELSE 'false' END` (DuckDB renders `true`, SQLite `1`)
  and timestamps through `SUBSTR(CAST(ts AS VARCHAR), 1, 19)` (microsecond text
  differs). `details` is what reaches the workpaper and the SARIF artifact, so
  this is a correctness property of the pack, not cosmetics; there is a test for
  the rendering difference itself.
