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
| `asmvm_evidence_builder.py` | Generate the pack's evidence CSVs (exporters, and the `ext_telecom_asmvm_asm_vm_surface` patch that rewrites asset-keyed rows onto real IP rows). |
| `livefire_capture.py` | Read-only verification of the pack's exposure claims against lab addresses: TCP banner grab and `openssl s_client` certificate capture, plus one DNS lookup. Nothing is mutated on the target; the host set is restricted to loopback/RFC1918 and the DNS name defaults to a `.local` name (`--dns-name`, `ASMVM_DNS_PROBE_NAME`) so a stray lookup does not disclose anything. |
| `livefire_target_list.py` | Derives the live-fire target list from the pack's own reproduction queue (which endpoints the checks say are exposed), so the live-fire set is derived rather than invented. |
| `livefire_overlay.py` | Applies live observations to the evidence and re-runs the checks. The overlay is a delta: it patches existing rows (a host observed listening moves `has_active_service`/`is_exposed`), it does not invent new findings. |
| `indirect_recon.py` | Corroborates ASM service claims using only data the pack already holds plus this host's local services file - **zero packets**. See "Indirect recon" below. |
| `seif_ivanti_roundtrip.py`, `seif_ivanti_asset_id_variant.py`, `make_seif_evidence_dir.py` | SEIF (asset/finding interchange) round trip: export evidence, read it back through the pack's own projection code, and report per column what survived. See the report for what does not survive. |
| `report_diff.py` | Diff two run reports per check id. |

## Indirect recon: what the data already knows about a claim (`indirect_recon.py`)

The reproduction queue in this pack is long because nothing outside the two feeds
has checked the ASM's claims. Actively checking means traffic to hosts that belong
to whoever the ASM describes - not ours to probe. Most of the question can still
be asked offline, from three things already in hand:

1. the vulnerability feed's **own port observations** on the same IP - a second
   sensor of the same estate, already in the pack's tables;
2. **this host's services file**, parsed rather than looked up, so no name service
   is consulted and a miss means "not in the file", not "the resolver did
   something"; plus a small table of telecom/infra ports the file does not know
   (GTP-C/GTP-U, SIGTRAN, TR-069, NETCONF) with where each assignment comes from;
3. the **pack's port classes** (telecom control plane, management ports).

Per claimed endpoint the receipt records whether the other sensor agrees the port
is open, whether the service name matches what that port normally carries, and
the port class. Service-name comparison is deliberately conservative: banner prose
that names the right service (`http server at host:443`) counts as agreement by
equivalent name, prose that names nothing comparable is `claim_not_comparable`,
and only a claim that names a different service is a `label_disagreement` - a
wrong disagreement sends an auditor to a port that is fine.

Measured on a 240k-finding corpus (77,098 ASM service endpoints, 39,845 IPs,
`packets_sent: 0`):

| observation | endpoints |
| --- | --- |
| VM feed open on the **same ip:port** | 2,196 (2.8 %) |
| VM feed open on the same IP, different port | 7,542 (9.8 %) |
| no VM-feed observation of that IP at all | 67,360 (87.4 %) |
| service label agrees with the port (incl. equivalents) | 72,955 |
| label is banner prose, not comparable | 2,359 |
| outright label disagreement | 0 |
| port unknown to this host's services file | 1,784 |
| telecom control-plane endpoints | 3,597 |

Two results are worth more than the tool cost. First, **2.8 %**: the ASM's
advertised surface is almost entirely uncorroborated by the vulnerability feed -
the visibility gap the pack's checks assert, now quantified with no traffic.
Second, this corpus carries **no `service_endpoint` rows at all** for GTP
(2123/2152/3386) or SIGTRAN (2905/2904/2901) even though those ports appear in
the surface census - a check that reads `service_endpoint` cannot see the telecom
control plane at all; only one reading the census can.

What it does not do, stated in the receipt itself: it is not live fire, not
independent **active** reproduction, not adversarial re-verification. The second
sensor is another dataset, not a new observation, so it must not be allowed to
flip a `has_live_fire` flag.

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
