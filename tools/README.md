# tools/ - ASM/VM evidence tooling

Scripts that build, repair and verify the evidence a pack runs on, plus two
instruments for the runner itself. They are used *around* `ctf_run_checks.py`;
none of them changes a check or a migration.

Run them from a directory that has no private paths baked in - every default
that used to point at somebody's laptop has been replaced by a required
argument (`--pack`, `--evidence-dir`, `--seif-src`, `--dns-name`, ...).

```bash
python tools/ctf_run_checks.py --pack packs/ext_telecom_offsec \
    --evidence-dir <evidence> --out-dir out/run --db duckdb --fast-csv \
    --limit 500000 --run-id <run_id>
```

The runner stamps `--run-id` into each pack table's `run_id` column at load time
("accept lineage"). When a mapping declares `source_run_id`, it copies the
CSV's original run identifier there. The report's `run_id` names the check run,
while `source_run_id` names the source evidence run.

The evidence directory must contain one CSV for every table in the pack
manifest's `input_contract.required_tables`. A header-only CSV represents a
present, empty source. `asmvm_evidence_builder.py` projects the ASM/VM source
only; its output alone is incomplete for this consolidated pack. Supply AWS
posture and Technology candidate/validation CSVs from their respective
authorized producers before running the full pack. The runner refuses missing
sources before issuing any report.

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
| `asmvm_evidence_builder.py` | Generate the ASM/VM portion of the pack's evidence CSVs (exporters, and the `ext_telecom_offsec_asmvm_asm_vm_surface` patch that rewrites asset-keyed rows onto real IP rows). |
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

## T7 candidate coverage and diagnostic plans

The shipped `ext_telecom_offsec_asmvm_t7_asmvm_candidate_backlog.sql` matches
each accepted source identity to a candidate's exact `finding_key`. A VM
critical finding also requires its `vcand-<finding_id>` candidate ID. The query
counts logical source identities and queued candidates once across accept
events, so an unrelated candidate cannot cancel a missing source. It reports
definite backlog and over-queue alongside possible bounds and identity or
chronology uncertainty. Producers with no candidates or no eligible sources
still appear when the opposite side has rows.

Alert source keys use the accepted alert's vendor ID. Conflicting accepted
vendor IDs remain uncertain, with their observed IDs as possible keys.
The over-queue lower bound gives each possible source and each known candidate
at most one unit of support. Candidates with unknown keys use only remaining
possible source capacity, so a NULL key or overlapping ambiguous alert keys
cannot conceal an extra queued candidate.
For VM critical findings, a corroborated CVE pair excludes the finding
definitively only when all three pair components share its non-default accept
event. Vendor observation dates cannot establish the order of accept events;
cross-accept pair evidence therefore contributes to possible eligibility.

`sql/t7_asmvm_candidate_backlog.scalar_eligible.sql` retains its historical
filename and mirrors the shipped query's logic and complete output.
`sql/t7_asmvm_candidate_backlog.materialised.sql` explicitly materialises
reused source and queue identity sets for plan comparison. The parity test
compares complete rows under SQLite and DuckDB for repeated accepts, alert
vendor IDs and conflicts, queue-capacity overlap, wrong IDs, moved VM findings,
and known or unknown pair times. No performance result is claimed for these
revised plans; run
`check_probe.py` on a representative typed corpus before using either one for
performance decisions.

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
