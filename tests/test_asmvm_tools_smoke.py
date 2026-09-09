"""Smoke tests for the ASM/VM tools in tools/ (asmvm evidence builder, check
probe, CSV type preflight, live-fire helpers, SEIF round-trip projection).

These tools came out of an ASM/VM rehearsal loop, where each one encoded a
defect found against real evidence. The tests keep the *reason they exist*
alive on a mini fixture - no scanner, no network, no vendor export:

* ctf_run_checks.py runs the same check SQL on both engines, so both engines
  have to agree row for row - asserted here on a 3-table mini pack.
* --fast-csv (DuckDB native read_csv) types columns from a sample and rejects a
  quoted value in a numeric column that the row-by-row SQLite path accepts: the
  engine asymmetry is asserted, not just documented.
* check_probe.py's SQLite budget depends on sqlite3's ``set_progress_handler``
  (the misspelled ``setprogresshandler`` made the timeout silently inert, which
  hid a check that had been running for two hours) - asserted via the JSON
  report's ``progress_handler`` field.
* t7's scalar-aggregate rewrite is reproducible at test scale: an equivalent
  candidate reports identical rows, a different one does not.
* live-fire target classification refuses public addresses (the egress policy
  is 'lab only'), and the overlay classifies banners into the vendor service
  taxonomy the pack already uses.
* the SEIF projection states, per column, what the round trip could not carry
  (qid/port/protocol have no SEIF home) instead of pretending they survived.

Hermetic like the rest of the suite: everything is built in tmp_path, subprocess
runs use sys.executable, no PATH binaries are needed.
"""

from __future__ import annotations

import csv
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import asmvm_evidence_builder as builder  # noqa: E402
import csv_type_preflight as preflight  # noqa: E402
import livefire_overlay as overlay  # noqa: E402
import livefire_target_list as target_list  # noqa: E402

RUNNER = str(TOOLS / "ctf_run_checks.py")
RUN_ID = "smoke-run-1"


# --------------------------------------------------------------------------
# mini pack: two evidence tables + a candidate queue, two checks
# --------------------------------------------------------------------------

DDL = """CREATE TABLE smoke_vm_finding (
    run_id VARCHAR,
    ip VARCHAR,
    severity DOUBLE,
    is_open BOOLEAN
)
"""

DDL_SERVICE = """CREATE TABLE smoke_service (
    run_id VARCHAR,
    ip VARCHAR,
    port BIGINT,
    has_active_service BOOLEAN
)
"""

DDL_CANDIDATE = """CREATE TABLE smoke_candidate (
    run_id VARCHAR,
    check_id VARCHAR,
    llm_verdict VARCHAR,
    passed_deterministic_gate BOOLEAN
)
"""

# 8-column row contract: finding_key, title, affected_count, exposure_estimate,
# record_locator, details, run_id, risk_score.
CHECK_T1 = """SELECT 'vm:' || f.ip AS finding_key,
       'critical open finding on exposed host ' || f.ip AS title,
       CAST(COUNT(*) AS BIGINT) AS affected_count,
       CAST(COUNT(*) AS BIGINT) AS exposure_estimate,
       'ip:' || f.ip AS record_locator,
       'severity=' || CAST(MAX(f.severity) AS VARCHAR) AS details,
       f.run_id AS run_id,
       90 AS risk_score
FROM smoke_vm_finding f
JOIN smoke_service s ON s.ip = f.ip AND CAST(s.has_active_service AS BOOLEAN)
WHERE f.run_id = ?1 AND CAST(f.is_open AS BOOLEAN) AND f.severity >= 9.0
GROUP BY f.ip, f.run_id
ORDER BY 1
LIMIT ?2
"""

# Same shape as the t7 backlog check: an aggregate eligible population joined
# to the candidate queue. Written in the scalar-aggregate form that SQLite can
# plan without an index (the shipped correlated-EXISTS form cannot).
CHECK_T2 = """WITH eligible AS (
    SELECT 'vm.scan' AS producer,
           (SELECT COUNT(*)
            FROM smoke_vm_finding f
            WHERE f.run_id = ?1 AND CAST(f.is_open AS BOOLEAN)
              AND f.severity >= 9.0) AS eligible_rows
)
SELECT 'queue:' || c.check_id AS finding_key,
       'candidate backlog for ' || c.check_id AS title,
       CAST(MAX(e.eligible_rows) AS BIGINT) AS affected_count,
       CAST(MAX(e.eligible_rows) - COUNT(*) AS BIGINT) AS exposure_estimate,
       'queue:' || c.check_id AS record_locator,
       'eligible=' || CAST(MAX(e.eligible_rows) AS VARCHAR)
         || '; queued=' || CAST(COUNT(*) AS VARCHAR) AS details,
       c.run_id AS run_id,
       20 AS risk_score
FROM smoke_candidate c
JOIN eligible e ON e.producer = c.check_id AND e.eligible_rows > 0
WHERE c.run_id = ?1
GROUP BY c.check_id, c.run_id
ORDER BY 1
LIMIT ?2
"""

MANIFEST = """pack_id: smoke_asmvm
checks:
  - id: smoke_t1_critical_on_exposed
    file: checks/smoke_t1.sql
    severity: high
    technique: smoke
  - id: smoke_t2_candidate_backlog
    file: checks/smoke_t2.sql
    severity: medium
    technique: smoke
"""


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture()
def mini_pack(tmp_path):
    pack = tmp_path / "pack"
    _write(pack / "manifest.yaml", MANIFEST)
    _write(pack / "schema" / "migrations" / "0001_smoke.sql",
           DDL + "\n" + DDL_SERVICE + "\n" + DDL_CANDIDATE)
    _write(pack / "checks" / "smoke_t1.sql", CHECK_T1)
    _write(pack / "checks" / "smoke_t2.sql", CHECK_T2)
    return pack


@pytest.fixture()
def mini_evidence(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    with (ev / "smoke_vm_finding.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id", "ip", "severity", "is_open"])
        w.writerows([
            ["stale", "10.0.0.5", "9.5", "true"],     # critical, open, exposed
            ["stale", "10.0.0.6", "2.0", "true"],     # low severity
            ["stale", "10.0.0.5", "9.9", "false"],    # closed: not eligible
            ["stale", "10.0.0.7", "9.7", "true"],     # critical, open, exposed
            ["stale", "10.0.0.8", "9.9", "true"],     # critical, no service
        ])
    with (ev / "smoke_service.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id", "ip", "port", "has_active_service"])
        w.writerows([
            ["stale", "10.0.0.5", "443", "true"],
            ["stale", "10.0.0.7", "22", "true"],
            ["stale", "10.0.0.8", "80", "false"],
            ["stale", "10.0.0.6", "8080", "true"],
        ])
    with (ev / "smoke_candidate.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id", "check_id", "llm_verdict",
                    "passed_deterministic_gate"])
        w.writerows([
            ["stale", "vm.scan", "pending", "true"],
            ["stale", "vm.scan", "duplicate", "false"],
        ])
    return ev


def _run(args, expect_ok=True):
    proc = subprocess.run([sys.executable] + args, capture_output=True,
                          text=True, timeout=300)
    if expect_ok and proc.returncode != 0:
        raise AssertionError("command failed (%s): %s\n%s"
                             % (proc.returncode, " ".join(args), proc.stderr[-2000:]))
    if not expect_ok and proc.returncode == 0:
        raise AssertionError("command unexpectedly succeeded: %s\n%s"
                             % (" ".join(args), proc.stdout[-2000:]))
    return proc


def _report(out_dir):
    return json.loads((Path(out_dir) / "report.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# runner: both engines, same rows
# --------------------------------------------------------------------------

def _shape(report):
    return sorted((f["finding_alias"], f["affected_count"],
                   f["exposure_estimate"], f["record_locator"], f["details"])
                  for f in report["findings"])


def test_runner_agrees_across_engines(mini_pack, mini_evidence, tmp_path):
    """DuckDB runs with --fast-csv and SQLite without it (the row-by-row loader
    types columns from the CSV sample, which DuckDB's strict typing rejects -
    see test_duckdb_needs_fast_csv_for_typed_comparisons). Both engines still
    have to agree row for row: that parity is what the pack depends on."""
    reports = {}
    for engine, extra in (("sqlite", []), ("duckdb", ["--fast-csv"])):
        out = tmp_path / ("run_" + engine)
        proc = _run([RUNNER, "--pack", str(mini_pack),
                     "--evidence-dir", str(mini_evidence),
                     "--out-dir", str(out), "--db", engine] + extra +
                    ["--run-id", RUN_ID, "--limit", "100"])
        assert "run %s (%s engine): 3 finding(s) total" % (RUN_ID, engine) in proc.stdout
        reports[engine] = _report(out)

    assert reports["sqlite"]["engine"] == "sqlite"
    assert reports["duckdb"]["engine"] == "duckdb"
    assert _shape(reports["sqlite"]) == _shape(reports["duckdb"])
    aliases = {f["finding_alias"] for f in reports["sqlite"]["findings"]}
    assert aliases == {
        "smoke_asmvm:smoke_t1_critical_on_exposed:vm:10.0.0.5",
        "smoke_asmvm:smoke_t1_critical_on_exposed:vm:10.0.0.7",
        "smoke_asmvm:smoke_t2_candidate_backlog:queue:vm.scan",
    }, "closed / unexposed / low-severity rows must not appear"
    # run_id is stamped at load, not read from the CSV (the CSVs say 'stale').
    # Eligible for the backlog check is "open and critical" (3 rows: 10.0.0.5,
    # 10.0.0.7 and 10.0.0.8 - reachability is not part of that producer's
    # eligibility, which is exactly what t7's eligible population counts), while
    # t1 above only reports the two that are also exposed.
    assert {f["details"] for f in reports["sqlite"]["findings"]
            if "eligible=" in f["details"]} == {"eligible=3; queued=2"}


def test_fast_csv_rejects_headers_the_migrations_do_not_declare(mini_pack,
                                                                mini_evidence,
                                                                tmp_path):
    """--fast-csv creates the table from the CSV itself, so a header the pack
    migrations never declared would silently widen the table; the runner refuses
    it and names the table and column. The row-by-row path accepts the same file
    (mapping aliases and value maps are allowed to rename columns), which is why
    the guard exists only on the fast path - and why csv_type_preflight exists."""
    bad = mini_evidence / "smoke_service.csv"
    rows = list(csv.reader(bad.open(encoding="utf-8")))
    rows[0].append("surprise_column")
    for row in rows[1:]:
        row.append("x")
    with bad.open("w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)

    proc = _run([RUNNER, "--pack", str(mini_pack),
                 "--evidence-dir", str(mini_evidence),
                 "--out-dir", str(tmp_path / "out_fast_bad"),
                 "--db", "duckdb", "--fast-csv",
                 "--run-id", RUN_ID, "--limit", "100"], expect_ok=False)
    assert "smoke_service" in (proc.stderr + proc.stdout)
    assert "surprise_column" in (proc.stderr + proc.stdout)

    _run([RUNNER, "--pack", str(mini_pack),
          "--evidence-dir", str(mini_evidence),
          "--out-dir", str(tmp_path / "out_row_ok"),
          "--db", "sqlite", "--run-id", RUN_ID, "--limit", "100"])


def test_duckdb_loads_the_same_way_with_and_without_fast_csv(mini_pack, mini_evidence,
                                                             tmp_path):
    """The loader takes column types from the pack's migrations, so the two
    DuckDB load paths (native read_csv with declared types, and row-by-row with
    converted values) agree.

    This used to be an asymmetry: the row-by-row path inserted everything as
    text and DuckDB then refused ``severity >= 9.0`` on a VARCHAR column, so
    ``--fast-csv`` was not a speed option but a correctness one. Typing from the
    DDL removed the difference; the fast path stays the one production uses."""
    reports = {}
    for tag, extra in (("fast", ["--fast-csv"]), ("rowby", [])):
        out = tmp_path / ("out_" + tag)
        _run([RUNNER, "--pack", str(mini_pack),
              "--evidence-dir", str(mini_evidence),
              "--out-dir", str(out),
              "--db", "duckdb"] + extra + ["--run-id", RUN_ID, "--limit", "100"])
        reports[tag] = _report(out)
    for field in ("finding_alias", "details", "risk_score", "affected_count"):
        assert [f[field] for f in reports["fast"]["findings"]] == \
            [f[field] for f in reports["rowby"]["findings"]], field
    assert reports["fast"]["findings"], "the mini pack must produce findings to compare"


def _load_mini_table_on_sqlite(module, evidence, tmp_path, table, ddl_types, tag="typed"):
    conn = sqlite3.connect(str(tmp_path / (tag + "-" + table + ".db")))
    conn.row_factory = sqlite3.Row
    with (evidence / (table + ".csv")).open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        headers = next(reader)
        rows = [row for row in reader]
    module.create_table(conn, "sqlite", table, rows, headers, ddl_types=ddl_types)
    return conn


def test_declared_ddl_types_beat_what_the_values_look_like(tmp_path):
    """The defect this guards: a column full of numeric-looking text keeps TEXT
    affinity in SQLite, and in SQLite any TEXT sorts above any REAL. A check
    written against the declared DOUBLE therefore silently becomes true for
    every row - measured on the corpus as 3,998 findings scoring 60 where the
    data said 58. Typing from the migrations is what makes the two engines
    agree; inferring from values is what made them disagree."""
    runner = pytest.importorskip("ctf_run_checks")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with (evidence / "smoke_vm_finding.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id", "ip", "severity", "is_open"])
        w.writerows([["stale", "10.0.0.5", "9.64", "true"],
                     ["stale", "10.0.0.6", "9.1", "false"]])
    ddl_types = {"smoke_vm_finding": {"run_id": "VARCHAR", "ip": "VARCHAR",
                                     "severity": "DOUBLE", "is_open": "BOOLEAN"}}
    score = ("SELECT CASE WHEN (SELECT MAX(severity) FROM smoke_vm_finding) >= 9.8 "
             "THEN 60 ELSE 58 END")

    typed = _load_mini_table_on_sqlite(runner, evidence, tmp_path,
                                       "smoke_vm_finding", ddl_types)
    types = {row[1]: row[2] for row in typed.execute("PRAGMA table_info(smoke_vm_finding)")}
    assert types["severity"].upper() == "DOUBLE"
    assert types["is_open"].upper() in ("BOOLEAN", "BOOL")
    assert typed.execute(score).fetchone()[0] == 58, "typed: 9.64 is not >= 9.8"
    # 'true' has to mean true: CAST('true' AS BOOLEAN) is 0 in SQLite
    assert typed.execute("SELECT COUNT(*) FROM smoke_vm_finding"
                         " WHERE CAST(is_open AS BOOLEAN)").fetchone()[0] == 1

    inferred = _load_mini_table_on_sqlite(runner, evidence, tmp_path,
                                         "smoke_vm_finding", None, tag="inferred")
    inferred_types = {row[1]: row[2] for row in
                      inferred.execute("PRAGMA table_info(smoke_vm_finding)")}
    assert inferred_types["severity"].upper() in ("TEXT", "VARCHAR"), (
        "value inference gives text affinity, which is the problem")
    assert inferred.execute(score).fetchone()[0] == 60, (
        "the value-inference path is the bug: text '9.64' compares >= 9.8 in SQLite")


def test_a_value_that_does_not_fit_its_declared_type_is_kept_and_reported(tmp_path,
                                                                          capsys):
    """Evidence with a bad cell should produce findings, not an exception - and
    the run has to say how many cells did not fit."""
    runner = pytest.importorskip("ctf_run_checks")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with (evidence / "smoke_vm_finding.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id", "ip", "severity", "is_open"])
        w.writerows([["stale", "10.0.0.5", "9.5", "true"],
                     ["stale", "10.0.0.6", "not-a-number", "true"]])
    ddl_types = {"smoke_vm_finding": {"run_id": "VARCHAR", "ip": "VARCHAR",
                                     "severity": "DOUBLE", "is_open": "BOOLEAN"}}
    conn = _load_mini_table_on_sqlite(runner, evidence, tmp_path,
                                      "smoke_vm_finding", ddl_types)
    rows = conn.execute("SELECT ip, severity FROM smoke_vm_finding ORDER BY ip").fetchall()
    assert [r[0] for r in rows] == ["10.0.0.5", "10.0.0.6"], "the bad row is not dropped"
    assert float(rows[0][1]) == 9.5
    assert rows[1][1] == "not-a-number", "kept as text so the check can still see it"
    captured = capsys.readouterr()
    runner.report_type_mismatches("smoke_vm_finding",
                                 {"severity": 1, "_sample_DOUBLE": "not-a-number"})
    reported = capsys.readouterr()
    out = captured.out + captured.err + reported.out + reported.err
    assert "smoke_vm_finding" in out and "severity" in out and "not-a-number" in out


def test_sqlite_join_indexes_come_from_the_pack_checks(tmp_path):
    """SQLite needs join indexes the hash-joining engine does not: without them
    an aggregate-per-candidate check over 400k-row evidence does not finish
    inside its budget (measured >240s unindexed, 13.4s after the runner built
    12 indexes derived from the pack's own JOIN clauses, whole pack run 1m57s).
    They are run_id-scoped and never created for DuckDB."""
    runner = pytest.importorskip("ctf_run_checks")
    conn = sqlite3.connect(str(tmp_path / "indexes.db"))
    for table in ("smoke_vm_finding", "smoke_service", "smoke_candidate"):
        conn.execute("CREATE TABLE %s (run_id TEXT, ip TEXT, cve TEXT)" % table)
    loaded = {"smoke_vm_finding", "smoke_service", "smoke_candidate"}
    runner.sqlite_join_indexes(conn, "sqlite", [CHECK_T1, CHECK_T2], loaded)
    indexed = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert "ix_smoke_vm_finding_run_id_ip" in indexed, indexed
    assert "ix_smoke_service_run_id_ip" in indexed, indexed

    duckdb = pytest.importorskip("duckdb")
    duck = duckdb.connect(str(tmp_path / "indexes.duckdb"))
    for table in ("smoke_vm_finding", "smoke_service", "smoke_candidate"):
        duck.execute("CREATE TABLE %s (run_id VARCHAR, ip VARCHAR, cve VARCHAR)" % table)
    runner.sqlite_join_indexes(duck, "duckdb", [CHECK_T1, CHECK_T2], loaded)
    assert duck.execute("SELECT COUNT(*) FROM duckdb_indexes()").fetchone()[0] == 0


def test_boolean_and_timestamp_detail_text_agrees_across_engines(tmp_path):
    """The pack renders details text as CASE ... 'true'/'false' and
    SUBSTR(CAST(ts AS VARCHAR), 1, 19) instead of CAST(bool/ts AS VARCHAR).
    Not cosmetics: on the corpus DuckDB and SQLite disagreed in the details
    string of 4,554 findings - true vs 1, and ...44.9893 vs ...44.989300 - and
    details is what reaches the workpaper and the SARIF artifact."""
    duckdb = pytest.importorskip("duckdb")
    sql = {
        "cast_bool": "SELECT CAST(is_open AS VARCHAR) FROM t",
        "case_bool": "SELECT CASE WHEN is_open THEN 'true' ELSE 'false' END FROM t",
        "cast_ts": "SELECT CAST(last_seen_ts AS VARCHAR) FROM t",
        "substr_ts": "SELECT SUBSTR(CAST(last_seen_ts AS VARCHAR), 1, 19) FROM t",
    }
    duck = duckdb.connect(str(tmp_path / "render.duckdb"))
    duck.execute("CREATE TABLE t (is_open BOOLEAN, last_seen_ts TIMESTAMP)")
    duck.execute("INSERT INTO t VALUES (true, '2026-08-17 13:53:44.989300')")
    lite = sqlite3.connect(str(tmp_path / "render.db"))
    lite.execute("CREATE TABLE t (is_open BOOLEAN, last_seen_ts TIMESTAMP)")
    lite.execute("INSERT INTO t VALUES (1, '2026-08-17 13:53:44.989300')")

    duck_values = {name: duck.execute(query).fetchone()[0] for name, query in sql.items()}
    lite_values = {name: lite.execute(query).fetchone()[0] for name, query in sql.items()}

    assert duck_values["cast_bool"] == "true" and lite_values["cast_bool"] == "1"
    assert duck_values["case_bool"] == lite_values["case_bool"] == "true"
    assert duck_values["cast_ts"] != lite_values["cast_ts"], (
        "microsecond text differs between the engines; if this stops being true "
        "the SUBSTR form is still the one to use")
    assert duck_values["substr_ts"] == lite_values["substr_ts"] == "2026-08-17 13:53:44"


def test_check_probe_reports_equivalence_and_arms_budget(mini_pack, mini_evidence,
                                                         tmp_path):
    base = mini_pack / "checks" / "smoke_t1.sql"
    # Rewrites are made inside the WHERE clause: an AND appended after ORDER BY
    # parses as a boolean sort key, not as a filter, and both engines then return
    # the same rows for the wrong reason.
    same = _write(tmp_path / "t1_rewritten.sql",
                  CHECK_T1.replace("f.severity >= 9.0",
                                   "f.severity >= 9.0 AND 1 = 1"))
    fewer = _write(tmp_path / "t1_narrower.sql",
                   CHECK_T1.replace("f.severity >= 9.0",
                                    "f.severity >= 9.0 AND f.ip <> '10.0.0.7'"))

    def probe(*extra):
        out = tmp_path / ("probe_%d.json" % len(list(tmp_path.glob("probe_*.json"))))
        _run([str(TOOLS / "check_probe.py"), "--pack", str(mini_pack),
              "--evidence-dir", str(mini_evidence), "--check", str(base),
              "--run-id", RUN_ID, "--limit", "100", "--budget", "120",
              "--out", str(out)] + list(extra))
        return json.loads(out.read_text(encoding="utf-8"))

    for engine, extra in (("sqlite", []), ("duckdb", ["--fast-csv"])):
        only = probe("--engine", engine, *extra)
        assert only["queries"][0]["status"] == "ok", only["queries"][0].get("error")
        assert only["queries"][0]["row_count"] == 2, (
            "loaded=%s run_id=%s" % (only.get("loaded"), only.get("run_id")))
        if engine == "sqlite":
            # Regression guard: the budget used to call a non-existent
            # setprogresshandler() inside a try/except, so the budget silently
            # never armed and a check that ran for two hours looked merely slow.
            # A TIMEOUT_INCOMPLETE result is only worth what the interrupt that
            # produced it is worth, so the report states whether it was armed.
            assert only["progress_handler"].startswith("armed"), only["progress_handler"]
        else:
            assert only["progress_handler"].startswith("not armed")

        eq = probe("--engine", engine, *extra, "--candidate", str(same))
        assert eq["equivalence"]["identical_rows"] is True, eq["equivalence"]
        assert eq["equivalence"]["identical_as_multiset"] is True
        assert eq["equivalence_extra"]["first_difference"] is None

        ne = probe("--engine", engine, *extra, "--candidate", str(fewer))
        assert ne["equivalence"]["identical_rows"] is False
        assert ne["equivalence"]["candidate_rows"] == 1
        assert ne["equivalence"]["original_rows"] == 2
        # A rewrite that drops rows is the failure mode the probe exists for:
        # the eligible-population rewrite must not change the row set.
        assert str(ne["equivalence_extra"]["first_difference"]).startswith("row 1"), \
            ne["equivalence_extra"]


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------

def test_target_list_refuses_public_addresses():
    """The live-fire leg is lab-only: anything public must be refused, not probed."""
    assert target_list.classify("10.0.0.5") == "lab_rfc1918"
    assert target_list.classify("192.168.2.1") == "lab_rfc1918"
    assert target_list.classify("169.254.1.1") == "lab_rfc1918"
    assert target_list.classify("127.0.0.1") == "loopback"
    assert target_list.classify("100.64.0.7") == "cgnat"
    assert target_list.classify("8.8.8.8") == "public"
    assert target_list.classify("gateway.internal") == "not_ipv4"
    assert target_list.ip_to_int("10.0.0.5") == (10 << 24) + 5
    assert target_list.ip_to_int("not-an-ip") is None


def test_overlay_maps_captures_to_pack_service_taxonomy():
    assert overlay.classify(443, "tcp", "open", "HTTP/1.1 200 OK", "TLSv1.3") == "HttpServer"
    assert overlay.classify(22, "tcp", "open", "SSH-2.0-OpenSSH_9.9", "") == "SshServer"
    assert overlay.classify(445, "tcp", "open", "", "") == "SmbFileServer"
    assert overlay.classify(53, "udp", "open", "dns rcode=NOERROR", "") == "DnsServer"
    assert overlay.classify(9999, "tcp", "open", "", "") == "UnidentifiedService"

    rec = {"http_server_header": "nginx/1.27.4", "tls_protocol": "TLSv1.3",
           "tls_cipher": "TLS_AES_256_GCM_SHA384",
           "cert_subject": "CN=unifi.local", "self_signed": "true",
           "http_status": "200"}
    assert overlay.product_version(rec) == (
        "nginx/1.27.4 TLSv1.3/TLS_AES_256_GCM_SHA384 cert CN=unifi.local "
        "(self-signed) HTTP 200")


def test_preflight_type_rules():
    """What --fast-csv will reject, stated as a predicate the tool can assert."""
    assert preflight.fails_type('"12"', "BIGINT") is True
    assert preflight.fails_type("http", "INTEGER") is True
    assert preflight.fails_type("12", "BIGINT") is False
    assert preflight.fails_type("", "BIGINT") is False       # empty = NULL = legal
    assert preflight.fails_type("maybe", "BOOLEAN") is True
    assert preflight.fails_type("TRUE", "BOOLEAN") is False
    assert preflight.fails_type("anything", "VARCHAR") is False


def test_preflight_reads_pack_migration_types(mini_pack):
    types = preflight.ddl_types(mini_pack)
    assert types["smoke_vm_finding"]["severity"].upper().startswith("DOUBLE")
    assert types["smoke_service"]["port"].upper().startswith("BIGINT")
    assert types["smoke_vm_finding"]["is_open"].upper().startswith("BOOLEAN")


def test_builder_lineage_spine_and_grouping_key():
    """The builder's two SQL fragments carry the lineage columns the pack's
    checks group findings by, and the ingest-computed CIDR grouping key that
    exists because string functions differ between the two engines."""
    spine = builder.spine("asm_export", "assets.csv", "asset_id", "asset_id", "asm")
    for column in ("source_system", "source_file", "source_row_id", "record_hash",
                   "lineage_batch_id", "mapping_version", "model_version",
                   "run_id", "engagement_id", "accept_event_id"):
        assert column in spine, column
    assert "row_number() OVER (ORDER BY asset_id)" in spine
    # derived rows synthesise the accept event; base rows copy it through
    assert "md5(concat('accept|asm|" in spine
    copied = builder.spine("asm_export", "assets.csv", "asset_id", "asset_id",
                           "asm", spine_from_src=True)
    assert "COALESCE(accept_event_id" in copied

    assert builder.prefix_expr("ip", 2, 16) == (
        "concat(SPLIT_PART(ip, '.', 1), '.', SPLIT_PART(ip, '.', 2), '.0.0/16')")
    assert builder.prefix_expr("ip", 3, 24) == (
        "concat(SPLIT_PART(ip, '.', 1), '.', SPLIT_PART(ip, '.', 2), '.', "
        "SPLIT_PART(ip, '.', 3), '.0/24')")


def test_seif_projection_states_what_the_round_trip_lost(tmp_path):
    pytest.importorskip("duckdb")           # module imports duckdb at the top
    import seif_ivanti_roundtrip as seif_rt

    seif = tmp_path / "findings.seif.json"
    seif.write_text(json.dumps({"findings": [
        {"finding_id": "ivanti-finding-1", "title": "Apache HTTP Server <2.4.63",
         "status": "active", "resource_uid": "10.0.0.5",
         "details": {"vrr": 9.8, "tags": ["Web Server"],
                     "Vulnerabilities": [{"Id": "CVE-2025-1234"}]}},
        {"finding_id": "ivanti-finding-2", "title": "Self-signed certificate",
         "status": "resolved", "resource_uid": "10.0.0.6",
         "details": {"vrr": 3.1, "tags": []}},
    ]}), encoding="utf-8")

    out_a = tmp_path / "vm_finding_a.csv"
    stats_a = seif_rt.project(str(seif), str(out_a), "A", "batch-1")
    rows = list(csv.DictReader(out_a.open(encoding="utf-8", newline="")))
    assert [r["ip"] for r in rows] == ["10.0.0.5", "10.0.0.6"]
    assert [r["is_open"] for r in rows] == ["true", "false"]
    # severity comes back as written: the converter copies details.vrr verbatim
    assert rows[0]["severity"] in (9.8, "9.8")
    # The loss statement, in the report rather than in the rows: SEIF has no
    # home for qid/port/protocol, and variant A carries no plugin family.
    assert stats_a["fields_with_no_seif_home"]["qid"] == 2
    assert stats_a["fields_with_no_seif_home"]["port"] == 2
    assert stats_a["fields_with_no_seif_home"]["protocol"] == 2
    assert all(r["qid"] == "" and r["port"] == "" for r in rows)
    assert all(r["plugin_family"] == "" for r in rows)
    assert stats_a["cve_pairs_in_seif"] == 1
    # The converter never sets first/last_observed_at, so last_found_ts is empty.
    assert stats_a["findings_with_last_observed_at"] == 0

    out_b = tmp_path / "vm_finding_b.csv"
    stats_b = seif_rt.project(str(seif), str(out_b), "B", "batch-1")
    rows_b = list(csv.DictReader(out_b.open(encoding="utf-8", newline="")))
    assert rows_b[0]["plugin_family"] == "Web Server"
    assert stats_b["fields_with_no_seif_home"]["plugin_family"] == 0


# --------------------------------------------------------------------------
# 10. indirect recon: corroborate ASM service claims without sending anything
# --------------------------------------------------------------------------


def _write_csv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(header + "\n")
        for row in rows:
            fh.write(",".join(str(cell) for cell in row) + "\n")


def _recon_module():
    import importlib
    return importlib.import_module("indirect_recon")


def test_indirect_recon_corroborates_and_disagrees_without_packets(tmp_path,
                                                                  monkeypatch):
    """A VM-feed observation on the same ip:port is corroboration; a claim that
    names a different service for that port is a disagreement; and none of it
    sent a packet, which is the only reason this arm is allowed to exist."""
    recon = _recon_module()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_csv(evidence / "ext_telecom_asmvm_service_endpoint.csv",
               "run_id,ip,port,protocol,service_name,service_type,"
               "product_version,source_system",
               [["r1", "10.0.0.1", 443, "tcp", "http server at api.internal:443",
                 "web", "", "asm"],
                ["r1", "10.0.0.2", 22, "tcp", "ssh", "remote access", "", "asm"],
                ["r1", "10.0.0.3", 7547, "tcp", "ftp", "file", "", "asm"],
                ["r1", "10.0.0.4", 65001, "tcp", "telemetry", "other", "", "asm"],
                ["r2", "10.9.9.9", 443, "tcp", "https", "web", "", "asm"]])
    _write_csv(evidence / "ext_telecom_asmvm_vm_finding.csv",
               "run_id,finding_id,ip,port,protocol,is_open,status",
               [["r1", "f1", "10.0.0.1", 443, "tcp", "true", "open"],
                ["r1", "f2", "10.0.0.1", 443, "tcp", "false", "resolved"],
                ["r1", "f3", "10.0.0.2", 80, "tcp", "true", "open"],
                ["r1", "f4", "10.0.0.3", 0, "tcp", "true", "open"]])

    # Hermetic registry: no dependence on the host's services file. Port 7547 is
    # in the tool's own known-unregistered table (TR-069/CWMP), so the
    # disagreement below is deterministic whatever the host has installed.
    monkeypatch.setattr(recon, "load_local_services",
                        lambda: {22: ("ssh", {"ssh"}),
                                 443: ("https", {"https"})})

    summary = recon.run(str(evidence), str(tmp_path / "out"), run_id="r1")

    rows = list(csv.DictReader((tmp_path / "out" / "indirect_recon_receipts.csv")
                               .open(encoding="utf-8")))
    by_ip = {row["ip"]: row for row in rows}
    assert summary["endpoints_examined"] == 4, "run_id must scope the scan"
    assert by_ip["10.0.0.1"]["label_agreement"] == "agree_by_equivalent_name"
    assert by_ip["10.0.0.1"]["vm_corroboration"] == "vm_feed_same_port"
    assert by_ip["10.0.0.1"]["vm_open_findings_on_port"] == "1", \
        "a resolved finding must not corroborate an open port"
    assert by_ip["10.0.0.2"]["label_agreement"] == "agree"
    assert by_ip["10.0.0.2"]["vm_corroboration"] == "vm_feed_same_ip_other_port"
    assert by_ip["10.0.0.3"]["label_agreement"] == "label_disagreement"
    assert by_ip["10.0.0.3"]["port_class"] == "cpe_management"
    assert by_ip["10.0.0.3"]["vm_corroboration"] == "no_vm_feed_observation", \
        "a finding with port 0 (not a per-port finding) says nothing about 7547"
    assert by_ip["10.0.0.4"]["label_agreement"] == "no_local_reference"

    assert summary["packets_sent"] == 0
    # The gate this arm must never claim: corroboration from data we already
    # hold is not an observation of the endpoint.
    assert set(summary["does_not_satisfy"]) >= {
        "live_fire", "independent_active_reproduction", "adversarial_reverify"}
    assert summary["evidence_class"] == recon.EVIDENCE_CLASS


def test_indirect_recon_label_comparison_is_conservative():
    """A wrong 'disagreement' sends an auditor to a port that is fine, so prose
    and unknown ports must not be called contradictions."""
    recon = _recon_module()

    names_443 = {"https"}
    assert recon.label_agreement(443, "http server at host.internal:443",
                                 names_443) == "agree_by_equivalent_name"
    assert recon.label_agreement(443, "https", names_443) == "agree"
    assert recon.label_agreement(443, "ssh", names_443) == "label_disagreement"
    assert recon.label_agreement(443, "a banner that names nothing usable",
                                 names_443) == "claim_not_comparable"
    assert recon.label_agreement(443, "", names_443) == "no_claim"
    assert recon.label_agreement(65001, "telemetry", set()) == "no_local_reference"
    # 7680 is in the pack's management list; winrm and wsman are one service
    assert recon.label_agreement(
        7680, "wsman",
        {"http", "winrm"}) == "agree_by_equivalent_name"
    # port classes come from the pack's classes, not invented here
    assert recon.classify(2152) == "gtp_core"
    assert recon.classify(7680) == "management_port"
    assert recon.classify(443) == "other"
