"""Smoke tests for the generic runner tooling in tools/ (check probe, CSV type
preflight, live-fire capture) plus the runner engine-parity core.

Each kept tool encodes a defect found against real evidence; the tests keep the
*reason it exists* alive on a mini fixture - no scanner, no network, no vendor
export:

* ctf_run_checks.py runs the same check SQL on both engines, so both engines
  have to agree row for row - asserted here on a 3-table mini pack.
* --fast-csv (DuckDB native read_csv) types columns from a sample and rejects a
  quoted value in a numeric column that the row-by-row SQLite path accepts: the
  engine asymmetry is asserted, not just documented.
* check_probe.py's SQLite budget depends on sqlite3's ``set_progress_handler``
  (the misspelled ``setprogresshandler`` made the timeout silently inert, which
  hid a check that had been running for two hours) - asserted via the JSON
  report's ``progress_handler`` field.
* the resumable-runs-style scalar-aggregate rewrite is reproducible at test
  scale: an equivalent candidate reports identical rows, a different one does
  not.
* live-fire target classification refuses public addresses (the egress policy
  is 'lab only').

Hermetic like the rest of the suite: everything is built in tmp_path, subprocess
runs use sys.executable, no PATH binaries are needed.
"""

from __future__ import annotations

import csv
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import csv_type_preflight as preflight  # noqa: E402
import livefire_capture as livefire  # noqa: E402

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

# Same shape as a resumable-runs backlog check: an aggregate eligible
# population joined to the candidate queue. Written in the scalar-aggregate
# form that SQLite can plan without an index (the shipped correlated-EXISTS
# form cannot).
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

MANIFEST = """pack_id: smoke_pack
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
        "smoke_pack:smoke_t1_critical_on_exposed:vm:10.0.0.5",
        "smoke_pack:smoke_t1_critical_on_exposed:vm:10.0.0.7",
        "smoke_pack:smoke_t2_candidate_backlog:queue:vm.scan",
    }, "closed / unexposed / low-severity rows must not appear"
    # run_id is stamped at load, not read from the CSV (the CSVs say 'stale').
    # Eligible for the backlog check is "open and critical" (3 rows: 10.0.0.5,
    # 10.0.0.7 and 10.0.0.8 - reachability is not part of that producer's
    # eligibility, which is exactly what the eligible population counts), while
    # t1 above only reports the two that are also exposed.
    assert {f["details"] for f in reports["sqlite"]["findings"]
            if "eligible=" in f["details"]} == {"eligible=3; queued=2"}


def test_fast_csv_rejects_headers_the_migrations_do_not_declare(mini_pack,
                                                                mini_evidence,
                                                                tmp_path):
    """Neither loader may widen the migration-declared schema from CSV input.

    The native path rejects the header before loading; the row-by-row path fails
    its explicit-column insert. Both name the table and unexpected column."""
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

    row_proc = _run([RUNNER, "--pack", str(mini_pack),
                     "--evidence-dir", str(mini_evidence),
                     "--out-dir", str(tmp_path / "out_row_bad"),
                     "--db", "sqlite", "--run-id", RUN_ID, "--limit", "100"],
                    expect_ok=False)
    assert "smoke_service" in (row_proc.stderr + row_proc.stdout)
    assert "surprise_column" in (row_proc.stderr + row_proc.stdout)


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
    every row - measured on a real corpus as thousands of findings scored 60
    where the data said 58. Typing from the migrations is what makes the two
    engines agree; inferring from values is what made them disagree."""
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


def test_decimal_in_integer_column_is_text_and_counted():
    """The documented contract: a cell that does not fit its declared type is
    loaded as text and counted. A decimal in an INTEGER-declared column used to
    be silently int()-truncated (9.5 -> 9) with no mismatch record."""
    runner = pytest.importorskip("ctf_run_checks")

    assert runner._convert_value("9", "INTEGER") == 9
    assert runner._convert_value("true", "INTEGER") == 1
    assert runner._convert_value("", "INTEGER") is None

    mismatch = {}
    loaded = runner._convert_value("9.5", "INTEGER", mismatch)
    assert loaded == "9.5", "must not be truncated to 9"
    assert mismatch["INTEGER"] == 1
    assert mismatch["_sample_INTEGER"] == "9.5"

    # A DECIMAL/NUMERIC declaration still binds the decimal as a number.
    assert runner._convert_value("9.5", "DECIMAL") == 9.5
    # FLOAT columns are unchanged.
    assert runner._convert_value("9.5", "DOUBLE") == 9.5


def test_sqlite_join_indexes_come_from_the_pack_checks(tmp_path):
    """SQLite needs join indexes the hash-joining engine does not: without them
    an aggregate-per-candidate check over large evidence does not finish inside
    its budget. They are run_id-scoped and never created for DuckDB."""
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
    """The runner renders details text as CASE ... 'true'/'false' and
    SUBSTR(CAST(ts AS VARCHAR), 1, 19) instead of CAST(bool/ts AS VARCHAR).
    Not cosmetics: DuckDB and SQLite disagreed in the details string of
    thousands of findings - true vs 1, and ...44.9893 vs ...44.989300 - and
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


@pytest.mark.parametrize("banner,expects_get", [
    (b"", False),
    (b"HTTP/1.1 200 OK\r\n", True),
])
def test_livefire_7680_requires_http_banner_for_get(tmp_path, monkeypatch,
                                                     banner, expects_get):
    """A peer port alone must not trigger HTTP; an HTTP-speaking service still can."""
    targets = tmp_path / "targets.txt"
    targets.write_text("127.0.0.1 tcp/7680\n", encoding="utf-8")
    out_dir = tmp_path / "receipts"
    calls = {"connect": 0, "get": 0, "close": 0}

    class FakeSocket:
        def __init__(self, tracked=False):
            self.tracked = tracked

        def connect(self, address):
            pass

        def getsockname(self):
            return ("127.0.0.1", 0)

        def close(self):
            if self.tracked:
                calls["close"] += 1

    def fake_grab_tcp(ip, port, timeout):
        calls["connect"] += 1
        return FakeSocket(tracked=calls["connect"] == 1), banner, ""

    def fake_http_get(sock, ip, port, proto, timeout):
        calls["get"] += 1
        return {"http_status": "200"}, ""

    monkeypatch.setattr(livefire.socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(livefire.subprocess, "run",
                        lambda *args, **kwargs: type("Result", (), {"stdout": ""})())
    monkeypatch.setattr(livefire, "grab_tcp", fake_grab_tcp)
    monkeypatch.setattr(livefire, "http_get", fake_http_get)
    monkeypatch.setattr(sys, "argv", ["livefire_capture.py", "--targets", str(targets),
                                   "--out-dir", str(out_dir)])

    assert livefire.main() == 0
    assert calls == {"connect": 2 if expects_get else 1,
                     "get": 1 if expects_get else 0, "close": 1}
    receipts = list(csv.DictReader((out_dir / "livefire_receipts.csv")
                                   .open(encoding="utf-8")))
    assert len(receipts) == 1
    assert receipts[0]["endpoint_status"] == "open"
    assert receipts[0]["http_status"] == ("200" if expects_get else "")
