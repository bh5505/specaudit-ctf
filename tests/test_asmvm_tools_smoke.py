"""Smoke tests for the ASM/VM tools in tools/ (asmvm evidence builder, check
probe, CSV type preflight, live-fire helpers, SEIF round-trip projection).

These tools came out of the Glasswing pre-test loop, where each one encoded a
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


def test_duckdb_needs_fast_csv_for_typed_comparisons(mini_pack, mini_evidence,
                                                     tmp_path):
    """Characterisation, not aspiration: the row-by-row loader inserts CSV values
    as text, SQLite's dynamic typing forgives a numeric comparison written for
    typed columns and DuckDB does not. So a pack that claims both engines runs
    duckdb+--fast-csv and sqlite+row-by-row - two different loads - and
    csv_type_preflight is what says whether they see the same column types."""
    proc = _run([RUNNER, "--pack", str(mini_pack),
                 "--evidence-dir", str(mini_evidence),
                 "--out-dir", str(tmp_path / "out_row_duck"),
                 "--db", "duckdb", "--run-id", RUN_ID, "--limit", "100"],
                expect_ok=False)
    assert "smoke_vm_finding" in (proc.stderr + proc.stdout) or "severity" in proc.stderr
    _run([RUNNER, "--pack", str(mini_pack),
          "--evidence-dir", str(mini_evidence),
          "--out-dir", str(tmp_path / "out_row_sqlite"),
          "--db", "sqlite", "--run-id", RUN_ID, "--limit", "100"])


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
