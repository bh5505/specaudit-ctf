"""Per-check execution status in the loopback runner's report.json."""

import importlib.util
import json
from pathlib import Path

import pytest


CHECKS = {
    "checks/with-findings.sql": """\
SELECT name AS finding_key, 'found ' || name AS title,
       1 AS affected_count, 1 AS exposure_estimate,
       name AS record_locator, 'detail' AS details,
       ?1 AS run_id, 7 AS risk_score
FROM things
ORDER BY name
LIMIT ?2;
""",
    "checks/silent.sql": """\
SELECT name, 'silent', 1, 1, name, 'detail', ?1, 3
FROM things
WHERE 0 = 1
LIMIT ?2;
""",
    "checks/also-silent.sql": """\
SELECT name, 'also silent', 1, 1, name, 'detail', ?1, 1
FROM things
WHERE name = 'not-present'
LIMIT ?2;
""",
}


def _load_runner():
    path = Path(__file__).parents[1] / "tools" / "ctf_run_checks.py"
    spec = importlib.util.spec_from_file_location(
        "ctf_run_checks_report_status", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_pack_and_evidence(root, first_check_sql=None):
    pack = root / "pack"
    (pack / "checks").mkdir(parents=True)
    migrations = pack / "schema" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "001_things.sql").write_text(
        "CREATE TABLE things (\n"
        "  name VARCHAR, run_id VARCHAR, engagement_id VARCHAR,\n"
        "  accept_event_id VARCHAR\n);", encoding="utf-8")
    (pack / "manifest.yaml").write_text(
        "pack_id: status-pack\nchecks:\n"
        "  - id: C1\n    file: checks/with-findings.sql\n    severity: high\n"
        "  - id: C2\n    file: checks/silent.sql\n    severity: low\n"
        "  - id: C3\n    file: checks/also-silent.sql\n    severity: low\n",
        encoding="utf-8",
    )
    for relative, sql in CHECKS.items():
        if relative == "checks/with-findings.sql" and first_check_sql is not None:
            sql = first_check_sql
        (pack / relative).write_text(sql, encoding="utf-8")
    evidence = root / "evidence"
    evidence.mkdir()
    (evidence / "things.csv").write_text(
        "name\nalpha\nbeta\n", encoding="utf-8")
    return pack, evidence


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_report_records_every_check_in_manifest_order(tmp_path, engine, capsys):
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out = tmp_path / "out"

    assert runner.run(pack, evidence, out, engine, 100, "status-run") == 0

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    statuses = report["checks_status"]
    assert [status["check_id"] for status in statuses] == ["C1", "C2", "C3"]
    assert [status["file"] for status in statuses] == list(CHECKS)
    assert [status["row_count"] for status in statuses] == [2, 0, 0]
    assert all(isinstance(status["elapsed_ms"], int) for status in statuses)
    assert all(status["elapsed_ms"] >= 0 for status in statuses)

    assert len(report["findings"]) == 2
    assert {finding["check_id"] for finding in report["findings"]} == {"C1"}
    output = capsys.readouterr().out
    assert "check C2: 0 findings" in output
    assert "check C3: 0 findings" in output


def _check_with_safety(safety_expression):
    return """\
SELECT name AS finding_key, 'found ' || name AS title,
       1 AS affected_count, 1 AS exposure_estimate,
       name AS record_locator, 'detail' AS details,
       ?1 AS run_id, 7 AS risk_score, %s AS safety_json
FROM things
ORDER BY name
LIMIT ?2;
""" % safety_expression


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_optional_safety_json_object_is_stored(tmp_path, engine):
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    runner = _load_runner()
    sql = _check_with_safety("'{\"mode\":\"read-only\",\"retries\":2}'")
    pack, evidence = _make_pack_and_evidence(tmp_path, sql)
    out = tmp_path / "out"

    assert runner.run(pack, evidence, out, engine, 100, "safety-run") == 0

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert [finding["safety"] for finding in report["findings"]] == [
        {"mode": "read-only", "retries": 2},
        {"mode": "read-only", "retries": 2},
    ]
    assert [status["row_count"] for status in report["checks_status"]] == [2, 0, 0]


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
@pytest.mark.parametrize("safety_expression", [None, "NULL"])
def test_safety_is_absent_when_column_is_omitted_or_null(
        tmp_path, engine, safety_expression):
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    runner = _load_runner()
    sql = CHECKS["checks/with-findings.sql"] if safety_expression is None else \
        _check_with_safety(safety_expression)
    pack, evidence = _make_pack_and_evidence(tmp_path, sql)
    out = tmp_path / "out"

    assert runner.run(pack, evidence, out, engine, 100, "no-safety-run") == 0

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert all("safety" not in finding for finding in report["findings"])


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_malformed_safety_json_is_redacted_in_error(tmp_path, engine):
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    runner = _load_runner()
    raw_secret = "do-not-leak-raw"
    pack, evidence = _make_pack_and_evidence(
        tmp_path, _check_with_safety("'%s'" % raw_secret))

    with pytest.raises(runner.RunnerError) as caught:
        runner.run(pack, evidence, tmp_path / "out", engine, 100, "bad-safety-run")

    message = str(caught.value)
    assert "C1" in message
    assert "alpha" in message
    assert "malformed JSON" in message
    assert raw_secret not in message


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
@pytest.mark.parametrize("payload", ["[]", "\"text\""])
def test_non_object_safety_json_is_rejected(tmp_path, engine, payload):
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(
        tmp_path, _check_with_safety("'%s'" % payload))

    with pytest.raises(runner.RunnerError) as caught:
        runner.run(pack, evidence, tmp_path / "out", engine, 100, "bad-type-run")

    message = str(caught.value)
    assert "C1" in message
    assert "alpha" in message
    assert "expected a JSON object" in message
    assert payload not in message


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_safety_json_over_4k_is_rejected_without_raw_value(tmp_path, engine):
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    runner = _load_runner()
    marker = "oversize-secret-marker"
    payload = json.dumps({"value": marker + ("x" * 4096)})
    pack, evidence = _make_pack_and_evidence(
        tmp_path, _check_with_safety("'%s'" % payload))

    with pytest.raises(runner.RunnerError) as caught:
        runner.run(pack, evidence, tmp_path / "out", engine, 100, "large-safety-run")

    message = str(caught.value)
    assert "C1" in message
    assert "alpha" in message
    assert "maximum size is 4 KiB" in message
    assert marker not in message
