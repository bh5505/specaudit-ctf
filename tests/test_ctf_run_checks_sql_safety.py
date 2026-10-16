"""Security regressions for the local CTF SQL materializer."""

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest


def _load_runner():
    path = Path(__file__).parents[1] / "tools" / "ctf_run_checks.py"
    spec = importlib.util.spec_from_file_location("ctf_run_checks_security", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(("value", "expected"), [
    ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("réseau 🔒", "fb6c81e8cd0fbad82a0662c915da078f67c789ff9fa13ccfcc9121a192128494"),
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (None, None),
])
def test_sqlite_sha256_hashes_utf8_text_and_preserves_null(value, expected):
    runner = _load_runner()
    connection, engine = runner.open_engine("sqlite")
    try:
        assert engine == "sqlite"
        assert connection.execute("SELECT sha256(?)", (value,)).fetchone() == (expected,)
    finally:
        connection.close()


def test_sqlite_run_has_no_runner_version_floor(monkeypatch, tmp_path):
    runner = _load_runner()
    # The runner imposes no SQLite version floor: a simulated older SQLite
    # still opens and runs simple portable check SQL to completion. Packs
    # needing newer SQLite features fail at their own check with sqlite's
    # error rather than a pre-flight admission refusal.
    monkeypatch.setattr(runner.sqlite3, "sqlite_version_info", (3, 43, 2))
    pack = tmp_path / "pack"
    (pack / "checks").mkdir(parents=True)
    migrations = pack / "schema" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "001_things.sql").write_text(
        "CREATE TABLE things (\n"
        "  name VARCHAR, run_id VARCHAR, engagement_id VARCHAR,\n"
        "  accept_event_id VARCHAR\n);", encoding="utf-8")
    (pack / "manifest.yaml").write_text(
        "pack_id: demo_pack\n"
        "checks:\n  - id: demo_pack_t1_probe\n    file: checks/probe.sql\n",
        encoding="utf-8")
    (pack / "checks" / "probe.sql").write_text(
        "SELECT 'k', 't', 1, 1, 'loc', 'd', ?1, 0 LIMIT ?2;\n", encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "things.csv").write_text("name\nalpha\n", encoding="utf-8")
    rc = runner.run(pack, evidence, tmp_path / "out", "sqlite", 100,
                    "older-sqlite-still-runs")
    assert rc == 0
    report = json.loads(
        (tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert len(report["findings"]) == 1


def _create_test_table(runner, connection, engine, table, rows, headers):
    """Focused helper for lineage tests whose tables are not pack fixtures."""
    cols = runner._infer_columns(rows, headers)
    connection.execute(
        "CREATE TABLE %s (%s)" % (
            runner._quote_identifier(table),
            ", ".join("%s %s" % (runner._quote_identifier(name), coltype)
                      for name, coltype in cols),
        )
    )
    runner.insert_evidence_rows(connection, engine, table, rows, headers)


def test_materializer_quotes_untrusted_table_and_csv_header_identifiers():
    runner = _load_runner()
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE sentinel (value INTEGER)")
    connection.execute("INSERT INTO sentinel VALUES (1)")

    table = 'evidence"; DROP TABLE sentinel; --'
    header = 'field"; DROP TABLE sentinel; --'
    _create_test_table(runner, connection, "sqlite", table, [["value"]], [header])
    runner.stamp_accept_lineage(connection, table, [header], "run-1")

    assert connection.execute("SELECT value FROM sentinel").fetchall() == [(1,)]
    quoted_table = runner._quote_identifier(table)
    assert connection.execute(
        f"SELECT {runner._quote_identifier(header)}, run_id FROM {quoted_table}"
    ).fetchall() == [("value", "run-1")]


# ---------------------------------------------------------------------------
# Synthetic check-run ledger pack: a mapping spec declaring the source-run
# identity alias plus a status value_map, and a resumable-runs check bound to
# ?1 run_id / ?2 limit. Hermetic stand-in for an operator-supplied pack.
# ---------------------------------------------------------------------------

CHECK_RUN_TABLE = "demo_check_run"

_LEDGER_MANIFEST = """pack_id: demo_pack
contributes:
  ingest:
    mapping_spec_path: synthetic/mapping_spec.yaml
"""

_LEDGER_MAPPING_SPEC = """mappings:
  - source_pattern: demo_check_run.csv
    silver_table: demo_check_run
    columns:
      - target: source_run_id
        aliases: [run_id, batch id]
      - target: status
        value_map:
          interrupted: interrupted
          running: running
"""

# Same contract as a pack's resumable-runs check: flags ledger rows that are
# interrupted, or internally inconsistent (no finish time and a checkpoint
# older than the start). source_run_id identifies the source ledger row;
# run_id is the engine scope. Bound params: ?1 = run_id, ?2 = row limit.
_LEDGER_RESUMABLE_SQL = """SELECT
    'run:' || CAST(LENGTH(cr.source_run_id) AS VARCHAR) || ':' || cr.source_run_id || ':' ||
        CAST(LENGTH(cr.accept_event_id) AS VARCHAR) || ':' || cr.accept_event_id AS finding_key,
    'Interrupted or non-resumable check run: ' || cr.source_run_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    cr.source_run_id || ' / ' || cr.accept_event_id || ' / ' || COALESCE(cr.status, '') AS record_locator,
    'status=' || COALESCE(cr.status, '') || '; finished_at=' ||
        COALESCE(CAST(cr.finished_at AS VARCHAR), '') AS details,
    cr.run_id AS run_id,
    25 AS risk_score
FROM demo_check_run cr
WHERE cr.run_id = ?1
  AND (
    cr.status = 'interrupted'
    OR (cr.finished_at IS NULL AND cr.checkpoint_ts < cr.started_at)
  )
ORDER BY finding_key
LIMIT ?2;
"""


@pytest.fixture()
def ledger_pack(tmp_path):
    pack = tmp_path / "pack"
    (pack / "synthetic").mkdir(parents=True)
    (pack / "checks").mkdir()
    (pack / "manifest.yaml").write_text(_LEDGER_MANIFEST, encoding="utf-8")
    (pack / "synthetic" / "mapping_spec.yaml").write_text(
        _LEDGER_MAPPING_SPEC, encoding="utf-8")
    (pack / "checks" / "demo_pack_t7_resumable_runs.sql").write_text(
        _LEDGER_RESUMABLE_SQL, encoding="utf-8")
    return pack


def _t7_sql(pack, engine):
    sql = (pack / "checks" / "demo_pack_t7_resumable_runs.sql").read_text()
    if engine == "duckdb":
        # DuckDB uses positional '?' whereas SQLite accepts numbered '?N'.
        sql = sql.replace("?1", "?").replace("?2", "?")
    return sql


def test_duplicate_mapping_pattern_fails_before_any_csv_is_loaded(tmp_path):
    runner = _load_runner()
    (tmp_path / "manifest.yaml").write_text(
        "contributes:\n  ingest:\n    mapping_spec_path: mapping_spec.yaml\n",
        encoding="utf-8",
    )
    (tmp_path / "mapping_spec.yaml").write_text(
        "mappings:\n"
        "  - source_pattern: findings.csv\n"
        "    silver_table: first_table\n"
        "  - source_pattern: findings.csv\n"
        "    silver_table: second_table\n",
        encoding="utf-8",
    )
    with pytest.raises(runner.RunnerError, match="duplicate source_pattern"):
        runner.load_mapping_spec(tmp_path)


def test_overlapping_mapping_patterns_refuse_ambiguous_csv():
    runner = _load_runner()
    with pytest.raises(runner.RunnerError, match="ambiguous source filename"):
        runner._table_for({"*assets.csv": "asm_asset", "assets.csv": "vm_asset"},
                          "assets.csv")


def test_completeness_gate_uses_the_input_contract_not_a_self_declared_pack_id():
    runner = _load_runner()
    with pytest.raises(runner.RunnerError, match="required source table"):
        runner.require_complete_evidence(
            {"pack_id": "other-pack", "input_contract": {
                "required_tables": ["source_table"]}}, [])
    with pytest.raises(runner.RunnerError, match="required source table"):
        runner.require_complete_evidence(
            {"pack_id": "renamed-pack", "checks": [{
                "id": "demo_pack_t1_exposed"}],
             "input_contract": {"required_tables": ["source_table"]}}, [])
    with pytest.raises(runner.RunnerError, match="required_tables"):
        runner.require_complete_evidence(
            {"pack_id": "demo_pack", "checks": [{
                "id": "demo_pack_t1_exposed"}],
             "input_contract": {"required_tables": []}}, [])


def _event_key(source_id, accept_event_id):
    return (f"run:{len(source_id)}:{source_id}:"
            f"{len(accept_event_id)}:{accept_event_id}")


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_declared_value_map_normalizes_mixed_case_status(ledger_pack, engine):
    """Noncanonical status text must normalize via the DECLARED value_map.

    Reads the pack's mapping_spec through the existing loader (no private
    dictionary), applies it, and observes the result: 'Interrupted' and padded
    '  INTERRUPTED  ' land canonical and fire the resumable-runs check; an
    unmapped status passes through verbatim and fires nothing.
    """
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    status_map = runner.load_mapping_value_maps(ledger_pack)[CHECK_RUN_TABLE]["status"]
    assert status_map["interrupted"] == "interrupted"  # declared, not invented
    # CSV already carries the target plus an alias: rename must not duplicate.
    headers_in = ["source_run_id", "run_id", "status", "started_at",
                  "finished_at", "checkpoint_ts", "pages_completed"]
    renamed = runner.apply_mapping_column_aliases(
        runner.load_mapping_columns(ledger_pack), CHECK_RUN_TABLE, headers_in
    )
    assert renamed == headers_in
    assert renamed.count("source_run_id") == 1
    rows = [
        ["src-mixed", "stale-run-1", "Interrupted",
         "2026-01-01T00:00:00", "", "2026-01-01T00:05:00", "1"],
        ["src-padded", "stale-run-2", "  INTERRUPTED  ",
         "2026-01-01T00:00:00", "", "2026-01-01T00:05:00", "1"],
        ["src-canon", "stale-run-3", "interrupted",
         "2026-01-01T00:00:00", "", "2026-01-01T00:05:00", "1"],
        # finished_at set so only the status predicate could fire for this row.
        ["src-other", "stale-run-4", "weird-unmapped",
         "2026-01-01T00:00:00", "2026-01-01T00:10:00",
         "2026-01-01T00:05:00", "1"],
    ]
    normalized = runner.apply_mapping_value_maps(
        runner.load_mapping_value_maps(ledger_pack),
        CHECK_RUN_TABLE, renamed, rows,
    )
    assert [row[2] for row in normalized] == [
        "interrupted", "interrupted", "interrupted", "weird-unmapped",
    ]
    connection, engine = runner.open_engine(engine)
    try:
        _create_test_table(runner, connection, engine, CHECK_RUN_TABLE,
                           normalized, renamed)
        runner.stamp_accept_lineage(connection, CHECK_RUN_TABLE,
                                    renamed, "execution-current")
        stored = {r[0]: (r[1], r[2]) for r in connection.execute(
            "SELECT source_run_id, run_id, status FROM %s"
            % runner._quote_identifier(CHECK_RUN_TABLE)).fetchall()}
        assert stored == {
            "src-mixed": ("execution-current", "interrupted"),
            "src-padded": ("execution-current", "interrupted"),
            "src-canon": ("execution-current", "interrupted"),
            "src-other": ("execution-current", "weird-unmapped"),
        }
        sql = _t7_sql(ledger_pack, engine)
        findings = connection.execute(sql, ["execution-current", 100]).fetchall()
        assert {row[0] for row in findings} == {
            _event_key("src-mixed", runner.ZERO_ACCEPT_EVENT_ID),
            _event_key("src-padded", runner.ZERO_ACCEPT_EVENT_ID),
            _event_key("src-canon", runner.ZERO_ACCEPT_EVENT_ID),
        }
        assert all(row[-2] == "execution-current" for row in findings)
        assert connection.execute(sql, ["execution-sibling", 100]).fetchall() == []
    finally:
        connection.close()


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_stamp_accept_lineage_overwrites_stale_triple(engine):
    """Preexisting stale run_id/engagement_id/accept_event_id become ambient."""
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    headers = ["id", "run_id", "engagement_id", "accept_event_id"]
    rows = [["a", "stale-run", "stale-engagement",
             "11111111-1111-1111-1111-111111111111"],
            ["b", "stale-run", "stale-engagement",
             "11111111-1111-1111-1111-111111111111"]]
    connection, engine = runner.open_engine(engine)
    try:
        _create_test_table(runner, connection, engine, "stale_lineage", rows, headers)
        runner.stamp_accept_lineage(connection, "stale_lineage",
                                    headers, "execution-current")
        assert connection.execute(
            "SELECT id, run_id, engagement_id, accept_event_id "
            "FROM %s ORDER BY id" % runner._quote_identifier("stale_lineage")
        ).fetchall() == [
            ("a", "execution-current", runner.ENGAGEMENT_ID,
             runner.ZERO_ACCEPT_EVENT_ID),
            ("b", "execution-current", runner.ENGAGEMENT_ID,
             runner.ZERO_ACCEPT_EVENT_ID),
        ]
    finally:
        connection.close()


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_stamp_accept_lineage_separates_source_and_cross_run_scope(engine):
    """Source identity survives while an imported sibling run cannot set scope."""
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    headers = ["source_run_id", "run_id", "status"]
    rows = [["source-one", "execution-sibling", "interrupted"]]
    connection, engine = runner.open_engine(engine)
    try:
        _create_test_table(runner, connection, engine, "check_run", rows, headers)
        runner.stamp_accept_lineage(connection, "check_run", headers,
                                    "execution-current")
        assert connection.execute(
            "SELECT source_run_id, run_id FROM check_run WHERE run_id = ?",
            ["execution-current"],
        ).fetchall() == [("source-one", "execution-current")]
        assert connection.execute(
            "SELECT source_run_id FROM check_run WHERE run_id = ?",
            ["execution-sibling"],
        ).fetchall() == []
    finally:
        connection.close()


def test_identifier_quoting_rejects_empty_and_nul_names():
    runner = _load_runner()

    for value in ("", "bad\x00name", None):
        try:
            runner._quote_identifier(value)
        except runner.RunnerError:
            pass
        else:  # pragma: no cover - assertion aid
            raise AssertionError(f"unsafe identifier accepted: {value!r}")


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
@pytest.mark.parametrize("source_header", ["run_id", "batch id"])
def test_ledger_mapping_preserves_source_identity_and_binds_resumable_runs(
    engine, source_header, ledger_pack
):
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    headers = [
        source_header,
        "status",
        "started_at",
        "finished_at",
        "checkpoint_ts",
        "pages_completed",
    ]
    headers = runner.apply_mapping_column_aliases(
        runner.load_mapping_columns(ledger_pack), CHECK_RUN_TABLE, headers
    )
    assert headers[0] == "source_run_id"
    connection, engine = runner.open_engine(engine)
    try:
        _create_test_table(
            runner,
            connection,
            engine,
            CHECK_RUN_TABLE,
            [
                [
                    "source-one",
                    "interrupted",
                    "2026-01-01T00:00:00",
                    "",
                    "2026-01-01T00:05:00",
                    "1",
                ],
                [
                    "source-two",
                    "running",
                    "2026-01-01T00:00:00",
                    "",
                    "2025-12-31T23:55:00",
                    "0",
                ],
            ],
            headers,
        )
        runner.stamp_accept_lineage(connection, CHECK_RUN_TABLE, headers,
                                    "execution-current")
        sql = _t7_sql(ledger_pack, engine)
        rows = connection.execute(sql, ["execution-current", 100]).fetchall()
        assert {row[0] for row in rows} == {
            _event_key("source-one", runner.ZERO_ACCEPT_EVENT_ID),
            _event_key("source-two", runner.ZERO_ACCEPT_EVENT_ID),
        }
        assert all(row[-2] == "execution-current" for row in rows)
        assert connection.execute(sql, ["execution-sibling", 100]).fetchall() == []
    finally:
        connection.close()
