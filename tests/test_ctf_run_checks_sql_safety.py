"""Security regressions for the local CTF SQL materializer."""

import importlib.util
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


PRODUCT_PACK = Path(__file__).parents[1] / "packs/ext_telecom_cyber"
CHECK_RUN_TABLE = "gw_silver_ext_telecom_check_run"


def _product_t7_sql(engine):
    sql = (PRODUCT_PACK / "checks/ext_telecom_t7_resumable_runs.sql").read_text()
    if engine == "duckdb":
        # DuckDB uses positional '?' whereas SQLite accepts numbered '?N'.
        sql = sql.replace("?1", "?").replace("?2", "?")
    return sql


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_declared_value_map_normalizes_mixed_case_status_for_real_t7(engine):
    """Noncanonical status text must normalize via the DECLARED value_map.

    Reads the pack's real mapping_spec through the existing loader (no
    private dictionary), applies it, and observes the result: 'Interrupted'
    and padded '  INTERRUPTED  ' land canonical and fire the real product
    T7; an unmapped status passes through verbatim and fires nothing.
    """
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    status_map = runner.load_mapping_value_maps(PRODUCT_PACK)[CHECK_RUN_TABLE]["status"]
    assert status_map["interrupted"] == "interrupted"  # declared, not invented
    # CSV already carries the target plus an alias: rename must not duplicate.
    headers_in = ["source_run_id", "run_id", "status", "started_at",
                  "finished_at", "checkpoint_ts", "pages_completed"]
    renamed = runner.apply_mapping_column_aliases(
        runner.load_mapping_columns(PRODUCT_PACK), CHECK_RUN_TABLE, headers_in
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
        runner.load_mapping_value_maps(PRODUCT_PACK),
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
        sql = _product_t7_sql(engine)
        findings = connection.execute(sql, ["execution-current", 100]).fetchall()
        assert {row[0] for row in findings} == {
            "run:src-mixed:%s" % runner.ZERO_ACCEPT_EVENT_ID,
            "run:src-padded:%s" % runner.ZERO_ACCEPT_EVENT_ID,
            "run:src-canon:%s" % runner.ZERO_ACCEPT_EVENT_ID,
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
def test_stamp_accept_lineage_preserves_declared_run_id_source(engine):
    """Legacy mirror contract: mapped source run_id survives, the rest stamps."""
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    headers = ["run_id", "status", "engagement_id", "accept_event_id"]
    rows = [["cr-2026-001", "interrupted", "stale-engagement",
             "11111111-1111-1111-1111-111111111111"],
            ["cr-2026-002", "completed", "stale-engagement",
             "11111111-1111-1111-1111-111111111111"]]
    connection, engine = runner.open_engine(engine)
    try:
        _create_test_table(runner, connection, engine, "legacy_check_run", rows, headers)
        runner.stamp_accept_lineage(connection, "legacy_check_run",
                                    headers, "execution-current",
                                    preserve_run_id=True)
        assert connection.execute(
            "SELECT run_id, engagement_id, accept_event_id "
            "FROM %s ORDER BY run_id" % runner._quote_identifier("legacy_check_run")
        ).fetchall() == [
            ("cr-2026-001", runner.ENGAGEMENT_ID, runner.ZERO_ACCEPT_EVENT_ID),
            ("cr-2026-002", runner.ENGAGEMENT_ID, runner.ZERO_ACCEPT_EVENT_ID),
        ]
    finally:
        connection.close()


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_stamp_accept_lineage_rejects_missing_mapped_source_run_id(engine):
    """A missing source identity must not be fabricated from the ambient run."""
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    headers = ["status"]
    rows = [["interrupted"]]
    connection, engine = runner.open_engine(engine)
    try:
        _create_test_table(runner, connection, engine, "ledger_no_run", rows, headers)
        with pytest.raises(runner.RunnerError, match="missing its mapped source run_id"):
            runner.stamp_accept_lineage(connection, "ledger_no_run",
                                        headers, "execution-current",
                                        preserve_run_id=True)
        assert connection.execute("SELECT * FROM ledger_no_run").fetchall() == [
            ("interrupted",),
        ]
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
def test_product_ledger_mapping_preserves_source_identity_and_binds_t7(
    engine, source_header
):
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    pack = Path(__file__).parents[1] / "packs/ext_telecom_cyber"
    table = "gw_silver_ext_telecom_check_run"
    headers = [
        source_header,
        "status",
        "started_at",
        "finished_at",
        "checkpoint_ts",
        "pages_completed",
    ]
    headers = runner.apply_mapping_column_aliases(
        runner.load_mapping_columns(pack), table, headers
    )
    assert headers[0] == "source_run_id"
    connection, engine = runner.open_engine(engine)
    try:
        _create_test_table(
            runner,
            connection,
            engine,
            table,
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
        runner.stamp_accept_lineage(connection, table, headers, "execution-current")
        sql = (pack / "checks/ext_telecom_t7_resumable_runs.sql").read_text()
        # DuckDB uses positional '?' whereas SQLite accepts numbered '?N'.
        if engine == "duckdb":
            sql = sql.replace("?1", "?").replace("?2", "?")
        rows = connection.execute(sql, ["execution-current", 100]).fetchall()
        assert {row[0] for row in rows} == {
            f"run:source-one:{runner.ZERO_ACCEPT_EVENT_ID}",
            f"run:source-two:{runner.ZERO_ACCEPT_EVENT_ID}",
        }
        assert all(row[-2] == "execution-current" for row in rows)
        assert connection.execute(sql, ["execution-sibling", 100]).fetchall() == []
    finally:
        connection.close()
