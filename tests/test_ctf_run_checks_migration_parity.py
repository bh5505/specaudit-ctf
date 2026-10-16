"""Migration-created schema constraints must survive CTF evidence loading."""

import importlib.util
from pathlib import Path

import pytest


def _load_runner():
    path = Path(__file__).parents[1] / "tools" / "ctf_run_checks.py"
    spec = importlib.util.spec_from_file_location("ctf_run_checks_parity", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pack_with_constraints(tmp_path):
    migrations = tmp_path / "schema" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "001_schema.sql").write_text(
        """-- constraints are part of the rehearsal schema
        CREATE TABLE constrained_evidence (
            left_id VARCHAR,
            right_id VARCHAR,
            score INTEGER CHECK (score >= 0),
            PRIMARY KEY (left_id, right_id)
        );
        """,
        encoding="utf-8",
    )
    return tmp_path


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_composite_primary_key_rejects_duplicate_during_evidence_load(tmp_path, engine):
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    connection, actual_engine = runner.open_engine(engine)
    try:
        pack = _pack_with_constraints(tmp_path)
        runner._create_schema_from_migrations(connection, actual_engine, pack)
        ddl_types = runner.load_ddl_column_types(pack)
        with pytest.raises(
            runner.RunnerError,
            match=r"constrained_evidence.*constraint|constraint.*constrained_evidence",
        ):
            runner.insert_evidence_rows(
                connection,
                actual_engine,
                "constrained_evidence",
                [["same", "key", "1"], ["same", "key", "2"]],
                ["left_id", "right_id", "score"],
                ddl_types,
            )
    finally:
        connection.close()


@pytest.mark.parametrize("engine", ["sqlite", "duckdb"])
def test_check_clause_rejects_invalid_evidence_loudly(tmp_path, engine):
    runner = _load_runner()
    if engine == "duckdb":
        pytest.importorskip("duckdb")
    connection, actual_engine = runner.open_engine(engine)
    try:
        pack = _pack_with_constraints(tmp_path)
        runner._create_schema_from_migrations(connection, actual_engine, pack)
        with pytest.raises(
            runner.RunnerError,
            match=r"constrained_evidence.*constraint|constraint.*constrained_evidence",
        ):
            runner.insert_evidence_rows(
                connection,
                actual_engine,
                "constrained_evidence",
                [["left", "right", "-1"]],
                ["left_id", "right_id", "score"],
                runner.load_ddl_column_types(pack),
            )
    finally:
        connection.close()


def test_migration_failure_names_file_statement_and_original_error(tmp_path):
    runner = _load_runner()
    migrations = tmp_path / "schema" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "007_bad.sql").write_text(
        "CREATE TABLE okay (id INTEGER); BROKEN SQL HERE;", encoding="utf-8"
    )
    connection, engine = runner.open_engine("sqlite")
    try:
        with pytest.raises(runner.RunnerError) as caught:
            runner._create_schema_from_migrations(connection, engine, tmp_path)
        message = str(caught.value)
        assert "007_bad.sql" in message
        assert "statement 2" in message
        assert "syntax" in message.lower()
    finally:
        connection.close()
