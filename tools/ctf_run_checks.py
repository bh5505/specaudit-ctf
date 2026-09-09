#!/usr/bin/env python3
"""ctf_run_checks.py - loopback check runner for the specaudit-ctf telecom
pack (an ASM/VM rehearsal).

Materializes the seven evidence CSVs produced by gen_evidence.py into a
chosen engine (DuckDB when importable, SQLite fallback), creates a
``fusion_runs`` shim binding the ambient run, executes every ``checks[].file``
SQL from the pack's manifest.yaml, and writes:

    <out-dir>/report.json   - {pack_id, run_id, generated_at, engine, findings[]}
    <out-dir>/report.sarif  - SARIF 2.1.0

With --export-bin <the pack export binary>, the run's complete artifact set
(report.json + report.sarif + the auto-rendered two-sided-declared workpaper
+ export_manifest.json) is then promoted into one directory via the engine's
`pack export` subcommand (tracker #7). The export re-validates the pack's
two-sided workpaper declaration and fails loudly rather than exporting an
incomplete set. The engagement id recorded in the workpaper is derived as
``ctf-loopback:<run_id>`` — the loopback has no engagement entity of its own.
The sandbox mirror has no workpaper declaration; select the current product
pack explicitly when requesting workpaper export (see tools/README.md).

Check SQL contract (portable across DuckDB + SQLite):
  - SELECT finding_key, title, affected_count, exposure_estimate,
          record_locator, details, ?1 AS run_id, risk_score ... LIMIT ?2
  - the ambient run reaches the checks through the stamped ``run_id``
    column; the ``fusion_runs`` shim records the ambient run. The current
    product T7 filters the stamped engine scope directly
    (``cr.run_id = ?1``) while the legacy mirror T7 joins ``fusion_runs``
    for the ambient run/engagement (``fr.run_id = ?1 AND
    fr.engagement_id = cr.engagement_id``) and reads finding identity from
    the preserved source ``run_id`` — see ``stamp_accept_lineage`` for the
    two lineage contracts.
  - portable SQL only: ``||`` concatenation, ``CAST(x AS VARCHAR)``, no
    DISTINCT ON, no DuckDB-only functions.
  - in the current product pack, migration 002_ext_telecom_source_run_identity
    separates the check-run identities:
    ledger's source identity ingests as ``source_run_id`` (via the mapping
    aliases from the CSV's ``run_id`` column) while ``run_id`` is the engine
    run scope stamped at accept time — the materializer mirrors both.

Column types mirror the pack spine DDL (001_ext_telecom_silver.sql): booleans
are stored as 1/0 INTEGERs on ingest for both engines so check SQL can write
``public_access_block_enabled = false`` engine-neutrally; the numeric spine
columns (audit_year, from_port, to_port, population_size, pages_completed) are
INTEGER; ts-like columns (started_at, finished_at, checkpoint_ts, any *_ts)
are TIMESTAMP. Empty CSV cells become NULL (never '').

Usage:
    python ctf_run_checks.py --pack <pack-root> --evidence-dir <dir> \
        --out-dir <dir> [--db duckdb|sqlite] [--limit 100] [--run-id auto] \
        [--export-bin <path>] [--export-dir <dir>]
"""

import argparse
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import time
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Python 3.12 deprecated the sqlite3 default datetime adapter; register the
# explicit space-separated ISO form so TIMESTAMP cells store exactly like the
# CSV wrote them (and like DuckDB's CAST(... AS VARCHAR)).
sqlite3.register_adapter(datetime, lambda v: v.isoformat(sep=" "))

try:
    import yaml
except ImportError:  # pragma: no cover - environment-specific
    print("error: PyYAML is required (install into the CTF venv: "
          "python -m pip install pyyaml)", file=sys.stderr)
    raise SystemExit(1)

ENGINE_DB = "sqlite"  # replaced below when duckdb is importable
try:
    import duckdb  # type: ignore

    ENGINE_DB = "duckdb"
except ImportError:
    duckdb = None

ENGAGEMENT_ID = "asmvm-rehearsal-2026"
ZERO_ACCEPT_EVENT_ID = "00000000-0000-0000-0000-000000000000"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "informational": "note"}


class RunnerError(Exception):
    """Fatal runner error (missing pack/evidence, engine init, check SQL)."""


def _quote_identifier(value):
    """Quote a SQLite/DuckDB identifier without narrowing valid CSV headers."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RunnerError("invalid SQL identifier %r" % (value,))
    return '"%s"' % value.replace('"', '""')


def load_manifest(pack_root):
    manifest_path = pack_root / "manifest.yaml"
    if not manifest_path.is_file():
        raise RunnerError("manifest.yaml not found at %s" % manifest_path)
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = yaml.safe_load(fh)
    if not isinstance(manifest, dict):
        raise RunnerError("manifest.yaml does not parse to a mapping")
    checks = manifest.get("checks")
    if not isinstance(checks, list) or not checks:
        raise RunnerError("manifest.yaml has no non-empty checks list")
    for check in checks:
        if not isinstance(check, dict) or not check.get("id"):
            raise RunnerError("every manifest check needs an id")
    return manifest


def _load_raw_mapping_spec(pack_root):
    """The pack's raw mapping_spec.yaml ({} when absent)."""
    manifest_path = pack_root / "manifest.yaml"
    if not manifest_path.is_file():
        return {}
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = yaml.safe_load(fh)
    ingest = (manifest or {}).get("contributes", {}).get("ingest", {}) or {}
    spec_rel = ingest.get("mapping_spec_path")
    if not spec_rel:
        return {}
    spec_path = pack_root / str(spec_rel)
    if not spec_path.is_file():
        return {}
    with open(spec_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_mapping_spec(pack_root):
    """CSV filename -> silver table name from contributes.ingest.mapping_spec_path.

    Returns {} when the mapping spec is absent; callers then fall back to the
    CSV stem as the table name.
    """
    spec = _load_raw_mapping_spec(pack_root)
    mapping = {}
    for entry in spec.get("mappings", []) or []:
        pattern = entry.get("source_pattern", "")
        table = entry.get("silver_table", "")
        if pattern and table:
            mapping[pattern] = table
    return mapping


def load_mapping_columns(pack_root):
    """silver_table -> [{target, aliases}] from the same mapping_spec_path,
    so the materializer can mirror the product ingest's ALIAS resolution.
    Returns {} when the spec is absent."""
    spec = _load_raw_mapping_spec(pack_root)
    columns_by_table = {}
    for entry in spec.get("mappings", []) or []:
        table = entry.get("silver_table", "")
        if table and entry.get("columns"):
            columns_by_table[table] = entry["columns"]
    return columns_by_table


def load_mapping_value_maps(pack_root):
    """silver_table -> {target: {raw_key: canonical}} from mapping_spec_path.

    Mirrors the pack-declared per-column ``value_map`` substitutions the
    product applies in ``apply_column_value_maps`` (fusion-ingest applier).
    Returns {} when the spec is absent or declares no value_map.
    """
    spec = _load_raw_mapping_spec(pack_root)
    value_maps = {}
    for entry in spec.get("mappings", []) or []:
        table = entry.get("silver_table", "")
        if not table:
            continue
        per_column = {}
        for column in entry.get("columns") or []:
            target = column.get("target")
            value_map = column.get("value_map")
            if target and isinstance(value_map, dict) and value_map:
                per_column[target] = {str(k): str(v) for k, v in value_map.items()}
        if per_column:
            value_maps[table] = per_column
    return value_maps


def lookup_declared_value(value, value_map):
    """Product ``lookup_value_map`` ladder: raw, trimmed, trimmed-lowercased.

    Returns the canonical replacement on the first candidate that is a key
    in the declared map, else None (caller keeps the original value, exactly
    like the product's passthrough-on-no-match).
    """
    hit = value_map.get(value)
    if hit is not None:
        return hit
    trimmed = value.strip()
    hit = value_map.get(trimmed)
    if hit is not None:
        return hit
    return value_map.get(trimmed.lower())


def apply_mapping_value_maps(mapping_value_maps, table, headers, rows):
    """Normalize CSV cell values through the pack's DECLARED value_map.

    Runs after header alias resolution, keyed by target column name, so a
    row with status 'Interrupted' or padded mixed-case text lands canonical
    (e.g. 'interrupted') before materialization — the same substitution the
    product performs. Unmapped values pass through untouched; no other
    normalization is applied here.
    """
    per_column = mapping_value_maps.get(table)
    if not per_column:
        return rows
    indexes = [(i, per_column[header]) for i, header in enumerate(headers)
               if header in per_column]
    if not indexes:
        return rows
    normalized = []
    for row in rows:
        row = list(row)
        for i, value_map in indexes:
            if i < len(row) and isinstance(row[i], str):
                mapped = lookup_declared_value(row[i], value_map)
                if mapped is not None and mapped != row[i]:
                    row[i] = mapped
        normalized.append(row)
    return normalized


def apply_mapping_column_aliases(mapping_columns, table, headers):
    """Mirror the product ingest's alias resolution on the CSV headers.

    Since migration 002_ext_telecom_source_run_identity, the check-run
    ledger's CSV ``run_id`` column ingests as ``source_run_id`` (the source
    identity), while ``run_id`` itself is the ENGINE run scope stamped at
    accept time. Renaming the header through the pack's own mapping aliases
    before materialization is what lets the post-002 check SQL compile and
    bind here exactly as on the server. Only renames are applied here —
    per-cell value_map normalization is a separate pass
    (``apply_mapping_value_maps``); derived_key evaluation stays the
    server's business.
    """
    column_specs = mapping_columns.get(table) or []
    renamed = list(headers)
    for column in column_specs:
        target = column.get("target")
        if not target or target in renamed:
            continue
        alias_hits = [i for i, header in enumerate(renamed) if header in (column.get("aliases") or [])]
        for i in alias_hits:
            renamed[i] = target
    return renamed


def _pattern_matches(pattern, filename):
    """Match a mapping_spec source_pattern like '*s3_bucket.{csv,xlsx}' against
    a CSV filename. Expands {a,b} alternation; treats '*' as a wildcard."""
    import fnmatch
    import re

    expanded = pattern.replace("{", "(").replace("}", ")").replace(",", "|")
    return fnmatch.fnmatchcase(filename, expanded) or \
        bool(re.match("^" + re.escape(expanded).replace(r"\*", ".*").replace(r"\(", "(")
                      .replace(r"\|", "|").replace(r"\)", ")") + "$", filename))


def _table_for(mapping, filename):
    for pattern, table in mapping.items():
        if _pattern_matches(pattern, filename):
            return table
    return Path(filename).stem


# Spine column types from schema/migrations/001_ext_telecom_silver.sql. The
# numeric names are matched by header name (NOT by value: e.g. account_id is
# all-digits but must stay VARCHAR).
_NUMERIC_COLUMNS = {"audit_year", "from_port", "to_port", "population_size",
                    "pages_completed"}
_TS_COLUMNS = {"started_at", "finished_at", "checkpoint_ts"}


def _infer_columns(rows, headers):
    """[(name, type)] with type in {'VARCHAR', 'INTEGER', 'TIMESTAMP'}:

    - a column whose non-empty data values are all true/false
      (case-insensitive) is INTEGER (booleans stored as 1/0)
    - the numeric spine columns (_NUMERIC_COLUMNS) are INTEGER
    - ts-like columns (started_at, finished_at, checkpoint_ts, any *_ts) are
      TIMESTAMP
    - everything else is VARCHAR
    """
    ncols = len(headers)
    cols = []
    for c in range(ncols):
        header = headers[c]
        vals = [row[c] for row in rows if c < len(row) and row[c] != ""]
        if vals and all(str(v).strip().lower() in ("true", "false") for v in vals):
            cols.append((header, "INTEGER"))
        elif header in _NUMERIC_COLUMNS:
            cols.append((header, "INTEGER"))
        elif header in _TS_COLUMNS or header.endswith("_ts"):
            cols.append((header, "TIMESTAMP"))
        else:
            cols.append((header, "VARCHAR"))
    return cols


_INT_TYPES = {"INTEGER", "BIGINT", "SMALLINT", "TINYINT", "HUGEINT", "UBIGINT",
              "USMALLINT", "UTINYINT"}
_FLOAT_TYPES = {"DOUBLE", "REAL", "FLOAT"}
_TRUE_WORDS = {"true", "t", "yes", "y", "1"}
_FALSE_WORDS = {"false", "f", "no", "n", "0", ""}


def _type_base(coltype):
    return str(coltype or "VARCHAR").upper().split("(")[0].strip()


def _convert_value(value, coltype, mismatch=None):
    """Bind one CSV cell to the column's declared SQL type.

    An empty cell is NULL, mirroring the server accept path. Everything else is
    converted to the type the pack's migrations declare, because both engines
    otherwise fall back to text and silently change what a check means: SQLite
    compares any TEXT as greater than any number, so `severity >= 9.0` over a
    text severity column is true for every row (measured: 3,998 findings of the
    ASM/VM pack came out in the wrong risk band on SQLite for this reason), and
    DuckDB rejects the comparison outright without --fast-csv.

    A value that does not fit its declared type is loaded as text and counted in
    `mismatch` so create_table can report it - the alternative is failing a whole
    evidence load over one cell.
    """
    if value == "" or value is None:
        return None
    base = _type_base(coltype)
    if base in _INT_TYPES or base == "DECIMAL" or base == "NUMERIC":
        stripped = str(value).strip()
        low = stripped.lower()
        if low in ("true", "false"):
            return 1 if low == "true" else 0
        try:
            return int(stripped)
        except ValueError:
            pass
        if base in _INT_TYPES:
            try:
                return int(float(stripped))  # '9.0' from a float-formatted export
            except ValueError:
                pass
        else:
            try:
                return float(stripped)
            except ValueError:
                pass
    elif base in _FLOAT_TYPES:
        try:
            return float(str(value).strip())
        except ValueError:
            pass
    elif base == "BOOLEAN":
        low = str(value).strip().lower()
        if low in _TRUE_WORDS:
            return 1 if low != "" else None
        if low in _FALSE_WORDS:
            return 0
    elif base in ("TIMESTAMP", "DATE", "DATETIME"):
        try:
            return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            pass
    else:
        return value  # VARCHAR/TEXT/UUID/JSON and friends
    if mismatch is not None:
        mismatch[str(coltype)] = mismatch.get(str(coltype), 0) + 1
        mismatch.setdefault("_sample_" + str(coltype), str(value)[:40])
    return value


def open_engine(db_choice):
    if db_choice == "sqlite":
        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys = OFF")
        return conn, "sqlite"
    if db_choice == "duckdb":
        if duckdb is None:
            raise RunnerError("--db duckdb requested but duckdb is not importable; "
                              "install duckdb into the CTF venv or use --db sqlite")
        conn = duckdb.connect(":memory:")
        return conn, "duckdb"
    raise RunnerError("unknown --db value %r (expected duckdb|sqlite)" % db_choice)


# Row-by-row INSERT is the bottleneck on real evidence (a 700k-row ASM endpoint
# table took ~25 minutes at ~450 rows/s because every statement is its own
# transaction). Batched executemany, one explicit transaction for sqlite, keeps
# identical per-value typing and loads the same table in seconds.
_INSERT_CHUNK = 20000


def _insert_chunk(insert, rows, cols, mismatch=None):
    return [[_convert_value(v, ctype, mismatch) for v, (_, ctype) in zip(row, cols)]
            for row in rows]


def declared_columns(ddl_types, table, headers):
    """[(name, declared type)] when the pack's migrations declare this table.

    The migrations are the contract the checks are written against, so they -
    not value sniffing - decide how evidence is bound. Headers the migration
    does not declare fall back to VARCHAR (the header guard in --fast-csv, and
    the mapping's column aliases, keep this list honest).
    """
    types = (ddl_types or {}).get(table)
    if not types:
        return None
    return [(header, types.get(header, "VARCHAR")) for header in headers]


def create_table(conn, engine, table, rows, headers, ddl_types=None):
    cols = declared_columns(ddl_types, table, headers) or _infer_columns(rows, headers)
    mismatch = {}
    for name, ctype in cols:
        if _type_base(ctype) not in _INT_TYPES | _FLOAT_TYPES | {"BOOLEAN", "TIMESTAMP",
                                                                "DECIMAL", "NUMERIC"}:
            continue
        # Only report a mismatch rate for columns that declare a non-text type;
        # a text column accepting anything is not a defect.
        mismatch.setdefault("_declared_" + name, _type_base(ctype))
    coldefs = ", ".join("%s %s" % (_quote_identifier(name), ctype) for name, ctype in cols)
    quoted_table = _quote_identifier(table)
    conn.execute(
        "CREATE TABLE %s (%s)" % (quoted_table, coldefs)
    )
    placeholders = ", ".join(["?"] * len(cols))
    insert = "INSERT INTO %s VALUES (%s)" % (quoted_table, placeholders)
    if not rows:
        return
    if engine == "sqlite":
        # Per-statement autocommit costs one journal sync per row; one
        # transaction per table turns N syncs into one. `with conn` (not an
        # explicit BEGIN) because the sqlite3 module opens its own implicit
        # transaction before an INSERT, and "BEGIN" inside it is an error.
        with conn:
            for start in range(0, len(rows), _INSERT_CHUNK):
                conn.executemany(insert, _insert_chunk(insert, rows[start:start + _INSERT_CHUNK], cols, mismatch))
                _progress(table, start + _INSERT_CHUNK, len(rows))
    else:
        for start in range(0, len(rows), _INSERT_CHUNK):
            conn.executemany(insert, _insert_chunk(insert, rows[start:start + _INSERT_CHUNK], cols, mismatch))
            _progress(table, start + _INSERT_CHUNK, len(rows))
    report_type_mismatches(table, mismatch)


def report_type_mismatches(table, mismatch):
    """Print the cells that did not fit their declared type, if any."""
    counts = {k: v for k, v in mismatch.items()
              if not k.startswith("_sample_") and not k.startswith("_declared_")}
    for coltype, count in sorted(counts.items()):
        sample = mismatch.get("_sample_" + coltype, "")
        print("  WARNING %s: %d value(s) do not fit declared type %s "
              "(first: %r); loaded as text" % (table, count, coltype, sample),
              file=sys.stderr, flush=True)


_RUN_T0 = time.monotonic()


def _progress(table, done, total):
    """Load progress to stderr so a long load is visibly progressing."""
    if total > _INSERT_CHUNK:
        print("  loading %s: %d/%d rows (%.1fs)"
              % (table, min(done, total), total, time.monotonic() - _RUN_T0),
              file=sys.stderr, flush=True)


def create_fusion_runs_shim(conn, run_id):
    conn.execute("CREATE TABLE fusion_runs ("
                 "run_id VARCHAR, engagement_id VARCHAR, audit_year INTEGER, "
                 "prior_year_engagement_id VARCHAR)")
    conn.execute(
        "INSERT INTO fusion_runs (run_id, engagement_id, audit_year, "
        "prior_year_engagement_id) VALUES (?, ?, ?, ?)",
        (run_id, ENGAGEMENT_ID, 2026, None),
    )


def mapping_declares_run_id_source(mapping_columns, table):
    """Whether the mapping treats run_id itself as a source column.

    The legacy mirror declares target run_id; the current product declares
    source_run_id instead. Only a mapping declaration permits preservation:
    an imported stale run_id header alone never opts out of engine stamping.
    """
    for column in mapping_columns.get(table) or []:
        if isinstance(column, dict) and column.get("target") == "run_id":
            return True
    return False


def stamp_accept_lineage(conn, table, headers, run_id, *, preserve_run_id=False):
    """Stamp ambient lineage, with an explicit legacy source-ID exception.

    By default, overwrite run_id/engagement_id/accept_event_id even when
    imported values exist; source_run_id remains untouched. The current
    product's checks bind this stamped engine run_id.

    run() derives preserve_run_id from a declared target: run_id mapping.
    The legacy mirror uses that column as source identity and joins
    fusion_runs for ambient scope, so preserve it while stamping the other
    two fields. A missing mapped source ID fails before changing the table.
    """
    existing = set(headers)
    if preserve_run_id and "run_id" not in existing:
        raise RunnerError("%s is missing its mapped source run_id column" % table)
    quoted_table = _quote_identifier(table)
    for col in ("run_id", "engagement_id", "accept_event_id"):
        if col not in existing:
            conn.execute(
                "ALTER TABLE %s ADD COLUMN %s VARCHAR"
                % (quoted_table, _quote_identifier(col))
            )
    if preserve_run_id:
        conn.execute(
            "UPDATE %s SET \"engagement_id\" = ?, "
            "\"accept_event_id\" = ?" % quoted_table,
            (ENGAGEMENT_ID, ZERO_ACCEPT_EVENT_ID),
        )
    else:
        conn.execute(
            "UPDATE %s SET \"run_id\" = ?, \"engagement_id\" = ?, "
            "\"accept_event_id\" = ?" % quoted_table,
            (run_id, ENGAGEMENT_ID, ZERO_ACCEPT_EVENT_ID),
        )


_FROM_JOIN_RE = re.compile(
    r"\b(?:FROM|JOIN)\s+([A-Za-z_][\w.]*)"
    r"(?:\s+(?!ON\b|WHERE\b|GROUP\b|ORDER\b|LIMIT\b|LEFT\b|RIGHT\b|FULL\b|INNER\b|"
    r"CROSS\b|JOIN\b|USING\b|VALUES\b|UNION\b|SET\b)([A-Za-z_]\w*))?",
    re.I)
_JOIN_EQ_RE = re.compile(
    r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)")


def sqlite_join_indexes(conn, engine, check_sqls, loaded_tables):
    """Index the columns the pack's own checks join on (SQLite only).

    Evidence arrives as CSV, so on SQLite it arrives with no indexes at all, and
    a correlated EXISTS across two 400k-row tables is a nested-loop scan: the
    ASM/VM pack's candidate-backlog check needed over 240 s (and did not finish
    inside any sane budget) and took 13.4 s once the join keys were indexed, for
    3 s of index build. DuckDB builds hash joins itself and needs nothing.

    The index set is derived from the checks rather than hardcoded, so it follows
    the pack when its joins change. Aliases that resolve to more than one table
    in the same file are skipped rather than guessed.
    """
    if engine != "sqlite":
        return []
    wanted = {}
    known = set(loaded_tables)
    for sql in check_sqls:
        aliases = {}
        for table, alias in _FROM_JOIN_RE.findall(sql):
            name = table.split(".")[-1]
            if name not in known:
                continue
            aliases[alias or name] = name
            aliases.setdefault(name, name)
        for left, lcol, right, rcol in _JOIN_EQ_RE.findall(sql):
            lt, rt = aliases.get(left), aliases.get(right)
            if lt and lt == rt and lcol == rcol:
                continue
            if lt and lcol != "run_id":
                wanted.setdefault(lt, [])
                if lcol not in wanted[lt]:
                    wanted[lt].append(lcol)
            if rt and rcol != "run_id":
                wanted.setdefault(rt, [])
                if rcol not in wanted[rt]:
                    wanted[rt].append(rcol)
    created = []
    for table in sorted(wanted):
        cols = [r[1] for r in conn.execute(
            "PRAGMA table_info(%s)" % _quote_identifier(table)).fetchall()]
        use = ["run_id"] if "run_id" in cols else []
        use += [c for c in wanted[table] if c in cols and c != "run_id"]
        if len(use) < 2:
            continue
        name = ("ix_%s_%s" % (table, "_".join(use)))[:60]
        stmt = ("CREATE INDEX IF NOT EXISTS %s ON %s (%s)"
                % (_quote_identifier(name), _quote_identifier(table),
                   ", ".join(_quote_identifier(c) for c in use)))
        try:
            conn.execute(stmt)
        except Exception as exc:  # a bad index must not break the run
            print("  sqlite index skipped (%s): %s" % (name, exc), file=sys.stderr)
            continue
        created.append(name)
    if created:
        conn.commit()
        print("sqlite join indexes (%d): %s" % (len(created), ", ".join(created)),
              flush=True)
    return created


def execute_check(conn, engine, sql, run_id, limit):
    """Execute one check with ?1 = run_id, ?2 = limit.

    DuckDB < 0.10 rejects bound parameters in LIMIT; fall back to textual
    substitution when parameter binding fails with an engine error.
    Limit is validated as a non-negative integer before any substitution.
    """
    try:
        return conn.execute(sql, (run_id, limit)).fetchall()
    except Exception as first_exc:
        if engine != "duckdb":
            raise RunnerError("check SQL failed (%s)" % first_exc)
        # Validate limit is a safe integer before textual substitution
        if not isinstance(limit, int) or limit < 0:
            raise RunnerError("invalid limit for textual substitution: %r" % limit)
        quoted = "'" + run_id.replace("'", "''") + "'"
        substituted = sql.replace("?1", quoted).replace("?2", str(limit))
        try:
            return conn.execute(substituted).fetchall()
        except Exception as exc:
            raise RunnerError("check SQL failed (param binding: %s; "
                              "substitution: %s)" % (first_exc, exc))


def _as_scalar(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    return str(value)


def verify_export_artifacts(export_dir, reports_dir, report, engagement_id):
    """Verify identities and artifact bytes before discarding input reports."""
    export_dir = Path(export_dir)
    try:
        manifest_path = export_dir / "export_manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise RunnerError("export manifest is missing or is not a regular file")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise RunnerError("export manifest must be an object")
        for key, expected in (("pack_id", report["pack_id"]),
                              ("run_id", report["run_id"]),
                              ("engagement_id", engagement_id)):
            if manifest.get(key) != expected:
                raise RunnerError("export manifest %s does not match this run" % key)
        for key, expected in (("workpaper", "rendered"), ("sarif", "exported")):
            record = manifest.get(key)
            if not isinstance(record, dict) or record.get("status") != expected:
                raise RunnerError("export manifest does not confirm %s %s" % (key, expected))
        required = {"report.json", "report.sarif", "workpaper.md"}
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list):
            raise RunnerError("export manifest has no artifact list")
        seen = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise RunnerError("invalid export artifact record")
            name = artifact.get("path")
            if not isinstance(name, str) or name not in required or name in seen:
                raise RunnerError("export artifact paths must name each canonical artifact once")
            seen.add(name)
            path = export_dir / name
            if path.is_symlink() or not path.is_file():
                raise RunnerError("export artifact is not a regular file: %s" % name)
            data = path.read_bytes()
            if (artifact.get("bytes") != len(data)
                    or artifact.get("sha256") != hashlib.sha256(data).hexdigest()):
                raise RunnerError("export artifact digest/size mismatch: %s" % name)
            if name in ("report.json", "report.sarif"):
                if data != (Path(reports_dir) / name).read_bytes():
                    raise RunnerError("exported %s differs from this run's input" % name)
        if seen != required:
            raise RunnerError("export manifest omits required artifacts")
    except (OSError, ValueError) as exc:
        raise RunnerError("cannot verify export artifacts: %s" % exc) from exc


def report_export_recovery_paths(export_dir):
    """Name surviving native trees after failure, without modifying them."""
    try:
        destination = Path(export_dir).resolve()
        if not destination.exists():
            print("warning: export destination is absent: %s" % destination,
                  file=sys.stderr)
        prefixes = tuple(".%s.%s-" % (destination.name, kind)
                         for kind in ("export-backup", "export-staging"))
        for path in sorted(destination.parent.iterdir()):
            if path.name.startswith(prefixes):
                print("warning: retained native export path (inspect before recovery): %s"
                      % path, file=sys.stderr)
    except OSError as exc:
        print("warning: could not inspect export recovery paths: %s" % exc,
              file=sys.stderr)


def _read_csv_header(csv_path):
    with open(csv_path, "r", encoding="utf-8", newline="") as fh:
        return next(csv.reader(fh), None) or []


def _parse_migration_tables(pack_root):
    """{table: [(column, declared type)]} from schema/migrations/*.sql, in order."""
    tables = {}
    for sql_path in sorted((pack_root / "schema" / "migrations").glob("*.sql")):
        text = re.sub(r"--[^\n]*", "", sql_path.read_text(encoding="utf-8"))
        for match in re.finditer(
                r"CREATE TABLE(?: IF NOT EXISTS)?\s+([\w.]+)\s*\((.*?)\n\)",
                text, re.S):
            name = match.group(1).split(".")[-1]
            cols, depth, cur = [], 0, ""
            for char in match.group(2).replace("\n", " "):
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                if char == "," and depth == 0:
                    cols.append(cur.strip())
                    cur = ""
                else:
                    cur += char
            cols.append(cur.strip())
            parsed = []
            for part in cols:
                if not part or re.match(r"^(PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT)\b",
                                        part, re.I):
                    continue
                tokens = part.split(None, 2)
                col = tokens[0].strip('"`[]')
                coltype = tokens[1].upper() if len(tokens) > 1 else "VARCHAR"
                parsed.append((col, coltype))
            tables.setdefault(name, []).extend(parsed)
    return tables


def load_ddl_column_types(pack_root):
    """{table: {column: declared type}} - how evidence cells must be bound.

    Without this the loader decides types from the values it sees, which gives
    every text-shaped number a text column, and a text column changes what a
    check means (see _convert_value). The migrations already decide; read them.
    """
    return {table: dict(cols) for table, cols in _parse_migration_tables(pack_root).items()}


def load_ddl_columns(pack_root):
    """{table: {column}} from the pack's schema/migrations/*.sql.

    The migrations are the authoritative table shape, so they are what a
    header-perfect evidence directory must match (the mapping spec may declare
    only the columns that need renaming or value translation).
    """
    return {table: {name for name, _ in cols}
            for table, cols in _parse_migration_tables(pack_root).items()}


def _require_declared_headers(ddl_columns, table, headers, csv_path):
    """--fast-csv skips alias/value-map translation, so refuse unless every CSV
    header is a real column of the pack table (and say which table it was)."""
    declared = ddl_columns.get(table)
    if not declared:
        raise RunnerError(
            "--fast-csv: table %r is not created by the pack migrations (%s); "
            "load without --fast-csv" % (table, csv_path))
    undeclared = [h for h in headers if h not in declared]
    if undeclared:
        raise RunnerError(
            "--fast-csv: %s has headers that are not columns of %r: %s; "
            "load without --fast-csv so mapping aliases and value maps apply"
            % (csv_path, table, ", ".join(sorted(undeclared))))


def _read_csv_type_arg(ddl_types, table, headers):
    """read_csv() `types=` argument from the declared schema, as SQL text.

    Declaring the types is what keeps the two engines on the same schema:
    read_csv's own inference types an all-digits `ip` column BIGINT (a real Ivanti
    export whose ip column holds asset ids did exactly that, and the pack then
    failed to join it to the VARCHAR asm_vm_surface.ip), and it cannot infer a
    type at all from an all-empty column. Columns the CSV does not carry are left
    out; an unrecognised declared type is left to inference rather than guessed.
    """
    types = (ddl_types or {}).get(table)
    if not types:
        return ""
    known = ("VARCHAR", "TEXT", "BOOLEAN", "TIMESTAMP", "DATE", "BLOB", "UUID", "JSON")
    numeric = _INT_TYPES | _FLOAT_TYPES
    pairs = []
    for header in headers:
        coltype = str(types.get(header, "")).upper()
        base = coltype.split("(")[0]
        if base in numeric:
            sqltype = "BIGINT" if base in _INT_TYPES else (
                "DECIMAL" + coltype[len(base):] if coltype.startswith(base + "(")
                else "DOUBLE")
        elif base in known:
            sqltype = "TEXT" if coltype == "TEXT" else base
        else:
            continue
        pairs.append("'%s': '%s'" % (header.replace("'", "''"), sqltype))
    if not pairs:
        return ""
    return ", types={%s}" % ", ".join(pairs)


def load_evidence_native_csv(conn, evidence_dir, mapping, ddl_columns, ddl_types=None):
    """DuckDB-native CSV load (vectorised, no Python row loop).

    Only for evidence whose headers already name real pack columns - mapping
    aliases and value maps are NOT applied here, which is verified per table by
    _require_declared_headers. Column types come from the pack's migrations when
    they declare the table (so DuckDB and SQLite see the same schema), and from
    read_csv's own inference only for columns the migrations leave open.
    """
    loaded = []
    for csv_path in sorted(evidence_dir.glob("*.csv")):
        table = _table_for(mapping, csv_path.name)
        headers = _read_csv_header(csv_path)
        _require_declared_headers(ddl_columns, table, headers, csv_path.name)
        conn.execute(
            "CREATE TABLE %s AS SELECT * FROM read_csv('%s', header=true%s)"
            % (_quote_identifier(table), csv_path.as_posix().replace("'", "''"),
               _read_csv_type_arg(ddl_types, table, headers)))
        loaded.append(table)
        n = conn.execute("SELECT count(*) FROM %s" % _quote_identifier(table)).fetchone()[0]
        print("loaded %s -> table %s (%d rows, duckdb native read_csv)"
              % (csv_path.name, table, n), flush=True)
    return loaded


def run(pack_root, evidence_dir, out_dir, db_choice, limit, run_id,
        export_bin=None, export_dir=None, fast_csv=False):
    pack_root = Path(pack_root)
    evidence_dir = Path(evidence_dir)
    out_dir = Path(out_dir)
    if not pack_root.is_dir():
        raise RunnerError("pack root not found: %s" % pack_root)
    if not evidence_dir.is_dir():
        raise RunnerError("evidence dir not found: %s" % evidence_dir)

    manifest = load_manifest(pack_root)
    pack_id = str(manifest.get("pack_id") or "unknown")
    mapping = load_mapping_spec(pack_root)
    mapping_columns = load_mapping_columns(pack_root)
    mapping_value_maps = load_mapping_value_maps(pack_root)

    conn, engine = open_engine(db_choice)
    if fast_csv and engine != "duckdb":
        raise RunnerError("--fast-csv requires --db duckdb")

    if run_id == "auto":
        run_id = "ctf-%s-%s" % (datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
                                uuid.uuid4().hex[:6])
    create_fusion_runs_shim(conn, run_id)

    csv_files = sorted(evidence_dir.glob("*.csv"))
    if not csv_files:
        raise RunnerError("no *.csv files in evidence dir %s" % evidence_dir)
    loaded_tables = []
    # Declared column types drive both load paths: the row-by-row path binds
    # cells to them, and --fast-csv hands them to read_csv. Value-sniffed types
    # made the two engines disagree about what a check means.
    ddl_types = load_ddl_column_types(pack_root)
    if fast_csv:
        loaded_tables = load_evidence_native_csv(conn, evidence_dir, mapping,
                                                load_ddl_columns(pack_root), ddl_types)
        for table in loaded_tables:
            headers = [r[0] for r in conn.execute(
                "DESCRIBE %s" % _quote_identifier(table)).fetchall()]
            stamp_accept_lineage(
                conn, table, headers, run_id,
                preserve_run_id=mapping_declares_run_id_source(
                    mapping_columns, table),
            )

    for csv_path in ([] if fast_csv else csv_files):
        with open(csv_path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            headers = next(reader, None)
            if not headers:
                raise RunnerError("empty CSV (no header): %s" % csv_path)
            rows = [r for r in reader]
            _progress(csv_path.name, 0, len(rows))
        table = _table_for(mapping, csv_path.name)
        headers = apply_mapping_column_aliases(mapping_columns, table, headers)
        rows = apply_mapping_value_maps(mapping_value_maps, table, headers, rows)
        create_table(conn, engine, table, rows, headers, ddl_types=ddl_types)
        stamp_accept_lineage(
            conn, table, headers, run_id,
            preserve_run_id=mapping_declares_run_id_source(
                mapping_columns, table),
        )
        loaded_tables.append(table)
        print("loaded %s -> table %s (%d rows)" % (csv_path.name, table, len(rows)))

    check_sqls = []
    for check in manifest["checks"]:
        sql_path = pack_root / str(check.get("file") or "")
        if not sql_path.is_file():
            raise RunnerError("check file missing: %s" % sql_path)
        with open(sql_path, "r", encoding="utf-8") as fh:
            check_sqls.append(fh.read())
    sqlite_join_indexes(conn, engine, check_sqls, loaded_tables)

    findings = []
    for check, sql in zip(manifest["checks"], check_sqls):
        check_id = str(check["id"])
        rows = execute_check(conn, engine, sql, run_id, limit)
        severity = str(check.get("severity") or "medium").lower()
        technique = check.get("technique")
        for row in rows:
            if len(row) < 8:
                raise RunnerError(
                    "check %s returned %d columns; the row contract requires 8 "
                    "(finding_key, title, affected_count, exposure_estimate, "
                    "record_locator, details, run_id, risk_score)" % (check_id, len(row)))
            finding_key = str(row[0])
            findings.append({
                "finding_alias": "%s:%s:%s" % (pack_id, check_id, finding_key),
                "check_id": check_id,
                "technique": technique,
                "severity": severity,
                "risk_score": _as_scalar(row[7]),
                "title": str(row[1]),
                "details": str(row[5]) if row[5] is not None else "",
                "record_locator": str(row[4]) if row[4] is not None else "",
                "affected_count": _as_scalar(row[2]),
                "exposure_estimate": _as_scalar(row[3]),
            })
        if rows:
            print("check %s: %d finding(s)" % (check_id, len(rows)))

    export_dir = Path(export_dir) if export_dir else out_dir
    in_place_export = bool(export_bin) and export_dir.resolve() == out_dir.resolve()
    reports_dir = out_dir
    if in_place_export:
        # Only the native exporter may publish into its destination. Preparing
        # inputs beside it preserves the previous complete export if rendering
        # or promotion fails, and prevents concurrent runs mixing source bytes.
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        reports_dir = Path(tempfile.mkdtemp(
            prefix=".%s.run-reports-" % out_dir.name, dir=out_dir.parent))
    elif any((out_dir / name).exists() or (out_dir / name).is_symlink()
             for name in ("export_manifest.json", "workpaper.md")):
        raise RunnerError(
            "refusing to overwrite reports in a completed export: %s; "
            "choose another --out-dir or use --export-bin with in-place export"
            % out_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    report = {
        "pack_id": pack_id,
        "run_id": run_id,
        "generated_at": generated_at,
        "engine": engine,
        "findings": findings,
    }
    # Provenance: stamp the evidence seed when the generator recorded it.
    seed_file = Path(evidence_dir) / "seed.json"
    if seed_file.is_file():
        try:
            stamped = json.loads(seed_file.read_text(encoding="utf-8")).get("seed")
            if stamped is not None:
                report["seed"] = stamped
        except (OSError, ValueError):
            pass
    with open(reports_dir / "report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    write_sarif(reports_dir / "report.sarif", findings)

    by_technique = {}
    for f in findings:
        tech = f.get("technique") or "unmapped"
        by_technique[tech] = by_technique.get(tech, 0) + 1
    print("run %s (%s engine): %d finding(s) total" % (run_id, engine, len(findings)))
    for tech in sorted(by_technique):
        print("  %s: %d finding(s)" % (tech, by_technique[tech]))
    print("wrote %s" % (reports_dir / "report.json"))
    print("wrote %s" % (reports_dir / "report.sarif"))
    if export_bin:
        engagement_id = "ctf-loopback:%s" % run_id
        cmd = [
            str(export_bin), "pack", "export",
            "--external", str(pack_root.resolve()),
            "--report", str((reports_dir / "report.json").resolve()),
            "--sarif", str((reports_dir / "report.sarif").resolve()),
            "--out", str(export_dir.resolve()),
            "--engagement-id", engagement_id,
            "--require-workpaper",
        ]
        print("workpaper export: %s" % " ".join(cmd))
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            print("error: workpaper export timed out after 600s; the run reports "
                  "remain in %s" % reports_dir, file=sys.stderr)
            report_export_recovery_paths(export_dir)
            return 1
        except OSError as exc:
            print("error: cannot start workpaper export (%s); the run reports "
                  "remain in %s" % (exc, reports_dir), file=sys.stderr)
            return 1
        if completed.stdout:
            sys.stdout.write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        if completed.returncode != 0:
            print("error: workpaper export failed (exit %d); the run reports "
                  "remain in %s" % (completed.returncode, reports_dir), file=sys.stderr)
            report_export_recovery_paths(export_dir)
            return 1
        try:
            verify_export_artifacts(export_dir, reports_dir, report, engagement_id)
        except RunnerError as exc:
            print("error: workpaper export returned success but verification failed (%s); "
                  "the run reports remain in %s" % (exc, reports_dir), file=sys.stderr)
            report_export_recovery_paths(export_dir)
            return 1
        if in_place_export:
            try:
                shutil.rmtree(reports_dir)
            except OSError as exc:
                print("warning: export is complete, but input report cleanup failed "
                      "at %s (%s); remove any remaining files manually" %
                      (reports_dir, exc), file=sys.stderr)
        print("wrote %s (unified run export)" % (export_dir / "export_manifest.json"))
    else:
        print("workpaper export not run (--export-bin not given; reports only)")
    return 0


def write_sarif(path, findings):
    rules = {}
    for f in findings:
        check_id = f["check_id"]
        if check_id not in rules:
            rules[check_id] = {
                "id": check_id,
                "name": check_id,
                "shortDescription": {"text": check_id},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(f["severity"], "warning")},
            }
    results = []
    for f in findings:
        result = {
            "ruleId": f["check_id"],
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["title"]},
            "partialFingerprints": {"finding_alias": f["finding_alias"]},
            "properties": {
                "technique": f.get("technique"),
                "severity": f.get("severity"),
                "risk_score": f.get("risk_score"),
                "exposure_estimate": f.get("exposure_estimate"),
            },
        }
        if f.get("record_locator"):
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["record_locator"]},
                },
            }]
        results.append(result)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0-json-schema.json",
        "runs": [{
            "tool": {"driver": {"name": "specaudit-ctf", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run all manifest checks over generated evidence and emit "
                    "report.json + report.sarif (CTF loopback; not a production gate)."
    )
    parser.add_argument("--pack", required=True, help="Pack root (workbench.toml/manifest.yaml).")
    parser.add_argument("--evidence-dir", required=True,
                        help="Directory with gen_evidence.py CSVs.")
    parser.add_argument("--out-dir", required=True, help="Where report.json/report.sarif go.")
    parser.add_argument("--db", choices=["duckdb", "sqlite"], default=None,
                        help="Engine: duckdb when importable, else sqlite (default).")
    parser.add_argument("--limit", type=int, default=100, help="LIMIT ?2 binding (default 100).")
    parser.add_argument("--run-id", default="auto",
                        help="Run id bound as ?1 (default: auto-generated).")
    parser.add_argument("--fast-csv", action="store_true",
                        help="Load CSVs with DuckDB's native read_csv instead of the "
                             "Python row loop (requires --db duckdb). Only valid when "
                             "the CSV headers are already the pack's mapping targets; "
                             "mapping aliases and value maps are NOT applied, and the "
                             "runner verifies that per table.")
    parser.add_argument("--export-bin", default=None,
                        help="Path to a built pack export binary; when given, the "
                             "run's artifact set (report.json + report.sarif + auto-rendered "
                             "workpaper + export manifest) is exported via `pack export` "
                             "after the checks.")
    parser.add_argument("--export-dir", default=None,
                        help="Export destination (default: --out-dir). Only used with "
                             "--export-bin.")
    args = parser.parse_args(argv)

    db_choice = args.db or ENGINE_DB
    if args.db == "duckdb" and duckdb is None:
        print("error: --db duckdb requested but duckdb is not importable "
              "(install duckdb into the CTF venv or use --db sqlite)", file=sys.stderr)
        return 1
    if args.export_dir and not args.export_bin:
        print("error: --export-dir needs --export-bin", file=sys.stderr)
        return 1
    if args.export_bin and not Path(args.export_bin).is_file():
        print("error: --export-bin is not a file: %s" % args.export_bin, file=sys.stderr)
        return 1
    try:
        return run(args.pack, args.evidence_dir, args.out_dir, db_choice,
                   args.limit, args.run_id,
                   export_bin=args.export_bin, export_dir=args.export_dir,
                   fast_csv=args.fast_csv)
    except RunnerError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
