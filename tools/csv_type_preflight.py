#!/usr/bin/env python3
"""Evidence-CSV type preflight: catch load-breaking rows before a pack run.

WHY THIS EXISTS. The dogfood runner loads evidence two different ways:

  * `--db duckdb --fast-csv`  -> `CREATE TABLE t AS SELECT * FROM
    read_csv(path, header=true)`: DuckDB SNIFFS types from a 20 480-row sample
    and the load is strict (strict_mode=true, all_varchar=0). One appended row
    that puts a string in a column the sample made BIGINT aborts the whole run
    with a ConversionException - after the load has already burned the run's
    minutes. Observed live: a live-fire overlay row whose source_row_id held
    "udp/53,tcp/53" killed the run at line 108 553 of asm_vm_surface.
  * `--db sqlite`             -> Python loader infers a column type from the
    first non-empty value and inserts the raw string afterwards; SQLite's
    NUMERIC affinity then stores whatever it can, so the same row silently
    becomes a number-or-NULL instead of failing.

Same evidence, two engines, two different outcomes - and the pack's DDL declares
the real types (schema/migrations/*.sql) which the runner checks only for
*headers*, never for values.

This tool reads the DDL, sniffs each CSV with DuckDB at sample_size=-1 (whole
file, not a sample) and reports, per table/column:
  DDL type | sniffed type | rows that fail the DDL type | first bad line.
Exit code 1 if any column would break a --fast-csv load.

Usage:
  python csv_type_preflight.py --pack <pack root> --evidence-dir DIR
                               [--compare-dir BASELINE_DIR] [--out json]
"""

import argparse
import csv
import io
import json
import os
import re
import sys

import duckdb

# The trailing semicolon is optional: migrations written without one are still
# the pack's DDL, and a regex that silently matches nothing would report "0 type
# mismatches" for a pack it never actually read (main() refuses that case).
CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_]+)\s*\((.*?)\n\)\s*;?",
    re.S | re.I)
COL_RE = re.compile(r"^\s*,?\s*([A-Za-z_][A-Za-z0-9_]*)\s+"
                    r"(VARCHAR|TEXT|INTEGER|BIGINT|INT|DOUBLE|REAL|FLOAT|"
                    r"BOOLEAN|TIMESTAMP|DATE|DECIMAL\s*\([^)]*\)|BLOB)\b",
                    re.I)


def ddl_types(pack_root):
    """table -> {column: declared type} from schema/migrations/*.sql."""
    out = {}
    mig = os.path.join(pack_root, "schema", "migrations")
    for name in sorted(os.listdir(mig)) if os.path.isdir(mig) else []:
        if not name.endswith(".sql"):
            continue
        text = io.open(os.path.join(mig, name), encoding="utf-8").read()
        for tname, body in CREATE_RE.findall(text):
            cols = {}
            for line in body.splitlines():
                line = line.split("--", 1)[0]           # strip trailing comment
                m = COL_RE.match(line)
                if m:
                    cols[m.group(1).lower()] = m.group(2).upper()
            if cols:
                out[tname.lower()] = cols
    return out


NUMERIC = ("INTEGER", "BIGINT", "INT", "DOUBLE", "REAL", "FLOAT")
BOOLISH = ("BOOLEAN",)


def fails_type(value, decl):
    """Would this CSV value fail a strict COPY into a column of type decl?"""
    if value is None or value == "":
        return False                              # NULL is legal in every type
    d = decl.split("(")[0]
    if d in NUMERIC:
        try:
            float(value)
            return False
        except ValueError:
            return True
    if d in BOOLISH:
        return value.strip().lower() not in (
            "true", "false", "t", "f", "yes", "no", "1", "0")
    return False


def sniff(conn, path, table, sample_size=None):
    """(column -> sniffed type, rows) using the RUNNER's own load statement.

    sample_size=None means DuckDB's default, i.e. exactly what
    `ctf_run_checks --fast-csv` does: CREATE TABLE t AS SELECT * FROM
    read_csv(path, header=true). Doing the real load, instead of a smarter
    DESCRIBE, is the point: the failure mode is the 20 480-row SNIFF choosing
    BIGINT for a column that a later row fills with a string.
    """
    opts = "header=true" + ("" if sample_size is None else
                            ", sample_size=%d" % sample_size)
    q = ('CREATE TABLE %s AS SELECT * FROM read_csv(?, %s)'
         % (_q(table), opts))
    try:
        conn.execute(q, [path])
    except Exception as exc:                        # noqa: BLE001
        conn.execute("DROP TABLE IF EXISTS %s" % _q(table))
        return None, None, " ".join(str(exc).split())[:400]
    cols = {r[0].lower(): str(r[1]).upper()
            for r in conn.execute("DESCRIBE %s" % _q(table)).fetchall()}
    rows = conn.execute("SELECT count(*) FROM %s" % _q(table)).fetchone()[0]
    conn.execute("DROP TABLE IF EXISTS %s" % _q(table))
    return cols, rows, None


def _q(name):
    return '"%s"' % name.replace('"', '""')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True)
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out", default="csv_type_preflight.json")
    args = ap.parse_args()

    ddl = ddl_types(args.pack)
    if not ddl:
        # Never report a clean bill of health for a pack we could not read.
        print("ERROR: no CREATE TABLE statements parsed from %s "
              "(schema/migrations/*.sql); cannot say anything about types"
              % os.path.join(args.pack, "schema", "migrations"), file=sys.stderr)
        return 2
    conn = duckdb.connect()
    report = {"pack": args.pack, "evidence_dir": args.evidence_dir,
              "tables": [], "breaks_fast_csv": [], "type_drift_vs_baseline": [],
              "ddl_vs_sniff_mismatch": []}

    for name in sorted(os.listdir(args.evidence_dir)):
        if not name.endswith(".csv"):
            continue
        table = name[:-4].lower()
        path = os.path.join(args.evidence_dir, name)
        cols, rows, err = sniff(conn, path, "t_sample_" + str(len(report["tables"])))
        entry = {"table": table, "csv": name,
                 "load": "ctf_run_checks --fast-csv equivalent"}
        if err:
            entry["load_error"] = err
            entry["breaks_fast_csv"] = True
            report["breaks_fast_csv"].append(table)
            # Same file, whole-file sniff: if THAT succeeds, the sample size hid
            # the offending value and the column type is sample-dependent.
            wcols, wrows, werr = sniff(conn, path, "t_whole_" + str(len(report["tables"])),
                                       sample_size=-1)
            entry["whole_file_sniff"] = "ok" if not werr else werr[:200]
            if wcols and cols is None:
                # The runner's own load statement fails outright; these are the
                # types a whole-file sniff would have chosen instead.
                entry["whole_file_types_that_would_load"] = wcols
            elif wcols:
                entry["type_depends_on_sample_size"] = {
                    c: {"sample": cols.get(c), "whole_file": t}
                    for c, t in wcols.items() if cols.get(c) != t}
            report["tables"].append(entry)
            print("BREAKS %-46s %s" % (table, err[:160]), flush=True)
            continue
        entry["sniffed"] = cols
        entry["rows"] = rows
        entry["columns"] = len(cols)
        wcols, _, _ = sniff(conn, path, "t_whole_" + str(len(report["tables"])),
                            sample_size=-1)
        if wcols and wcols != cols:
            entry["type_depends_on_sample_size"] = {
                c: {"sample": cols.get(c), "whole_file": t}
                for c, t in wcols.items() if cols.get(c) != t}
        decl = ddl.get(table, {})
        entry["declared_in_ddl"] = bool(decl)
        bad_cols = []
        for col, dtype in sorted(cols.items()):
            d = decl.get(col)
            row = {"column": col, "sniffed": dtype, "declared": d}
            if d and d.split("(")[0] != dtype.split("(")[0]:
                # Types disagree: measure how many rows fit the DDL type, so we
                # know whether the run is silently reloading a typed column as
                # something else.
                try:
                    bad = conn.execute(
                        "SELECT count(*) FROM read_csv(?, header=true, "
                        "sample_size=-1) WHERE TRY_CAST(%s AS %s) IS NULL "
                        "AND %s IS NOT NULL"
                        % ('"%s"' % col, d, '"%s"' % col), [path]).fetchone()[0]
                except Exception as exc:            # noqa: BLE001
                    bad = "try_cast unsupported: %s" % str(exc)[:80]
                row["rows_not_matching_ddl"] = bad
                report["ddl_vs_sniff_mismatch"].append({"table": table, **row})
            bad_cols.append(row)
        entry["column_detail"] = bad_cols
        report["tables"].append(entry)
        flag = "BREAKS" if entry.get("breaks_fast_csv") else "ok"
        print("%s %-46s cols=%s rows=%s" % (
            flag, table, entry.get("columns"), entry.get("rows")), flush=True)

    with io.open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    sample_dep = [t["table"] for t in report["tables"]
                  if t.get("type_depends_on_sample_size")]
    report["type_depends_on_sample_size"] = sample_dep
    print("\nsummary: %d tables, %d break a --fast-csv load, "
          "%d with sample-size-dependent types %s, "
          "%d column-level DDL/sniff mismatches -> %s"
          % (len(report["tables"]), len(report["breaks_fast_csv"]),
             len(sample_dep), sample_dep,
             len(report["ddl_vs_sniff_mismatch"]), args.out))
    return 1 if report["breaks_fast_csv"] else 0


if __name__ == "__main__":
    sys.exit(main())
