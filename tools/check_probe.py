#!/usr/bin/env python3
"""Per-check probe harness: run ONE pack check standalone on one engine.

The dogfood runner (ctf_run_checks.py) has no --only-check, so a single slow
check cannot be timed, explained or A/B-tested without loading the whole pack.
This harness loads only the tables a check references, using the runner's own
loader functions (same typing, same lineage stamping), then:

  * prints EXPLAIN QUERY PLAN / EXPLAIN,
  * times the check,
  * optionally runs a second SQL file against the same tables and compares the
    result rows cell-for-cell (the "counts unchanged" requirement).

Usage:
  python check_probe.py --engine sqlite --pack <pack root> \
      --evidence-dir <dir> --check <check.sql> [--candidate <new.sql>] \
      [--run-id gw-asmvm-20260902] [--limit 500000] [--budget 900]
"""

import argparse
import csv
import importlib.util
import io
import json
import os
import re
import sys
import time
import traceback

# The harness reuses the runner's own loader (typing, mapping aliases, lineage
# stamping) instead of reimplementing it, so results are comparable to a normal
# run. Override with CTF_RUNNER=<path> or --runner.
_RUNNER_CANDIDATES = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ctf_run_checks.py"),
]


def runner_path():
    env = os.environ.get("CTF_RUNNER")
    if env:
        return env
    for cand in _RUNNER_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    raise SystemExit("ctf_run_checks.py not found; set CTF_RUNNER")


def load_runner(path):
    spec = importlib.util.spec_from_file_location("ctf_run_checks", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TABLE_RE = re.compile(r"\b([a-z][a-z0-9_]*)\b")


def wanted_tables(ddl_columns, sql_texts):
    """Which evidence tables the probe has to load.

    Derived from the pack itself - the tables its migrations declare, intersected
    with the names the SQL actually mentions - rather than from a hardcoded name
    prefix, so the probe is not welded to one pack. Returns None ("load every
    CSV") when the pack declares no migrations at all.
    """
    declared = set(ddl_columns or {})
    if not declared:
        return None
    text = "\n".join(t for t in sql_texts if t)
    return {t for t in declared
            if re.search(r"\b%s\b" % re.escape(t), text, re.I)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["sqlite", "duckdb"], required=True)
    ap.add_argument("--pack", required=True)
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--check", required=True)
    ap.add_argument("--runner", default="",
                    help="path to ctf_run_checks.py (default: this tools/ dir, "
                         "or $CTF_RUNNER)")
    ap.add_argument("--candidate")
    ap.add_argument("--run-id", default="gw-asmvm-20260902")
    ap.add_argument("--limit", type=int, default=500000)
    ap.add_argument("--budget", type=float, default=0,
                    help="kill the original query after N seconds (0 = no limit)")
    ap.add_argument("--fast-csv", action="store_true",
                    help="duckdb only: load with native read_csv, mirroring the "
                         "runner's --fast-csv mode (the mode the DuckDB baseline "
                         "was produced with). Skips alias/value/lineage "
                         "normalisation - types come from DuckDB's sniff and "
                         "run_id from the CSV column.")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    m = load_runner(args.runner or runner_path())
    pack_root = m.Path(args.pack)
    evidence = m.Path(args.evidence_dir)
    mapping = m.load_mapping_spec(pack_root)
    mapping_columns = m.load_mapping_columns(pack_root)
    ddl_columns = m.load_ddl_columns(pack_root)
    ddl_types = m.load_ddl_column_types(pack_root)
    mapping_value_maps = m.load_mapping_value_maps(pack_root)

    sql_main = io.open(args.check, encoding="utf-8").read()
    sql_cand = io.open(args.candidate, encoding="utf-8").read() if args.candidate else None
    wanted = wanted_tables(ddl_columns, [sql_main, sql_cand])
    if wanted is None:
        print("note: pack declares no schema/migrations; loading every evidence "
              "CSV instead of only the ones the SQL mentions", flush=True)
    elif not wanted:
        print("warning: the check SQL mentions none of the pack's declared tables; "
              "nothing will be loaded", flush=True)

    conn, engine = m.open_engine(args.engine)
    if engine == "duckdb" and not args.fast_csv:
        # Both paths now bind cells to the types the pack's migrations declare;
        # --fast-csv stays the way the pack is normally run, and this probe still
        # says which one it used, because a probe that disagrees with production's
        # load path proves nothing about production.
        print("note: engine=duckdb without --fast-csv (row-by-row load; declared "
              "types still applied, but --fast-csv is how the pack normally runs)",
              flush=True)
    m.create_fusion_runs_shim(conn, args.run_id)
    t_load = time.time()
    loaded = {}
    if args.fast_csv and engine == "duckdb":
        for csv_path in sorted(evidence.glob("*.csv")):
            table = m._table_for(mapping, csv_path.name)
            if wanted is not None and table not in wanted:
                continue
            m._require_declared_headers(ddl_columns, table,
                                        m._read_csv_header(csv_path),
                                        csv_path.name)
            conn.execute(
                "CREATE TABLE %s AS SELECT * FROM read_csv('%s', header=true%s)"
                % (m._quote_identifier(table),
                   csv_path.as_posix().replace("'", "''"),
                   m._read_csv_type_arg(ddl_types, table,
                                        m._read_csv_header(csv_path))))
            # Stamp accept lineage exactly like the runner's fast path does. The
            # check SQL filters on run_id, so a probe that skips this silently
            # reports "ok rows=0" for any evidence whose run_id column holds a
            # different run from --run-id (the real pack's exports carry the run
            # id, which is why this stayed invisible there).
            headers = [r[0] for r in conn.execute(
                "DESCRIBE %s" % m._quote_identifier(table)).fetchall()]
            m.stamp_accept_lineage(
                conn, table, headers, args.run_id,
                preserve_run_id=m.mapping_declares_run_id_source(
                    mapping_columns, table))
            loaded[table] = conn.execute(
                "SELECT count(*) FROM %s"
                % m._quote_identifier(table)).fetchone()[0]
        print("engine=duckdb native read_csv loaded %d tables in %.1fs: %s"
              % (len(loaded), time.time() - t_load,
                 ", ".join("%s=%d" % kv for kv in sorted(loaded.items()))),
              flush=True)
    for csv_path in sorted(evidence.glob("*.csv")):
        table = m._table_for(mapping, csv_path.name)
        if wanted is not None and table not in wanted:
            continue
        if args.fast_csv and engine == "duckdb":
            continue
        with open(csv_path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            headers = next(reader, None)
            rows = [r for r in reader]
        headers = m.apply_mapping_column_aliases(mapping_columns, table, headers)
        rows = m.apply_mapping_value_maps(mapping_value_maps, table, headers, rows)
        m.create_table(conn, engine, table, rows, headers, ddl_types=ddl_types)
        m.stamp_accept_lineage(
            conn, table, headers, args.run_id,
            preserve_run_id=m.mapping_declares_run_id_source(mapping_columns, table))
        loaded[table] = len(rows)
    if not (args.fast_csv and engine == "duckdb"):
        print("engine=%s loaded %d tables in %.1fs: %s"
              % (engine, len(loaded), time.time() - t_load,
                 ", ".join("%s=%d" % kv for kv in sorted(loaded.items()))),
              flush=True)

    result = {"engine": engine, "run_id": args.run_id, "check": args.check,
              "loaded": loaded, "queries": []}

    def explain(sql, label):
        try:
            # the check SQL is parameterised (?1 run_id, ?2 limit); EXPLAIN needs
            # the same bindings or the engine rejects the statement.
            params = (args.run_id, args.limit)
            if engine == "sqlite":
                plan = conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
            else:
                plan = [("physical_plan", "\n".join(
                    r[0] for r in conn.execute("EXPLAIN " + sql, params).fetchall()))]
            result["queries"].append({"label": label,
                                      "plan": [list(p) for p in plan]})
        except Exception as exc:                       # noqa: BLE001
            result["queries"].append({"label": label, "plan_error": str(exc)})

    def run(sql, label, budget=0):
        t0 = time.time()
        box = {}
        timed_out = {"v": False}

        if engine == "sqlite" and budget:
            # SQLite cannot be interrupted from another thread, but its VM calls
            # a progress handler every N opcodes; raising there aborts the query
            # (sqlite3 translates it into OperationalError "interrupted").
            def _tick():
                if time.time() - t0 > budget:
                    timed_out["v"] = True
                    return 1          # non-zero -> interrupt
                return 0
            # NB the DB-API name is set_progress_handler; the old spelling
            # (setprogresshandler) raised AttributeError straight into this
            # except, so the budget silently never armed and a pathological
            # query ran to completion instead of reporting TIMEOUT_INCOMPLETE.
            try:
                conn.set_progress_handler(_tick, 200000)
                result["progress_handler"] = "armed (every 200000 vm ops)"
            except Exception as exc:                     # noqa: BLE001
                result["progress_handler"] = "FAILED: %r" % (exc,)
                print("WARNING: sqlite interrupt handler not armed: %r" % (exc,),
                      flush=True)
        else:
            # Say so in the report: a TIMEOUT_INCOMPLETE result is only as
            # trustworthy as the interrupt that produced it.
            result["progress_handler"] = "not armed (budget=%ss; the progress " \
                                         "interrupt is sqlite-only)" % budget

        def work():
            try:
                box["rows"] = conn.execute(sql, (args.run_id, args.limit)).fetchall()
            except Exception as exc:                   # noqa: BLE001
                box["error"] = traceback.format_exc()

        import threading
        th = None
        if engine != "sqlite":
            th = threading.Thread(target=work, daemon=True)
            th.start()
            th.join(budget if budget else None)
        else:
            work()
        elapsed = time.time() - t0
        entry = {"label": label, "seconds": round(elapsed, 3)}
        if (th is not None and th.is_alive()) or timed_out["v"]:
            entry["status"] = "TIMEOUT_INCOMPLETE"
            entry["note"] = ("query still running after %.0fs - abandoned; the "
                             "engine got no cooperative interrupt" % elapsed)
            print("%s: TIMEOUT after %.1fs" % (label, elapsed), flush=True)
        elif "error" in box:
            entry["status"] = "error"
            entry["error"] = box["error"][-1500:]
            print("%s: ERROR %s" % (label, box["error"].splitlines()[-1]),
                  flush=True)
        else:
            entry["status"] = "ok"
            entry["row_count"] = len(box["rows"])
            entry["rows"] = [[str(v) for v in r] for r in box["rows"]]
            print("%s: ok rows=%d in %.3fs" % (label, len(box["rows"]), elapsed),
                  flush=True)
        result["queries"].append(entry)
        return entry

    if os.environ.get("PROBE_EXPLAIN") == "1":
        explain(sql_main, "original_plan")
        if sql_cand:
            explain(sql_cand, "candidate_plan")
    base = run(sql_main, "original", args.budget)
    cand = run(sql_cand, "candidate", args.budget) if sql_cand else None
    if cand and base.get("status") == "ok" and cand.get("status") == "ok":
        same = (base["row_count"] == cand["row_count"]
                and base["rows"] == cand["rows"])
        # ORDER BY ties may legitimately reorder; compare as multisets too.
        same_multiset = (base["row_count"] == cand["row_count"]
                         and sorted(base["rows"]) == sorted(cand["rows"]))
        first_diff = next(("row %d" % i
                           for i, (a, b) in enumerate(zip(base["rows"],
                                                          cand["rows"]))
                           if a != b), None)
        if first_diff is None and base["row_count"] != cand["row_count"]:
            # zip() stops at the shorter result, so a rewrite that drops (or
            # adds) trailing rows shows no differing row at all. Say which row
            # the shorter side ran out of instead of reporting None.
            first_diff = "row %d: one side has no further rows (original %d, "\
                         "candidate %d)" % (min(base["row_count"],
                                                cand["row_count"]),
                                            base["row_count"],
                                            cand["row_count"])
        result["equivalence_extra"] = {
            "identical_as_multiset": same_multiset,
            "first_difference": first_diff,
        }
        result["equivalence"] = {
            "identical_rows": same,
            "identical_as_multiset": same_multiset,
            "original_rows": base["row_count"],
            "candidate_rows": cand["row_count"],
            "speedup_x": (round(base["seconds"] / cand["seconds"], 1)
                          if cand["seconds"] else None),
        }
        print("EQUIVALENCE: identical=%s (%d rows both)" % (same, base["row_count"]),
              flush=True)
    elif cand:
        result["equivalence"] = {"identical_rows": None,
                                 "reason": "original did not complete or errored"}
        print("EQUIVALENCE: original status=%s candidate status=%s"
              % (base.get("status"), cand.get("status")), flush=True)

    out = args.out or ("probe_%s_%s.json" % (
        engine, os.path.splitext(os.path.basename(args.check))[0]))
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
