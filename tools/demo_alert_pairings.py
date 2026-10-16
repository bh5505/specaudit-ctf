"""Durable per-alert technique<->stage pairing extractor (G3).

Extracts per-alert co-assertions from the canonical silver base tables using an
operator-supplied join predicate (alert -> alert_endpoint -> service_endpoint
with activity/mitre filters is the reference shape), so every pair keeps its
per-alert identity (vendor_alert_id / alert_id / rule) that a landing-zone
DISTINCT view would collapse. The base tables and the join predicate are
joint-run configuration supplied by the operator: this repository ships no
pack, so with no tables configured there is nothing durable to extract and the
result is [] rather than a report-text approximation.

Uses DuckDB in-memory over the silver CSVs (the harness already depends on
DuckDB, so this is not a new runtime requirement). Pure core
`extract_pairings()` returns per-alert pair dicts keyed by the predicate's
selected columns; the CLI writes them to a JSON file.
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Iterable, Sequence
from pathlib import Path


def _require_single_select(predicate: str) -> str:
    """Fail closed on anything but a single SELECT statement.

    The predicate is pasted into `predicate.format(placeholders=...)` and run
    verbatim, so a second statement or a non-SELECT must be refused before any
    engine sees it.
    """
    text = predicate.strip()
    while text.startswith("--"):  # strip leading full-line comments
        text = text.split("\n", 1)[1].strip() if "\n" in text else ""
    stripped = text.rstrip(";").strip()
    if not stripped or not stripped.upper().startswith("SELECT") \
            or ";" in stripped:
        raise ValueError(
            "join predicate must be a single SELECT statement (no ';', no "
            "non-SELECT statements)")
    return text


def extract_pairings(evidence_dir: Path, focus_ips: Iterable[str], *,
                     tables: Sequence[str] = (),
                     join_predicate: str | None = None) -> list[dict]:
    """Per-alert technique pairs for the focus IPs.

    ``tables`` (CSV base table names in ``evidence_dir``) and
    ``join_predicate`` (SQL over those tables; may reference ``{placeholders}``
    for the parameterized focus-IP list) are operator-supplied joint-run
    configuration. With no tables or no predicate configured the result is []
    -- pairing is unavailable, not fuzzily approximated.
    """
    if not tables or not join_predicate:
        return []
    import duckdb

    predicate = _require_single_select(join_predicate)
    focus = sorted(set(focus_ips))
    con = duckdb.connect(database=":memory:")
    try:
        for table in tables:
            csv_path = (evidence_dir / f"{table}.csv").as_posix()
            con.execute(f"CREATE TABLE {table} AS SELECT * FROM read_csv_auto('{csv_path}')")
        placeholders = ",".join("?" * len(focus))
        query = predicate.format(placeholders=placeholders)
        cur = con.execute(query, focus)
        columns = [d[0] for d in cur.description]
        rows = cur.fetchall()
    finally:
        con.close()
    pairs = []
    for row in rows:
        pair = dict(zip(columns, row))
        if isinstance(pair.get("port"), str):
            try:
                pair["port"] = int(pair["port"])
            except ValueError:
                pass
        pairs.append(pair)
    return pairs


def main() -> int:
    ap = argparse.ArgumentParser(description="extract per-alert technique pairs (G3)")
    ap.add_argument("--evidence", required=True, help="canonical silver evidence dir")
    ap.add_argument("--focus", required=True,
                    help="json array of focus IPs (or a hosts_ranked json)")
    ap.add_argument("--out", required=True, help="output alert_pairs.json path")
    ap.add_argument("--tables", default="",
                    help="comma-separated pairing base table names")
    ap.add_argument("--predicate-file",
                    help="SQL join predicate file; may reference {placeholders}")
    a = ap.parse_args()

    if not a.tables or not a.predicate_file:
        ap.error(
            "--tables and --predicate-file are required: the pairing base "
            "tables and join predicate are operator-supplied joint-run "
            "configuration (this repository ships no pack)")
    tables = [t.strip() for t in a.tables.split(",") if t.strip()]
    predicate = Path(a.predicate_file).read_text(encoding="utf-8")

    raw = json.load(open(a.focus, encoding="utf-8"))
    if isinstance(raw, dict):  # accept a hosts_ranked rollup
        focus = [r["ip"] for r in raw.get("hosts_ranked", [])]
    else:
        focus = [str(x) for x in raw]
    pairs = extract_pairings(Path(a.evidence), focus,
                             tables=tables, join_predicate=predicate)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump({"focus_hosts": sorted(set(focus)), "pair_rows": pairs}, fh, indent=1)
    print(f"{len(pairs)} per-alert pairs across {len(set(focus))} focus hosts -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
