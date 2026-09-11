"""Durable per-alert technique<->stage pairing extractor (G3).

Extracts REAL vendor co-assertions from the canonical silver base tables using
the migration-005 join predicate verbatim (alert -> alert_endpoint ->
service_endpoint with the same activity/mitre filters), so every pair keeps its
per-alert identity (vendor_alert_id / alert_id / asr_rule) that the landing-zone
VIEW intentionally drops when DISTINCT-collapsing. This is the honest supersession
of stage-union fuzzy pairing for the ranked target set.

Uses DuckDB in-memory over the silver CSVs (the harness already depends on
DuckDB, so this is not a new runtime requirement). Pure core `extract_pairings()`
returns per-alert pair dicts; CLI writes them to a JSON file.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

BASE_TABLES = ("ext_telecom_asmvm_alert",
               "ext_telecom_asmvm_alert_endpoint",
               "ext_telecom_asmvm_service_endpoint")

JOIN_PREDICATE = """
SELECT a.vendor_alert_id, a.alert_id, s.ip, s.port,
       a.mitre_tactic, a.mitre_technique, MAX(a.asr_rule) AS asr_rule,
       CASE WHEN a.ipv4_list = ae.ip THEN 'alert_asserted_direct'
            ELSE 'alert_endpoint_bridged' END AS provenance_class
FROM ext_telecom_asmvm_alert a
JOIN ext_telecom_asmvm_alert_endpoint ae
  ON ae.run_id = a.run_id AND ae.engagement_id = a.engagement_id
 AND ae.alert_id = a.alert_id
JOIN ext_telecom_asmvm_service_endpoint s
  ON s.run_id = ae.run_id AND s.engagement_id = ae.engagement_id AND s.ip = ae.ip
WHERE a.mitre_technique IS NOT NULL AND TRIM(a.mitre_technique) <> ''
  AND a.is_active_state AND ae.is_active_state AND s.is_active
  AND s.ip IN ({placeholders})
GROUP BY 1,2,3,4,5,6,8
ORDER BY s.ip, s.port, a.alert_id
"""


def extract_pairings(evidence_dir: Path, focus_ips: Iterable[str]) -> list[dict]:
    """Per-alert technique pairs for the focus IPs (migration-005 predicate)."""
    import duckdb

    focus = sorted(set(focus_ips))
    con = duckdb.connect(database=":memory:")
    try:
        for table in BASE_TABLES:
            csv_path = (evidence_dir / f"{table}.csv").as_posix()
            con.execute(f"CREATE TABLE {table} AS SELECT * FROM read_csv_auto('{csv_path}')")
        placeholders = ",".join("?" * len(focus))
        query = JOIN_PREDICATE.format(placeholders=placeholders)
        rows = con.execute(query, focus).fetchall()
    finally:
        con.close()
    return [{"vendor_alert_id": r[0], "alert_id": r[1], "ip": r[2],
             "port": int(r[3]), "mitre_tactic": r[4], "mitre_technique": r[5],
             "asr_rule": r[6] or "", "provenance_class": r[7]} for r in rows]


def main() -> int:
    ap = argparse.ArgumentParser(description="extract per-alert technique pairs (G3)")
    ap.add_argument("--evidence", required=True, help="canonical silver evidence dir")
    ap.add_argument("--focus", required=True,
                    help="json array of focus IPs (or a chains/hosts_ranked json)")
    ap.add_argument("--out", required=True, help="output alert_pairs.json path")
    a = ap.parse_args()

    raw = json.load(open(a.focus, encoding="utf-8"))
    if isinstance(raw, dict):  # accept a hosts_ranked rollup
        focus = [r["ip"] for r in raw.get("hosts_ranked", [])]
    else:
        focus = [str(x) for x in raw]
    pairs = extract_pairings(Path(a.evidence), focus)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump({"focus_hosts": sorted(set(focus)), "pair_rows": pairs}, fh, indent=1)
    print(f"{len(pairs)} per-alert pairs across {len(set(focus))} focus hosts -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
