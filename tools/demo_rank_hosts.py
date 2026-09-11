"""Demo-arc ranking of technique-contexted hosts (G4 asset).

Pure-python core `rank_hosts()` consumes already-parsed rollup inputs so it is
independent of any engine's report format; a CLI wrapper reads a D2-style
host_rollup.json and emits chains-style ranked output.

Scoring rule (identical to the session reference implementation kept under
the session working-notes tree, file findingD3/rank_actionable.py):

    score = 100 * (1 if host in C-tier else 0)
          + 30 if dominant provenance class == alert_asserted_direct else 15
          + 0.5 * n_bridge_gap_rows   (capped contribution: min(rows, 50) * 0.5)
          + 1.0 * n_distinct_stages
          + max report risk for that host

Deterministic tie-break: higher bridge-gap row count first, then ip order.
"""
from __future__ import annotations

import argparse
import json


def rank_hosts(rollup: dict) -> list[dict]:
    tiers = {k: set(v) for k, v in rollup.get("tiers", {}).items()}
    risk_by_ip = {r["ip"]: float(r.get("risk_max") or 0)
                  for r in rollup.get("rollup_top_risk", [])}
    hosts_ctx = rollup["hosts_ranked"]  # each: ip,t3_rows,stages_observed,prov_mix

    scored = []
    for h in hosts_ctx:
        prov_mix = h.get("prov_mix") or {}
        dominant = max(prov_mix.items(), key=lambda kv: (kv[1], kv[0]))[0] \
            if prov_mix else "unknown"
        score = 0.0
        if h["ip"] in tiers.get("C_port_corroborated", set()):
            score += 100
        score += 30 if dominant == "alert_asserted_direct" else 15
        score += min(h["t3_rows"], 50) * 0.5
        score += len(h.get("stages_observed", [])) * 1.0
        score += risk_by_ip.get(h["ip"], 0.0)
        badges = ""
        if h["ip"] in tiers.get("C_port_corroborated", set()):
            badges += "[C]"
        if h["ip"] in tiers.get("B_inverse_internal_only", set()):
            badges += "[Binv]"
        if h["ip"] in tiers.get("A_flagship_ip_only", set()):
            badges += "[A]"
        scored.append({"ip": h["ip"], "score": round(score, 1),
                       "t3_rows": h["t3_rows"],
                       "provenance_dominant": dominant,
                       "tier_badges": badges})

    scored.sort(key=lambda r: (-r["score"], -r["t3_rows"], r["ip"]))
    return scored


RULE_TEXT = ("100*C-tier + 30/15 dominant provenance + 0.5*min(rows,50) "
             "+ 1*distinct stages + max report risk")


def main() -> int:
    ap = argparse.ArgumentParser(description="rank technique-contexted hosts (demo arc)")
    ap.add_argument("--rollup", required=True, help="path to D2 host_rollup.json")
    ap.add_argument("--out", required=True, help="output chains-style json path")
    args = ap.parse_args()

    rollup = json.load(open(args.rollup, encoding="utf-8"))
    ranked = rank_hosts(rollup)
    payload = {"ranking_rule": RULE_TEXT, "source_rollup": str(args.rollup),
               "hosts_ranked": ranked}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1)
    print(f"ranked {len(ranked)} hosts -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
