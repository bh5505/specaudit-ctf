"""Durable host-rollup builder feeding the demo-arc ranking/analysis pipeline.

Consumes the ext_telecom_asmvm pack report.json (the durable output of a real
`ctf_run_checks.py` run) and produces the exact `g_rollup_input`-style rollup
that `tools/demo_rank_hosts.py` consumes. This closes the durable end-to-end
pipeline: pack report -> demo_rollup_hosts -> demo_rank_hosts ->
demo_target_analysis.

Tiers are derived by check_id (mirroring the operator flagship ruling, option C):
  A_flagship_ip_only         <- ext_telecom_asmvm_t1_critical_vuln_on_exposed
  C_port_corroborated        <- ext_telecom_asmvm_t1_asmvm_critical_service_corroborated
  B_inverse_internal_only    <- ext_telecom_asmvm_t1_asmvm_critical_internal_record_only
  T3_technique_context       <- any technique-context bridge-gap finding

Technique context (t3_rows / stages_observed / prov_mix) is parsed from the T3
bridge-gap details string (`tactic=` / `provenance_class=`), so ranking inputs
stay engine-agnostic and derived purely from pack output.

Pure-stdlib core (json/re); CLI wrapper reads a report.json and writes rollup.json.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict

T3 = "ext_telecom_asmvm_t3_asmvm_technique_context_bridge_gap"
A = "ext_telecom_asmvm_t1_critical_vuln_on_exposed"
C = "ext_telecom_asmvm_t1_asmvm_critical_service_corroborated"
B = "ext_telecom_asmvm_t1_asmvm_critical_internal_record_only"

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
TACTIC_RE = re.compile(r"tactic=([^;]*)")
PROV_RE = re.compile(r"provenance_class=([^;]*)")

TIER_FOR_CHECK = {A: "A_flagship_ip_only", C: "C_port_corroborated",
                  B: "B_inverse_internal_only", T3: "T3_technique_context"}


def build_rollup(findings: list[dict]) -> dict:
    tiers = {name: set() for name in
             ("A_flagship_ip_only", "B_inverse_internal_only",
              "C_port_corroborated", "T3_technique_context")}
    risk_by_ip: dict[str, float] = defaultdict(float)
    ctx: dict[str, dict] = defaultdict(lambda: {
        "t3_rows": 0, "stages_observed": set(), "prov_mix": defaultdict(int)})

    for f in findings:
        cid = f.get("check_id")
        loc = f.get("record_locator") or ""
        ips = set(IP_RE.findall(loc)) | set(IP_RE.findall(f.get("title") or ""))
        tier = TIER_FOR_CHECK.get(cid)
        if tier:
            tiers[tier].update(ips)
        if cid == T3:
            tm = TACTIC_RE.search(f.get("details") or "")
            stages = [s.strip() for s in tm.group(1).split(",") if s.strip()] if tm else []
            pm = PROV_RE.search(f.get("details") or "")
            prov = pm.group(1).strip() if pm else "unknown"
            for ip in ips:
                c = ctx[ip]
                c["t3_rows"] += 1
                c["stages_observed"].update(
                    s.split(" - ")[0].strip() for s in stages)
                c["prov_mix"][prov] += 1
        if f.get("risk_score"):
            for ip in ips:
                risk_by_ip[ip] = max(risk_by_ip[ip], float(f["risk_score"]))

    hosts_ranked = []
    for ip, c in ctx.items():
        if not c["t3_rows"]:
            continue
        hosts_ranked.append({
            "ip": ip, "t3_rows": c["t3_rows"],
            "stages_observed": sorted(c["stages_observed"]),
            "prov_mix": dict(c["prov_mix"])})

    return {
        "tiers": {name: sorted(s) for name, s in tiers.items()},
        "rollup_top_risk": sorted(
            ({"ip": ip, "risk_max": r} for ip, r in risk_by_ip.items()),
            key=lambda e: (-e["risk_max"], e["ip"])),
        "hosts_ranked": sorted(
            hosts_ranked, key=lambda h: (-h["t3_rows"], h["ip"])),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="build host rollup from pack report")
    ap.add_argument("--report", required=True, help="pack report.json")
    ap.add_argument("--out", required=True, help="output rollup json path")
    a = ap.parse_args()
    findings = json.load(open(a.report, encoding="utf-8"))["findings"]
    rollup = build_rollup(findings)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(rollup, fh, indent=1)
    print(f"rollup: {len(rollup['hosts_ranked'])} technique-contexted hosts, "
          f"A={len(rollup['tiers']['A_flagship_ip_only'])}, "
          f"C={len(rollup['tiers']['C_port_corroborated'])}, "
          f"B={len(rollup['tiers']['B_inverse_internal_only'])} -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
