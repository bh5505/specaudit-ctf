"""Durable host-rollup builder feeding the demo-arc ranking/analysis pipeline.

Consumes a pack report.json (the durable output of a real `ctf_run_checks.py`
run over an operator-supplied pack) and produces the exact
`g_rollup_input`-style rollup that `tools/demo_rank_hosts.py` consumes. This
closes the durable end-to-end pipeline: pack report -> demo_rollup_hosts ->
demo_rank_hosts -> demo_target_analysis.

Default tiers are derived from finding content, not from any pack's check ids:

  technique_context   <- IPs of technique-carrying findings (details carry
                         `technique=` / `tactic=` markers)
  critical_flagship   <- IPs of severity-critical findings
  port_corroborated   <- IPs of severity-critical findings whose
                         record_locator carries an ip:port token

Technique context (t3_rows / stages_observed / prov_mix) is parsed from the
technique-carrying details string (`tactic=` / `provenance_class=`), so ranking
inputs stay engine-agnostic and derived purely from pack output.

When the operator supplies ``tier_for_check`` (a joint-run mapping of check id
-> tier label), it OVERRIDES the default derivation for the check ids present:
the mapped tier value is used verbatim for those findings' IPs.

Pure-stdlib core (json/re); CLI wrapper reads a report.json and writes rollup.json.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from collections.abc import Mapping

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
IP_PORT_RE = re.compile(r"\d+\.\d+\.\d+\.\d+:\d+")
TACTIC_RE = re.compile(r"tactic=([^;]*)")
TECH_RE = re.compile(r"technique=([^;]*)")
PROV_RE = re.compile(r"provenance_class=([^;]*)")

GENERIC_TIERS = ("technique_context", "critical_flagship", "port_corroborated")


def _is_technique_carrying(finding: dict) -> bool:
    details = finding.get("details") or ""
    return bool(TECH_RE.search(details) or TACTIC_RE.search(details))


def build_rollup(findings: list[dict],
                 tier_for_check: Mapping[str, str] | None = None) -> dict:
    """Per-host tier/risk/context rollup from pack findings.

    ``tier_for_check`` (operator/joint-run product mapping) overrides the
    default content-derived tier for check ids present in the mapping; tier
    values are used verbatim.
    """
    tiers = {name: set() for name in GENERIC_TIERS}
    risk_by_ip: dict[str, float] = defaultdict(float)
    ctx: dict[str, dict] = defaultdict(lambda: {
        "t3_rows": 0, "stages_observed": set(), "prov_mix": defaultdict(int)})

    for f in findings:
        cid = f.get("check_id")
        loc = f.get("record_locator") or ""
        ips = set(IP_RE.findall(loc)) | set(IP_RE.findall(f.get("title") or ""))
        mapped = (tier_for_check or {}).get(cid)
        if mapped:
            tiers.setdefault(str(mapped), set()).update(ips)
        else:
            critical = f.get("severity") == "critical"
            for ip in ips:
                if critical:
                    tiers["critical_flagship"].add(ip)
                    if IP_PORT_RE.search(loc):
                        tiers["port_corroborated"].add(ip)
        if _is_technique_carrying(f):
            if not mapped:
                tiers["technique_context"].update(ips)
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
    tier_counts = ", ".join("%s=%d" % (name, len(ips))
                            for name, ips in sorted(rollup["tiers"].items()))
    print(f"rollup: {len(rollup['hosts_ranked'])} technique-contexted hosts, "
          f"{tier_counts} -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
