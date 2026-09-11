"""End-to-end priority-target + attack-path map generator (demo arc, v2).

Turns PACK OUTPUT (a real `ctf_run_checks.py` report.json) plus the canonical
silver evidence directory and the Finding E curated CVE->technique map into a
priority-target ranking and a grounded multi-step ATT&CK attack-path map.

Pure-python stdlib core (csv/json/re) so it stays hermetic and independent of
engine report formats. Inputs:

  --report   findings from the ext_telecom_asmvm pack run (the durable pack
             output; technique context in T3 details, tiers/risk in t1 rows)
  --evidence canonical silver evidence directory (cve_observation.csv for
             ASM-inferred CVEs, vm_cve_observation.csv for scan-confirmed)
  --map      Finding E curated CVE->technique map (bundle prose has zero anchors)

Output is a markdown deliverable: priority target list (sorted by pack score
and initial-access convergence) + per-target attack paths where alert-asserted
initial-access techniques are cross-corroborated by curated RCE-CVE mappings.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

T3 = "ext_telecom_asmvm_t3_asmvm_technique_context_bridge_gap"
T1_FLAGSHIP = "ext_telecom_asmvm_t1_critical_vuln_on_exposed"
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
TECH_RE = re.compile(r"technique=([^;]*)")


def parse_report(findings: list[dict]) -> dict:
    """Per-IP rollup from pack findings: techniques, ports, tiers, risk."""
    per_ip: dict[str, dict] = defaultdict(lambda: {
        "techniques": set(), "ports": set(), "tiers": set(),
        "risk_max": 0.0, "t3_rows": 0})
    for f in findings:
        cid = f.get("check_id")
        loc = f.get("record_locator") or ""
        ips = set(IP_RE.findall(loc)) | set(IP_RE.findall(f.get("title") or ""))
        if cid == T3:
            m = TECH_RE.search(f.get("details") or "")
            techs = [t.strip() for t in m.group(1).split(",")] if m else []
            ports = set(IP_RE.findall(loc)) and _ports(loc)
            for ip in ips:
                rec = per_ip[ip]
                rec["techniques"].update(t for t in techs if t)
                rec["ports"].update(ports)
                rec["t3_rows"] += 1
        elif cid == T1_FLAGSHIP:
            tier = "C_flagship" if f.get("severity") == "critical" else "A_baseline"
            for ip in ips:
                per_ip[ip]["tiers"].add(tier)
                per_ip[ip]["risk_max"] = max(per_ip[ip]["risk_max"],
                                             float(f.get("risk_score") or 0))
    return {ip: {**r, "techniques": sorted(r["techniques"]),
                 "ports": sorted(r["ports"]), "tiers": sorted(r["tiers"])}
            for ip, r in per_ip.items() if r["techniques"] or r["tiers"]}


def _ports(locator: str) -> set[int]:
    m = re.search(r":(\d{1,5})(?:\s|$|/)", locator.split("/")[0])
    return {int(m.group(1))} if m else set()


def read_cves(evidence_dir: Path) -> dict:
    """Per-IP CVEs with provenance from canonical silver CSVs."""
    out: dict[str, list] = defaultdict(list)
    co = evidence_dir / "ext_telecom_asmvm_cve_observation.csv"  # ASM-inferred
    if co.exists():
        with co.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                ip, cve = row.get("ip"), (row.get("cve") or "").strip()
                if ip and cve:
                    out[ip].append({"cve": cve, "inferred_score": row.get("inferred_score"),
                                    "provenance_class": "banner_asserted_inference"})
    vo = evidence_dir / "ext_telecom_asmvm_vm_cve_observation.csv"  # scan-confirmed
    if vo.exists():
        with vo.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                ip, cve = row.get("ip"), (row.get("cve") or "").strip()
                if ip and cve:
                    out[ip].append({"cve": cve, "severity": row.get("severity"),
                                    "provenance_class": "scan_corroborated"})
    return {ip: list(set((e["cve"], e["provenance_class"]) for e in es))
            for ip, es in out.items()}


def cross_ref(per_ip: dict, cves: dict, curated: dict) -> dict:
    """Attach curated technique mapping + flag initial-access convergence."""
    enriched = {}
    for ip, r in per_ip.items():
        r = dict(r)
        r["cves"] = cves.get(ip, [])
        r["curated_initial_access"] = []
        has_T1190_alert = any(t.strip().startswith("T1190") for t in r["techniques"])
        for cve, prov in r["cves"]:
            c = curated.get(cve)
            if c and c.get("technique") == "T1190":
                r["curated_initial_access"].append((cve, c.get("kind"), c.get("confidence")))
        r["convergence"] = bool(has_T1190_alert and r["curated_initial_access"])
        enriched[ip] = r
    return enriched


def build_attack_paths(enriched: dict) -> list[dict]:
    """Grounded multi-step chains seeded by initial-access technique."""
    paths = []
    for ip, r in enriched.items():
        steps = []
        if r["convergence"]:
            steps.append({"phase": "Initial Access", "technique": "T1190",
                          "evidence": ", ".join(f"{c} ({k})" for c, k, _ in r["curated_initial_access"][:3]),
                          "provenance": "alert_asserted_direct + curated_expert_map"})
        elif any(t.strip().startswith("T1110") for t in r["techniques"]):
            steps.append({"phase": "Initial Access", "technique": "T1110",
                          "evidence": "brute-force exposed service", "provenance": "alert_asserted_direct"})
        elif any(t.strip().startswith("T1190") for t in r["techniques"]):
            steps.append({"phase": "Initial Access", "technique": "T1190",
                          "evidence": "alert-asserted, no curated CVE anchor", "provenance": "alert_asserted_direct"})
        for t in r["techniques"]:
            tid = t.strip().split(" - ")[0]
            for phase, name in (("Execution", "T1059"), ("Credential Access", "T1110"),
                                ("Credential Access", "T1003"), ("Discovery", "T1082"),
                                ("Defense Evasion", "T1070"), ("Persistence", "T1053"),
                                ("Impact", "T1486")):
                if tid == name and not any(s["technique"] == name for s in steps):
                    steps.append({"phase": phase, "technique": name,
                                  "evidence": "", "provenance": "alert_asserted_direct"})
        if steps:
            paths.append({"ip": ip, "score": r.get("risk_max"), "convergence": r["convergence"],
                          "ports": r.get("ports"), "steps": steps})
    paths.sort(key=lambda p: (-p["convergence"], -(p["score"] or 0), p["ip"]))
    return paths


def emit_markdown(paths: list[dict]) -> str:
    lines = ["# Priority Target & Attack Path Map (v2 DRAFT)\n",
             f"_{len(paths)} targets with grounded multi-step attack paths from pack findings + "
             "Finding E curated CVE->technique map._\n"]
    for p in paths:
        lines.append(f"\n## {p['ip']}  (ports {p['ports'] or 'port-less'}, risk_max {p['score']}, "
                     f"{'CONVERGED INITIAL ACCESS' if p['convergence'] else 'alert-only'})\n")
        for s in p["steps"]:
            src = f" [{s['provenance']}]" if s.get("provenance") else ""
            ev = f" — {s['evidence']}" if s.get("evidence") else ""
            lines.append(f"- **{s['phase']}** ({s['technique']}){ev}{src}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="priority-target + attack-path map from pack output")
    ap.add_argument("--report", required=True, help="pack report.json")
    ap.add_argument("--evidence", required=True, help="canonical silver evidence dir")
    ap.add_argument("--map", required=True, help="curated CVE->technique map json")
    ap.add_argument("--out", required=True, help="output markdown path")
    a = ap.parse_args()

    findings = json.load(open(a.report, encoding="utf-8"))["findings"]
    per_ip = parse_report(findings)
    cves = read_cves(Path(a.evidence))
    curated = json.load(open(a.map, encoding="utf-8"))["entries"]
    enriched = cross_ref(per_ip, cves, curated)
    paths = build_attack_paths(enriched)
    md = emit_markdown(paths)
    Path(a.out).write_text(md, encoding="utf-8")
    print(f"built {len(paths)} target profiles -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
