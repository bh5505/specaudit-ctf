"""Durable governed pipeline: pack findings -> prioritized targets with threat
models + attack chains (the specaudit-ctf MCP-surface orchestration).

specaudit-ctf *is* the MCP surface. The ``tools/*.py`` scripts are the backend
logic; this module wires their durable cores behind a small set of stable MCP
surface tools so an agent drives the end-to-end loop through MCP surfaces, not
ad-hoc bash guessing at CLI shapes.

The governed end-to-end path (every step is an MCP surface tool):

    step 1   invoke <recon/enrich arm>          seed = top-level domains + a
             asset-recon, gti, vulnify, zdns,   description of the target
             zgrab2, httpprobe, nmap, ...       environment -> assets + intel
    step 2   pack_run                          ext_telecom_asmvm over evidence
                                                 -> report.json (findings)
    step 3   prioritize_targets                report -> prioritized target list
                                                 with threat models + attack
                                                 chains (HUMAN VALIDATION GATE
                                                 deliverable for red-team review)
    step 4   invoke <scan arm>                 agentic exploitability validation
             nmap, zgrab2, httpprobe,          of the human-validated targets
             snmp_readtier, ike_readtier, ...

Only steps 2 and 3 are new surface tools; steps 1 and 4 already exist as the
``invoke`` arm surface. The cores imported here are the same deterministic
logic the ``tools/demo_*`` CLIs call -- this module is the governed caller.

Pure-stdlib; sqlite is the default pack engine so the surface needs no duckdb.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# Make the repo-root ``tools/`` package importable regardless of cwd.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools import ctf_run_checks  # noqa: E402  (lazy duckdb; sqlite is stdlib)
from tools import demo_target_analysis as dta  # noqa: E402
from tools import demo_rollup_hosts as drh  # noqa: E402
from tools import demo_rank_hosts as drk  # noqa: E402
from tools import render_provenance_header as rph  # noqa: E402

# Default location of the curated CVE->technique map shipped with the vulnify arm.
_CURATED_MAP_DEFAULT = (
    _ROOT / "extension" / "arms" / "vulnify" / "data" / "curated_cve_technique_map.json"
)

# ATT&CK phases ordered for the threat-model narrative.
_PHASE_ORDER = (
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Impact",
)

# Inferred asset role by management/service ports (mirrors the pack port classes).
_ROLE_BY_PORT = {
    500: "VPN concentrator (IKE)", 4500: "VPN concentrator (NAT-T IKE)",
    123: "NTP timing element", 53: "DNS resolver", 161: "network element mgmt (SNMP)",
    22: "remote admin (SSH)", 23: "remote admin (Telnet)",
    80: "web origin (HTTP)", 443: "web origin (HTTPS)", 8443: "web origin (HTTPS alt)",
    25: "mail relay (SMTP)", 3389: "remote desktop (RDP)",
}


def _asset_role(ports: list) -> str:
    """Infer an asset-role label from the ports the pack surfaced."""
    if not ports:
        return "unknown (port-less finding)"
    roles = []
    for p in ports:
        if p in _ROLE_BY_PORT:
            roles.append(_ROLE_BY_PORT[p])
    return "; ".join(sorted(set(roles))) if roles else "service endpoint (unclassified)"


def _threat_model(ip: str, target: dict) -> dict:
    """Build a concise per-target threat model from pack findings.

    This is the human-validation framing: what the asset is, how it is most
    likely to be reached, what happens after, and why it is ranked where it is.
    It is deliberately a *hypothesis to be validated* -- every assertion is
    grounded in the pack finding provenance, and the human red-team analyst is
    the gate before any agentic exploitability validation proceeds.
    """
    steps = target.get("steps", [])
    initial = next((s for s in steps if s.get("phase") == "Initial Access"), None)
    post = [s for s in steps if s.get("phase") != "Initial Access"]
    phases_seen = [s.get("phase") for s in steps]
    impact = next((s for s in post if s.get("phase") == "Impact"), None)
    return {
        "ip": ip,
        "asset_role": _asset_role(target.get("ports") or []),
        "rank": target.get("rank"),
        "score": target.get("score"),
        "converged_initial_access": bool(target.get("convergence")),
        "priority_justification": (
            "CROSS-SOURCE CONVERGENCE: alert-asserted initial-access technique "
            "cross-corroborated by a curated RCE CVE mapping -- highest-confidence "
            "initial-access hypothesis"
            if target.get("convergence")
            else "alert-asserted initial-access technique, no curated CVE anchor yet"
        ),
        "expected_initial_access": {
            "technique": initial.get("technique") if initial else None,
            "evidence": initial.get("evidence") if initial else None,
            "provenance": initial.get("provenance") if initial else None,
        },
        "post_initial_access": [
            {"phase": s.get("phase"), "technique": s.get("technique")} for s in post
        ],
        "likely_impact": impact.get("technique") if impact else None,
        "phases_observed": sorted(set(phases_seen), key=lambda p: _PHASE_ORDER.index(p) if p in _PHASE_ORDER else 99),
        "validation_status": "awaiting human red-team analyst validation",
    }


def _ranked_targets(findings: list[dict]) -> list[dict]:
    """Ranked priority targets (ip + score + tiers) from pack findings."""
    rollup = drh.build_rollup(findings)
    try:
        ranked = drk.rank_hosts(rollup)
    except Exception:  # pragma: no cover - ranking is best-effort metadata
        ranked = []
    score_by_ip = {r.get("ip"): r.get("score") for r in ranked if isinstance(r, dict)}
    tiers_by_ip = {}
    for tier, ips in (rollup.get("tiers") or {}).items():
        for ip in ips:
            tiers_by_ip.setdefault(ip, []).append(tier)
    return [
        {"ip": ip, "score": score_by_ip.get(ip), "tiers": tiers_by_ip.get(ip, [])}
        for ip in score_by_ip
    ]


def pack_run(
    pack_root: str,
    evidence_dir: str,
    out_dir: str | None = None,
    db: str = "sqlite",
    limit: int = 100,
    run_id: str | None = None,
    fast_csv: bool = False,
) -> dict:
    """Run an ext_telecom_asmvm pack over an evidence dir (governed step 2).

    Wraps ``tools/ctf_run_checks.run()`` (the durable runner) and returns both
    the parsed report and the report.json path, so the next surface step
    (``prioritize_targets``) consumes a stable, discoverable artifact rather
    than guessing at output locations.
    """
    out = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="ctf-mcp-"))
    if db not in ("duckdb", "sqlite"):
        raise ValueError("db must be 'duckdb' or 'sqlite'")
    rid = run_id or "mcp-%s" % os.urandom(4).hex()
    rc = ctf_run_checks.run(
        pack_root, evidence_dir, str(out), db, limit, rid, fast_csv=fast_csv
    )
    if rc != 0:
        raise RuntimeError("pack run failed (rc=%r)" % rc)
    report_path = out / "report.json"
    if not report_path.is_file():
        raise RuntimeError("pack run did not produce report.json at %s" % report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return {"report": report, "report_path": str(report_path), "run_id": rid}


def _load_findings(report, report_path) -> list[dict]:
    if isinstance(report, dict) and isinstance(report.get("findings"), list):
        return report["findings"]
    if report_path:
        p = Path(report_path)
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))["findings"]
    if isinstance(report, list):
        return report
    raise ValueError("prioritize_targets needs a pack report (findings list) or a report_path")


def prioritize_targets(
    report: dict | list | None = None,
    report_path: str | None = None,
    evidence_dir: str | None = None,
    map_path: str | None = None,
    with_report: bool = True,
    out_path: str | None = None,
) -> dict:
    """Prioritized target list with threat models + attack chains (step 3).

    Consumes the pack report (from ``pack_run``) plus optional evidence/CVE
    cross-reference and the curated CVE->technique map, and produces the
    human-validation-ready deliverable: ranked targets, each with a threat
    model and a grounded multi-step ATT&CK attack chain, plus the rendered
    markdown report for human red-team analysts to validate.

    ``map_path`` defaults to the curated map shipped with the vulnify arm.
    ``evidence_dir`` enables CVE cross-reference (ASM-inferred + scan CVEs).
    """
    if report is None and report_path is None:
        raise ValueError("prioritize_targets needs report (dict/list) or report_path")
    findings = _load_findings(report, report_path)
    per_ip = dta.parse_report(findings)

    cves = {}
    if evidence_dir:
        cves = dta.read_cves(Path(evidence_dir))

    curated = {}
    map_file = Path(map_path) if map_path else _CURATED_MAP_DEFAULT
    if map_file.is_file():
        curated = json.loads(map_file.read_text(encoding="utf-8")).get("entries", {})

    enriched = dta.cross_ref(per_ip, cves, curated)
    paths = dta.build_attack_paths(enriched)
    ranked = _ranked_targets(findings)
    rank_by_ip = {t["ip"]: i for i, t in enumerate(ranked)}

    targets = []
    for p in paths:
        ip = p["ip"]
        tm = _threat_model(ip, p)
        tm["rank"] = rank_by_ip.get(ip)  # None if the host was not technique-context ranked
        targets.append({
            "ip": ip,
            "rank": tm["rank"],
            "score": p.get("score"),
            "ports": p.get("ports"),
            "convergence": p.get("convergence"),
            "threat_model": tm,
            "attack_chain": p.get("steps"),
        })

    result = {
        "targets": targets,
        "summary": {
            "total_targets": len(targets),
            "converged_initial_access": sum(1 for t in targets if t["convergence"]),
            "by_asset_role": _count_by(targets, lambda t: t["threat_model"]["asset_role"]),
            "human_validation_gate": "REQUIRED before any agentic exploitability validation",
        },
    }
    if with_report:
        md = _validation_report_markdown(targets, findings)
        if out_path:
            Path(out_path).write_text(md, encoding="utf-8")
            result["report_path"] = out_path
            result["markdown"] = None
        else:
            result["markdown"] = md
    return result


def _count_by(targets: list[dict], key) -> dict:
    out: dict[str, int] = {}
    for t in targets:
        k = key(t)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _validation_report_markdown(targets: list[dict], findings: list[dict]) -> str:
    """Human red-team validation report: prioritized targets, threat models,
    attack chains, and an explicit analyst sign-off gate."""
    lines = [
        "# Prioritized Target List — Threat Models & Attack Chains (human validation gate)\n",
        f"_{len(targets)} prioritized targets derived from {len(findings)} pack findings. "
        "Review and sign off below before any agentic exploitability validation._\n",
    ]
    for i, t in enumerate(targets, 1):
        tm = t["threat_model"]
        lines.append(
            f"\n## {i}. {t['ip']}  "
            f"(rank {tm.get('rank')}, risk_max {t['score']}, "
            f"{'CONVERGED INITIAL ACCESS' if t['convergence'] else 'alert-only'})"
        )
        lines.append(f"- **Asset role**: {tm['asset_role']}")
        lines.append(f"- **Priority**: {tm['priority_justification']}")
        ia = tm["expected_initial_access"]
        if ia and ia["technique"]:
            lines.append(f"- **Expected initial access**: {ia['technique']}"
                         + (f" — {ia['evidence']}" if ia["evidence"] else ""))
        if tm["post_initial_access"]:
            chain = " → ".join(f"{s['technique']} ({s['phase']})" for s in tm["post_initial_access"])
            lines.append(f"- **Post-initial-access chain**: {chain}")
        if tm["likely_impact"]:
            lines.append(f"- **Likely impact**: {tm['likely_impact']}")
        lines.append(f"- **Validation status**: {tm['validation_status']}")
    lines.append("\n---\n## Human red-team analyst validation gate\n")
    lines.append("For each target: confirm the asset role, initial-access hypothesis and")
    lines.append("attack chain are correct before agentic exploitability validation runs.")
    lines.append("\n- [ ] target set reviewed and confirmed\n")
    return "\n".join(lines) + "\n"


def validation_report(
    report: dict | list | None = None,
    report_path: str | None = None,
    evidence_dir: str | None = None,
    map_path: str | None = None,
    out_path: str | None = None,
    run_id: str = "mcp",
) -> dict:
    """Full handoff deliverable: prioritized targets + provenance header.

    Convenience that renders ``prioritize_targets`` output and injects the
    self-refreshing provenance block (generation stamp, run-id, cited receipt
    digests) so the validation report is auditable.
    """
    result = prioritize_targets(
        report=report, report_path=report_path, evidence_dir=evidence_dir,
        map_path=map_path, with_report=True, out_path=out_path,
    )
    md = result.get("markdown") or (
        Path(result["report_path"]).read_text(encoding="utf-8")
        if result.get("report_path") else ""
    )
    if md:
        block = rph.render_provenance_block([], run_id=run_id, repo=_ROOT)
        md = rph.inject_block(md, block)
        if out_path:
            Path(out_path).write_text(md, encoding="utf-8")
            result["report_path"] = out_path
            result["markdown"] = None
        else:
            result["markdown"] = md
    return result
