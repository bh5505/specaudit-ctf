"""Hermetic tests for tools/demo_target_analysis.py pure cores (v2 asset)."""
import json
from pathlib import Path

from tools.demo_target_analysis import (
    T3,
    build_attack_paths,
    cross_ref,
    emit_markdown,
    parse_report,
    read_cves,
)

T1 = "ext_telecom_asmvm_t1_critical_vuln_on_exposed"


def _t3(ip, port, tech):
    return {"check_id": T3, "record_locator": f"{ip}:{port} / service:x",
            "title": f"Technique context is not consumed for service {ip}:{port}",
            "details": f"technique={tech}; tactic=TA0001 - Initial Access",
            "severity": "high", "risk_score": 40}


def _t1(ip):
    return {"check_id": T1, "record_locator": f"vm:asset:{ip} + asm:ip:{ip}",
            "title": f"Open critical finding on internet-active IP: {ip}",
            "severity": "critical", "risk_score": 60}


def test_parse_report_technique_ports_tier():
    finds = [_t3("1.1.1.1", 80, "T1059 - X, T1190 - Y"), _t1("1.1.1.1")]
    per_ip = parse_report(finds)
    assert "1.1.1.1" in per_ip
    r = per_ip["1.1.1.1"]
    assert "T1190 - Y" in r["techniques"]
    assert 80 in r["ports"]
    assert r["risk_max"] == 60.0
    assert r["t3_rows"] == 1


def test_parse_report_ignores_empty():
    assert parse_report([]) == {}
    # a t3-only host still kept because techniques present
    assert "1.1.1.1" in parse_report([_t3("1.1.1.1", 22, "T1110 - Z")])


def test_cross_ref_convergence():
    per_ip = parse_report([_t3("1.1.1.1", 443, "T1190 - Exploit Public-Facing Application")])
    cves = {"1.1.1.1": [("CVE-2021-44790", "banner_asserted_inference")]}
    curated = {"CVE-2021-44790": {"technique": "T1190", "tactic": "Initial Access",
                                  "kind": "Apache httpd mod_lua RCE", "confidence": "high"}}
    en = cross_ref(per_ip, cves, curated)
    assert en["1.1.1.1"]["convergence"] is True
    assert en["1.1.1.1"]["curated_initial_access"]


def test_cross_ref_no_convergence_when_only_cve():
    per_ip = parse_report([_t3("2.2.2.2", 80, "T1059 - X")])
    cves = {"2.2.2.2": [("CVE-2021-44790", "banner_asserted_inference")]}
    curated = {"CVE-2021-44790": {"technique": "T1190"}}
    en = cross_ref(per_ip, cves, curated)
    assert en["2.2.2.2"]["convergence"] is False
    # curated_initial_access populated but no alert T1190 -> not converged


def test_build_attack_paths_seeds_from_convergence():
    per_ip = parse_report([_t3("1.1.1.1", 80, "T1190 - Y, T1059 - X")])
    cves = {"1.1.1.1": [("CVE-2021-44790", "banner_asserted_inference")]}
    curated = {"CVE-2021-44790": {"technique": "T1190", "kind": "Apache httpd mod_lua RCE"}}
    paths = build_attack_paths(cross_ref(per_ip, cves, curated))
    assert paths and paths[0]["convergence"] is True
    assert any(s["technique"] == "T1190" for s in paths[0]["steps"])
    assert any(s["technique"] == "T1059" for s in paths[0]["steps"])


def test_read_cves(tmp_path):
    co = tmp_path / "ext_telecom_asmvm_cve_observation.csv"
    co.write_text("ip,cve,inferred_score\n9.9.9.9,CVE-2021-44790,8.0\n", encoding="utf-8")
    cves = read_cves(tmp_path)
    assert cves["9.9.9.9"] == [("CVE-2021-44790", "banner_asserted_inference")]


def test_emit_markdown_ascii():
    path = {"ip": "1.1.1.1", "ports": [80], "score": 60.0, "convergence": True,
            "steps": [{"phase": "Initial Access", "technique": "T1190",
                       "evidence": "CVE-2021-44790", "provenance": "curated_expert_map"}]}
    md = emit_markdown([path])
    assert "1.1.1.1" in md and "T1190" in md and "CONVERGED" in md
