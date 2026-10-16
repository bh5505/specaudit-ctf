"""Hermetic tests for tools/demo_target_analysis.py pure cores (v2 asset)."""
from pathlib import Path

from tools.demo_target_analysis import (
    HIGH_SIGNAL_CHECK_IDS,
    build_attack_paths,
    cross_ref,
    emit_markdown,
    high_signal_check_ids,
    parse_report,
    read_cves,
)

CRIT = "demo_pack_t1_exposed"


def _tech(ip, port, tech):
    return {"check_id": "demo_pack_t3_technique_context",
            "record_locator": f"{ip}:{port} / service:x",
            "title": f"Technique context is not consumed for service {ip}:{port}",
            "details": f"technique={tech}; tactic=TA0001 - Initial Access",
            "severity": "high", "risk_score": 40}


def _crit(ip, severity="critical", risk=60):
    return {"check_id": CRIT, "record_locator": f"host:{ip} / asset:{ip}",
            "title": f"Open critical finding on internet-active IP: {ip}",
            "severity": severity, "risk_score": risk}


def test_high_signal_check_ids_default_empty():
    assert HIGH_SIGNAL_CHECK_IDS == frozenset()
    assert high_signal_check_ids() is HIGH_SIGNAL_CHECK_IDS


def test_parse_report_technique_ports_tier():
    finds = [_tech("1.1.1.1", 80, "T1059 - X, T1190 - Y"), _crit("1.1.1.1")]
    per_ip = parse_report(finds)
    assert "1.1.1.1" in per_ip
    r = per_ip["1.1.1.1"]
    assert "T1190 - Y" in r["techniques"]
    assert 80 in r["ports"]
    assert r["risk_max"] == 60.0
    assert r["t3_rows"] == 1
    assert r["tiers"] == ["baseline", "critical_flagship"]


def test_tier_by_severity_and_risk_from_all_findings():
    # a critical row and a lower-severity technique row for the same IP
    per_ip = parse_report([_crit("5.5.5.5", risk=20),
                           _tech("5.5.5.5", 443, "T1190 - X")])
    r = per_ip["5.5.5.5"]
    assert r["tiers"] == ["baseline", "critical_flagship"]
    # risk_max considers every finding, whatever its severity
    assert r["risk_max"] == 40.0
    # severity below critical never earns critical_flagship
    per_ip2 = parse_report([_crit("6.6.6.6", severity="medium", risk=25)])
    assert per_ip2["6.6.6.6"]["tiers"] == ["baseline"]
    assert per_ip2["6.6.6.6"]["risk_max"] == 25.0


def test_parse_report_ignores_empty():
    assert parse_report([]) == {}
    # a technique-row-only host still kept because techniques present
    assert "1.1.1.1" in parse_report([_tech("1.1.1.1", 22, "T1110 - Z")])


def test_cross_ref_convergence():
    per_ip = parse_report([_tech("1.1.1.1", 443, "T1190 - Exploit Public-Facing Application")])
    cves = {"1.1.1.1": [("CVE-2021-44790", "banner_asserted_inference")]}
    curated = {"CVE-2021-44790": {"technique": "T1190", "tactic": "Initial Access",
                                  "kind": "Apache httpd mod_lua RCE", "confidence": "high"}}
    en = cross_ref(per_ip, cves, curated)
    assert en["1.1.1.1"]["convergence"] is True
    assert en["1.1.1.1"]["curated_initial_access"]


def test_cross_ref_no_convergence_when_only_cve():
    per_ip = parse_report([_tech("2.2.2.2", 80, "T1059 - X")])
    cves = {"2.2.2.2": [("CVE-2021-44790", "banner_asserted_inference")]}
    curated = {"CVE-2021-44790": {"technique": "T1190"}}
    en = cross_ref(per_ip, cves, curated)
    assert en["2.2.2.2"]["convergence"] is False
    # curated_initial_access populated but no alert T1190 -> not converged


def test_build_attack_paths_seeds_from_convergence():
    per_ip = parse_report([_tech("1.1.1.1", 80, "T1190 - Y, T1059 - X")])
    cves = {"1.1.1.1": [("CVE-2021-44790", "banner_asserted_inference")]}
    curated = {"CVE-2021-44790": {"technique": "T1190", "kind": "Apache httpd mod_lua RCE"}}
    paths = build_attack_paths(cross_ref(per_ip, cves, curated))
    assert paths and paths[0]["convergence"] is True
    assert any(s["technique"] == "T1190" for s in paths[0]["steps"])
    assert any(s["technique"] == "T1059" for s in paths[0]["steps"])


def test_read_cves(tmp_path):
    co = tmp_path / "cve_observation.csv"
    co.write_text("ip,cve,inferred_score\n9.9.9.9,CVE-2021-44790,8.0\n", encoding="utf-8")
    cves = read_cves(tmp_path)
    assert cves["9.9.9.9"] == [("CVE-2021-44790", "banner_asserted_inference")]


def test_emit_markdown_ascii():
    path = {"ip": "1.1.1.1", "ports": [80], "score": 60.0, "convergence": True,
            "steps": [{"phase": "Initial Access", "technique": "T1190",
                       "evidence": "CVE-2021-44790", "provenance": "curated_expert_map"}]}
    md = emit_markdown([path])
    assert "1.1.1.1" in md and "T1190" in md and "CONVERGED" in md
