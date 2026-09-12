"""Hermetic tests for the governed MCP-surface pipeline.

Covers the two new surface tools wired into extension/mcp_server.py:
``pack_run`` (step 2: evidence -> pack report.json) and ``prioritize_targets``
(step 3: report -> prioritized targets + threat models + attack chains +
human-validation-ready report). The backend is extension/pipeline.py, which
imports the durable tools/demo_* cores.
"""
import json
import tempfile
from pathlib import Path

import pytest

from extension import mcp_server as mcp
from extension.pipeline import pack_run, prioritize_targets

T1 = "ext_telecom_asmvm_t1_critical_vuln_on_exposed"
T3 = "ext_telecom_asmvm_t3_asmvm_technique_context_bridge_gap"


def _t3(ip, port, tech):
    return {"check_id": T3, "record_locator": f"{ip}:{port} / service:x",
            "title": f"Technique context is not consumed for service {ip}:{port}",
            "details": f"technique={tech}; tactic=TA0001 - Initial Access",
            "severity": "high", "risk_score": 40}


def _t1(ip):
    return {"check_id": T1, "record_locator": f"vm:asset:{ip} + asm:ip:{ip}",
            "title": f"Open critical finding on internet-active IP: {ip}",
            "severity": "critical", "risk_score": 60}


def _converged_findings():
    return [
        _t3("1.1.1.1", 443, "T1190 - Exploit Public-Facing Application"),
        _t1("1.1.1.1"),
        _t3("2.2.2.2", 500, "T1190 - X, T1110 - Y"),
    ]


def test_prioritize_targets_hermetic():
    findings = _converged_findings()
    res = prioritize_targets(report=findings)
    assert res["summary"]["total_targets"] == 2
    ips = {t["ip"] for t in res["targets"]}
    assert ips == {"1.1.1.1", "2.2.2.2"}
    for t in res["targets"]:
        tm = t["threat_model"]
        assert tm["validation_status"].startswith("awaiting human")
        assert t["attack_chain"]
        # Every attack-chain step is a grounded ATT&CK technique entry.
        for step in t["attack_chain"]:
            assert step["technique"].startswith("T")
            assert "phase" in step
    by_ip = {t["ip"]: t for t in res["targets"]}
    # 1.1.1.1 has a T1190 alert (no T1110) -> T1190 initial access.
    assert by_ip["1.1.1.1"]["threat_model"]["expected_initial_access"]["technique"] == "T1190"
    # 2.2.2.2 carries a T1110 alert too; without a curated anchor the demo
    # core prefers the T1110 brute-force hypothesis for initial access.
    assert by_ip["2.2.2.2"]["threat_model"]["expected_initial_access"]["technique"] == "T1110"
    assert res["summary"]["human_validation_gate"] == (
        "REQUIRED before any agentic exploitability validation"
    )
    assert "markdown" in res
    assert "## Human red-team analyst validation gate" in res["markdown"]
    assert "- [ ] target set reviewed and confirmed" in res["markdown"]


def test_prioritize_convergence_flagging():
    # A host with T1190 alert + curated anchor converges; a plain alert does not
    # require the curated map to be present, but convergence needs both.
    res = prioritize_targets(report=[_t3("3.3.3.3", 80, "T1059 - X")])
    t = next(x for x in res["targets"] if x["ip"] == "3.3.3.3")
    assert t["convergence"] is False
    # T1190 alert still yields an initial-access hypothesis.
    res2 = prioritize_targets(report=[_t3("4.4.4.4", 500, "T1190 - X")])
    t2 = next(x for x in res2["targets"] if x["ip"] == "4.4.4.4")
    assert t2["threat_model"]["expected_initial_access"]["technique"] == "T1190"


def test_prioritize_requires_input():
    with pytest.raises(ValueError):
        prioritize_targets()
    with pytest.raises(ValueError):
        prioritize_targets(report={})  # dict without findings list


def test_pack_run_minimal_via_scenario(monkeypatch):
    """pack_run runs the real ext_telecom_asmvm pack over a scenario evidence
    dir and returns findings. Skips if the pack isn't present on this host."""
    pack_root = Path(r"C:/AuditPack/specaudit/packs/ext_telecom_asmvm")
    if not pack_root.is_dir():
        pytest.skip("ext_telecom_asmvm pack not present")
    sys_path = str(pack_root / "synthetic")
    monkeypatch.syspath_prepend(sys_path)
    import cox_scenario  # noqa: PLC0415 - scenario lives in the pack
    with tempfile.TemporaryDirectory(prefix="ctf-mcp-tst-") as td:
        evidence = cox_scenario.emit(cox_scenario._scenario(cox_scenario.RUN_COX), Path(td))
        res = pack_run(str(pack_root), str(evidence), db="sqlite", run_id="mcp-test-hermetic")
    rep = res["report"]
    assert rep["pack_id"] == "ext_telecom_asmvm"
    assert rep["engine"] == "sqlite"
    assert res["report_path"]
    assert isinstance(rep["findings"], list)
    # The Cox-shaped scenario surfaces control-plane/mgmt/T1190 findings.
    checks = {f["check_id"] for f in rep["findings"]}
    assert "ext_telecom_asmvm_t1_telecom_control_plane_exposed" in checks
    assert "ext_telecom_asmvm_t1_exposed_mgmt_ports" in checks


def test_mcp_tools_list_exposes_pipeline():
    srv = mcp.McpServer()
    listed = srv._dispatch("tools/list", {})
    names = [t["name"] for t in listed["tools"]]
    assert "pack_run" in names
    assert "prioritize_targets" in names


def test_mcp_call_prioritize_envelope():
    srv = mcp.McpServer()
    r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "prioritize_targets",
                               "arguments": {"report": {"findings": _converged_findings()}}}})
    result = r["result"]
    assert result["isError"] is False
    assert "content" in result
    body = json.loads(result["content"][0]["text"])
    assert body["summary"]["total_targets"] == 2
    assert body["targets"][0]["threat_model"]["expected_initial_access"]["technique"] == "T1190"


def test_mcp_call_prioritize_error_envelope():
    srv = mcp.McpServer()
    # No report/report_path is a param-shape error -> JSON-RPC -32602 (not an
    # isError envelope), consistent with _require_id handling.
    r = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "prioritize_targets", "arguments": {}}})
    assert r["error"]["code"] == -32602


def test_mcp_call_pack_run_envelope(monkeypatch):
    pack_root = Path(r"C:/AuditPack/specaudit/packs/ext_telecom_asmvm")
    if not pack_root.is_dir():
        pytest.skip("ext_telecom_asmvm pack not present")
    sys_path = str(pack_root / "synthetic")
    monkeypatch.syspath_prepend(sys_path)
    import cox_scenario  # noqa: PLC0415
    with tempfile.TemporaryDirectory(prefix="ctf-mcp-tst-") as td:
        evidence = cox_scenario.emit(cox_scenario._scenario(cox_scenario.RUN_COX), Path(td))
        srv = mcp.McpServer()
        r = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "pack_run", "arguments": {
                            "pack_root": str(pack_root),
                            "evidence_dir": str(evidence),
                            "db": "sqlite", "run_id": "mcp-test-env"}}})
    assert r["result"]["isError"] is False
    body = json.loads(r["result"]["content"][0]["text"])
    assert body["report"]["pack_id"] == "ext_telecom_asmvm"
    assert len(body["report"]["findings"]) > 0
