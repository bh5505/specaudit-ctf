"""Hermetic tests for the governed MCP-surface pipeline.

Covers the two new surface tools wired into extension/mcp_server.py:
``pack_run`` (step 2: evidence -> pack report.json) and ``prioritize_targets``
(step 3: report -> prioritized targets + threat models + attack chains +
human-validation-ready report). The backend is extension/pipeline.py, which
imports the durable tools/demo_* cores.
"""
import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from extension import mcp_server as mcp
from extension.pipeline import pack_run, prioritize_targets, validation_report
from tools import ctf_run_checks

T1 = "ext_telecom_offsec_asmvm_t1_critical_vuln_on_exposed"
T3 = "ext_telecom_offsec_asmvm_t3_asmvm_technique_context_bridge_gap"
PACK_ROOT = Path(__file__).resolve().parents[1] / "packs" / "ext_telecom_offsec"
AWS_T1 = "ext_telecom_offsec_aws_t1_trust_boundary"


def _synthetic_pack_evidence(root: Path, *, complete: bool = True,
                             benign: bool = False) -> Path:
    """Manifest-complete empty sources plus one documentation-only bucket."""
    evidence = root / "evidence"
    evidence.mkdir()
    if complete:
        required = ctf_run_checks.load_manifest(PACK_ROOT)["input_contract"]["required_tables"]
        for table in required:
            (evidence / f"{table}.csv").write_text("run_id\n", encoding="utf-8")
        empty_members = hashlib.sha256(
            b"ext_telecom_offsec.technology_inventory_members.v2.root|0|"
        ).hexdigest()
        (evidence / "ext_telecom_offsec_technology_inventory_receipt.csv").write_text(
            "validator_project_id,validator_engagement_id,inventory_snapshot_id,"
            "inventory_membership_id,source_inventory_total,"
            "expected_eligible_candidates,candidate_identity_sha256\n"
            f"synthetic-project,{ctf_run_checks.ENGAGEMENT_ID},{'a' * 64},"
            f"00000000-0000-0000-0000-000000000001,0,0,{empty_members}\n",
            encoding="utf-8",
        )
    (evidence / "ext_telecom_offsec_aws_s3_bucket.csv").write_text(
        "bucket_name,account_id,region,public_access_block_enabled,"
        "policy_allows_anonymous,run_id,engagement_id\n"
        "synthetic-offsec-bucket,000000000000,us-test-1,"
        f"{'true,false' if benign else 'false,true'},"
        "sibling-run,synthetic-engagement\n",
        encoding="utf-8",
    )
    return evidence


@pytest.mark.parametrize("db,fast_csv", [
    ("sqlite", False), ("duckdb", False), ("duckdb", True),
])
def test_pack_run_rejects_missing_required_sources(tmp_path, db, fast_csv):
    evidence = _synthetic_pack_evidence(tmp_path, complete=False)
    out = tmp_path / "out"
    with pytest.raises(RuntimeError, match="pack evidence incomplete") as exc:
        pack_run(str(PACK_ROOT), str(evidence), out_dir=str(out), db=db,
                 run_id="missing-sources", fast_csv=fast_csv)
    assert "ext_telecom_offsec_asmvm_asset" in str(exc.value)
    assert not (out / "report.json").exists()


def test_mcp_pack_run_missing_sources_is_error(tmp_path):
    evidence = _synthetic_pack_evidence(tmp_path, complete=False)
    result = mcp.McpServer().handle({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "pack_run", "arguments": {
            "pack_root": str(PACK_ROOT), "evidence_dir": str(evidence),
            "db": "sqlite", "run_id": "missing-sources"}},
    })
    assert result["result"]["isError"] is True
    assert "pack evidence incomplete" in result["result"]["content"][0]["text"]


def test_governed_pack_run_refuses_forged_offsec_manifest(tmp_path):
    fake_pack = tmp_path / "forged-pack"
    fake_pack.mkdir()
    (fake_pack / "manifest.yaml").write_text(
        "pack_id: ext_telecom_offsec\n"
        "input_contract:\n  required_tables: [dummy]\n"
        "checks:\n  - id: ext_telecom_offsec_aws_t1_trust_boundary\n"
        "    file: check.sql\n",
        encoding="utf-8",
    )
    (fake_pack / "check.sql").write_text(
        "SELECT 'none', 'none', 0, 0, 'none', 'none', ?1, 0 WHERE 0 LIMIT ?2;\n",
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "dummy.csv").write_text("run_id\n", encoding="utf-8")
    out = tmp_path / "out"

    with pytest.raises(ValueError, match="checked-in ext_telecom_offsec"):
        pack_run(str(fake_pack), str(evidence), out_dir=str(out), db="sqlite")
    with pytest.raises(ctf_run_checks.RunnerError,
                       match="checked-in pack root"):
        ctf_run_checks.run(fake_pack, evidence, out, "sqlite", 100, "fake-run")
    result = mcp.McpServer().handle({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "pack_run", "arguments": {
            "pack_root": str(fake_pack), "evidence_dir": str(evidence),
            "db": "sqlite", "run_id": "fake-run"}},
    })
    assert result["result"]["isError"] is True
    assert "checked-in ext_telecom_offsec" in result["result"]["content"][0]["text"]
    assert not (out / "report.json").exists()


def test_complete_benign_offsec_run_can_report_no_findings(tmp_path):
    evidence = _synthetic_pack_evidence(tmp_path, benign=True)
    result = pack_run(str(PACK_ROOT), str(evidence), db="sqlite",
                      run_id="complete-benign")
    assert result["report"]["findings"] == []
    assert len(result["report"]["checks_status"]) == len(
        ctf_run_checks.load_manifest(PACK_ROOT)["checks"])


def test_source_run_is_stamped_into_ambient_pack_run(tmp_path):
    evidence = _synthetic_pack_evidence(tmp_path)
    result = pack_run(str(PACK_ROOT), str(evidence), db="sqlite",
                      run_id="ambient-offsec-run")
    report = result["report"]
    assert report["run_id"] == "ambient-offsec-run"
    assert [finding["check_id"] for finding in report["findings"]] == [AWS_T1]
    assert "sibling-run" not in json.dumps(report["findings"])


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


def test_validation_report_injects_provenance_header():
    """The renderer takes repo_heads, not repo; every prior call raised
    TypeError. The end-to-end call must render a header and not raise."""
    res = validation_report(report=_converged_findings(), run_id="gate-run-7")
    md = res["markdown"]
    assert "<!-- PROVENANCE-BEGIN -->" in md
    assert "<!-- PROVENANCE-END -->" in md
    assert "run-id pinned: `gate-run-7`" in md
    assert "specaudit-ctf HEAD:" in md


def test_validation_report_binds_real_receipt_paths(tmp_path):
    """When the run context provides a report path, the provenance block cites
    that file with a real digest instead of an empty receipt list."""
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": _converged_findings()}),
                      encoding="utf-8")
    res = validation_report(report_path=str(report), run_id="gate-run-8")
    md = res["markdown"]
    assert str(report) in md
    assert "MISSING" not in md, "a supplied report file is a bound receipt"


def _pairing_evidence(tmp_path):
    d = tmp_path / "pairing_ev"
    d.mkdir()
    (d / "ext_telecom_offsec_asmvm_alert.csv").write_text(
        "vendor_alert_id,alert_id,mitre_tactic,mitre_technique,asr_rule,"
        "ipv4_list,is_active_state,run_id,engagement_id\n"
        "VA-1,al-1,Initial Access,T1190,Rule-A,203.0.113.10,true,r1,e1\n",
        encoding="utf-8")
    (d / "ext_telecom_offsec_asmvm_alert_endpoint.csv").write_text(
        "alert_id,ip,is_active_state,run_id,engagement_id\n"
        "al-1,203.0.113.10,true,r1,e1\n", encoding="utf-8")
    (d / "ext_telecom_offsec_asmvm_service_endpoint.csv").write_text(
        "service_endpoint_id,ip,port,is_active,run_id,engagement_id\n"
        "svc-1,203.0.113.10,443,true,r1,e1\n", encoding="utf-8")
    return d


def test_prioritize_consumes_g3_pairing_when_available(tmp_path):
    pytest.importorskip("duckdb")
    ev = _pairing_evidence(tmp_path)
    res = prioritize_targets(
        report=[_t3("203.0.113.10", 443, "T1190 - X")], evidence_dir=str(ev))
    assert res["pairing"]["available"] is True
    assert res["pairing"]["pair_count"] == 1
    target = res["targets"][0]
    assert target["pairing_evidence"][0]["vendor_alert_id"] == "VA-1"
    assert target["pairing_evidence"][0]["mitre_technique"] == "T1190"
    assert res["summary"]["pairing_available"] is True
    assert res["summary"]["pairing_incomplete_reason"] is None


def test_prioritize_degrades_when_pairing_extract_fails(tmp_path):
    """A malformed base table makes duckdb raise inside extract_pairings. The
    stage must degrade to an explicit incomplete marker, not crash
    prioritize_targets (the MCP surface only translates ValueError/RuntimeError,
    so an escaping duckdb error would abort the whole tool call)."""
    pytest.importorskip("duckdb")
    ev = _pairing_evidence(tmp_path)
    # Drop the is_active column the G3 join references: CREATE TABLE succeeds,
    # the JOIN then fails with a duckdb binder error.
    (ev / "ext_telecom_offsec_asmvm_service_endpoint.csv").write_text(
        "service_endpoint_id,ip,port,run_id,engagement_id\n"
        "svc-1,203.0.113.10,443,r1,e1\n", encoding="utf-8")
    res = prioritize_targets(
        report=[_t3("203.0.113.10", 443, "T1190 - X")], evidence_dir=str(ev))
    assert res["pairing"]["available"] is False
    assert "G3 pairing failed" in res["pairing"]["reason"]
    assert res["summary"]["pairing_available"] is False
    assert res["summary"]["pairing_incomplete_reason"] == res["pairing"]["reason"]
    assert res["targets"], "targets must still be produced when pairing degrades"
    assert all(t["pairing_evidence"] == [] for t in res["targets"])


def test_prioritize_marks_pairing_incomplete_without_evidence(tmp_path):
    """No pairing evidence must be an explicit incomplete marker, not a silent
    fall back to report-text matching."""
    res = prioritize_targets(report=_converged_findings())
    assert res["pairing"]["available"] is False
    assert res["summary"]["pairing_available"] is False
    assert res["summary"]["pairing_incomplete_reason"]
    assert all(t["pairing_evidence"] == [] for t in res["targets"])
    assert res["targets"], "targets are still produced from the pack report"

    empty = tmp_path / "empty_ev"
    empty.mkdir()
    res2 = prioritize_targets(
        report=[_t3("203.0.113.10", 443, "T1190 - X")], evidence_dir=str(empty))
    assert res2["pairing"]["available"] is False
    assert "absent" in res2["pairing"]["reason"]


@pytest.mark.parametrize("db,fast_csv", [
    ("sqlite", False), ("duckdb", False), ("duckdb", True),
])
def test_pack_run_minimal_via_scenario(db, fast_csv):
    """pack_run runs the checked-in offsec pack over synthetic evidence."""
    pack_root = PACK_ROOT
    assert pack_root.is_dir()
    with tempfile.TemporaryDirectory(prefix="ctf-mcp-tst-") as td:
        evidence = _synthetic_pack_evidence(Path(td))
        res = pack_run(str(pack_root), str(evidence), db=db,
                       run_id="mcp-test-hermetic", fast_csv=fast_csv)
    rep = res["report"]
    assert rep["pack_id"] == "ext_telecom_offsec"
    assert rep["engine"] == db
    assert res["report_path"]
    assert isinstance(rep["findings"], list)
    # The fixture's AWS trust-boundary finding is scoped to this execution.
    checks = {f["check_id"] for f in rep["findings"]}
    assert checks == {AWS_T1}
    assert rep["findings"][0]["finding_alias"].startswith(
        "ext_telecom_offsec:" + AWS_T1 + ":bucket:synthetic-offsec-bucket"
    )


@pytest.mark.parametrize("csv_body", [
    "source_run_id\nsource-original\n",
    ("source_run_id,run_id,engagement_id,accept_event_id\n"
     "source-original,sibling-run,sibling-engagement,"
     "11111111-1111-1111-1111-111111111111\n"),
])
def test_native_csv_stamps_lineage_before_constrained_insert(tmp_path, csv_body):
    """Absent or stale CSV lineage cannot fail or control the accepted scope."""
    pytest.importorskip("duckdb")
    (tmp_path / "native_lineage.csv").write_text(csv_body, encoding="utf-8")
    conn, _ = ctf_run_checks.open_engine("duckdb")
    try:
        conn.execute(
            "CREATE TABLE native_lineage ("
            "source_run_id VARCHAR NOT NULL, run_id VARCHAR NOT NULL, "
            "engagement_id VARCHAR NOT NULL, accept_event_id VARCHAR NOT NULL)"
        )
        columns = {"source_run_id", "run_id", "engagement_id", "accept_event_id"}
        loaded = ctf_run_checks.load_evidence_native_csv(
            conn, tmp_path, {}, {"native_lineage": columns}, "execution-current",
            {"native_lineage": {column: "VARCHAR" for column in columns}},
        )
        assert loaded == ["native_lineage"]
        assert conn.execute(
            "SELECT source_run_id, run_id, engagement_id, accept_event_id "
            "FROM native_lineage"
        ).fetchall() == [(
            "source-original", "execution-current", ctf_run_checks.ENGAGEMENT_ID,
            ctf_run_checks.ZERO_ACCEPT_EVENT_ID,
        )]
    finally:
        conn.close()


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


def test_mcp_call_pack_run_envelope():
    pack_root = PACK_ROOT
    assert pack_root.is_dir()
    with tempfile.TemporaryDirectory(prefix="ctf-mcp-tst-") as td:
        evidence = _synthetic_pack_evidence(Path(td))
        srv = mcp.McpServer()
        r = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "pack_run", "arguments": {
                            "pack_root": str(pack_root),
                            "evidence_dir": str(evidence),
                            "db": "sqlite", "run_id": "mcp-test-env"}}})
    assert r["result"]["isError"] is False
    body = json.loads(r["result"]["content"][0]["text"])
    assert body["report"]["pack_id"] == "ext_telecom_offsec"
    assert {f["check_id"] for f in body["report"]["findings"]} == {AWS_T1}
