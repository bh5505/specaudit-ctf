"""Hermetic operator-pipeline tests and attached MCP boundary regressions."""
import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from extension import mcp_server as mcp
from extension.pipeline import pack_run, prioritize_targets, validation_report
from extension.operator_analysis import finding_id
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
    stage must degrade to an explicit incomplete marker, without aborting
    the operator's prioritization run."""
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


def _graph_item(finding, *, block_candidate=False):
    graph = (PACK_ROOT.parents[1] / "graph_evidence/fixtures/synthetic-aws.rage.ndjson").read_text()
    bucket = finding["record_locator"].split(" / ")[0]
    graph = graph.replace("practice-data", bucket)
    if block_candidate:
        graph = graph.replace('"edge_id":"edge-2"', '"edge_id":"edge-2"').replace(
            '"state":"ACTIVE","target":"aws|000000000000|aws:s3:bucket|' + bucket,
            '"state":"BLOCKED","target":"aws|000000000000|aws:s3:bucket|' + bucket, 1)
    return {"finding": {"check_id": finding["check_id"], "record_locator": finding["record_locator"]},
            "kind": "graph", "input": {"graph_ndjson": graph, "sha256": hashlib.sha256(graph.encode()).hexdigest(),
                                       "source": "aws|000000000000|aws:iam:role|trainee",
                                       "target": f"aws|000000000000|aws:s3:bucket|{bucket}"}}


def test_actual_pack_report_cloud_target_and_graph_change_validation_work(tmp_path):
    evidence = _synthetic_pack_evidence(tmp_path)
    packed = pack_run(str(PACK_ROOT), str(evidence), db="sqlite", run_id="operator-integration")
    finding = next(f for f in packed["report"]["findings"] if f["check_id"] == AWS_T1)
    assert finding["record_locator"].startswith("synthetic-offsec-bucket / 000000000000")
    result = prioritize_targets(report=packed["report"], operator_evidence={
        "schema": "specaudit.operator-evidence.v1", "items": [_graph_item(finding)]})
    target = next(t for t in result["targets"] if t.get("finding", {}).get("check_id") == AWS_T1)
    assert target["ip"] is None
    assert target["operational_reviews"]["graph"][0]["review"]["path_verdicts"] == ["blocked", "configured_candidate", "unknown"]
    assert target["validation_tasks"][-1]["action"] == "verify-effective-permission"
    assert finding["record_locator"] in result["markdown"]

    blocked = prioritize_targets(report=packed["report"], operator_evidence={
        "schema": "specaudit.operator-evidence.v1", "items": [_graph_item(finding, block_candidate=True)]})
    blocked_target = next(t for t in blocked["targets"] if t.get("finding", {}).get("check_id") == AWS_T1)
    assert "configured_candidate" not in blocked_target["operational_reviews"]["graph"][0]["review"]["path_verdicts"]
    assert blocked_target["validation_tasks"][-1]["action"] == "resolve-path-prerequisite"
    assert blocked_target["score"] == target["score"]  # supplementary data does not change pack truth

    (tmp_path / "benign").mkdir()
    benign = pack_run(str(PACK_ROOT), str(_synthetic_pack_evidence(tmp_path / "benign", benign=True)),
                      db="sqlite", run_id="operator-benign")
    assert benign["report"]["findings"] == []
    with pytest.raises(ValueError, match="orphan"):
        prioritize_targets(report=benign["report"], operator_evidence={
            "schema": "specaudit.operator-evidence.v1", "items": [_graph_item(finding)]})


def test_detection_chain_binds_actual_attck_and_reports_gaps():
    finding = _t3("203.0.113.10", 443, "T1190 - Exploit Public-Facing Application")
    packet = {"schema": "specaudit.operational-detection.v1", "target": finding["record_locator"],
              "technique_id": "T1190", "prerequisite": {"datasource": "web-logs", "collection": "off", "attempt": "allowed"},
              "rule": {"id": "rule-web", "deployed": True, "event_kind": "request", "outcome": "allowed"},
              "events": [], "alerts": [], "actions": [], "retests": []}
    item = {"finding": {"check_id": finding["check_id"], "record_locator": finding["record_locator"]},
            "kind": "detection", "input": {"packet": packet}}
    evidence = {"schema": "specaudit.operator-evidence.v1", "items": [item]}
    result = prioritize_targets(report=[finding], operator_evidence=evidence)
    target = result["targets"][0]
    assert target["operational_reviews"]["detection"][0]["review"]["stages"]["events_collected"]["state"] == "not_met"
    assert target["validation_tasks"][-1]["action"] == "resolve-detection-gaps"
    item["input"]["packet"]["technique_id"] = "T1078"
    with pytest.raises(ValueError, match="absent from pack attack chain"):
        prioritize_targets(report=[finding], operator_evidence=evidence)


def test_two_same_kind_reviews_on_one_ip_remain_distinct():
    first = _t3("203.0.113.10", 443, "T1190 - Exploit Public-Facing Application")
    second = _t3("203.0.113.10", 8443, "T1190 - Exploit Public-Facing Application")
    def item(finding):
        return {"finding": {"check_id": finding["check_id"], "record_locator": finding["record_locator"]},
                "kind": "detection", "input": {"packet": {
                    "schema": "specaudit.operational-detection.v1", "target": finding["record_locator"],
                    "technique_id": "T1190", "prerequisite": {"datasource": "web-logs", "collection": "off", "attempt": "allowed"},
                    "rule": {"id": "rule-web", "deployed": False, "event_kind": "request", "outcome": "allowed"},
                    "events": [], "alerts": [], "actions": [], "retests": []}}}
    result = prioritize_targets(report=[first, second], operator_evidence={
        "schema": "specaudit.operator-evidence.v1", "items": [item(first), item(second)]})
    target = result["targets"][0]
    assert len(target["operational_reviews"]["detection"]) == 2
    assert len(target["validation_tasks"]) == 3
    assert {row["finding"]["record_locator"] for row in target["validation_tasks"][1:]} == {
        first["record_locator"], second["record_locator"]}
    assert target["validation_tasks"][0]["invocation"] == {
        "arm_id": "nmap", "action": "scan",
        "args": {"target": "203.0.113.10", "mode": "version-light", "ports": [443, 8443]}}


def test_captured_triage_order_is_bound_to_actual_targets():
    from extension.operator_analysis import finding_id
    from extension.triage.siftrank import UPSTREAM_REVISION

    findings = [_t3("203.0.113.11", 443, "T1190 - X"),
                _t3("203.0.113.12", 443, "T1110 - Y")]
    target_ids = ["ip:203.0.113.11", "ip:203.0.113.12"]
    source = "pack-report-sha256:" + hashlib.sha256(json.dumps(findings, sort_keys=True,
                                          separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    candidates = [{"id": identity, "text": "Review bound " + finding_id(f),
                   "source": source} for identity, f in zip(target_ids, findings)]
    ranking = [{"rank": rank, "input_index": idx, "document": candidates[idx],
                "value": "review", "score": 0.5, "exposure": 1, "rounds": 1}
               for rank, idx in enumerate((1, 0), 1)]
    raw_candidates = json.dumps(candidates)
    raw_ranking = json.dumps(ranking)
    binding = {"upstream_revision": UPSTREAM_REVISION,
               "input_sha256": hashlib.sha256(raw_candidates.encode()).hexdigest(),
               "ranking_sha256": hashlib.sha256(raw_ranking.encode()).hexdigest(),
               "prompt_sha256": "a" * 64, "run_id": "synthetic-captured-order",
               "captured_at": "2026-10-04T00:00:00Z", "provider": "synthetic",
               "model": "synthetic", "custody_ref": "synthetic-only"}
    triage = {"candidates_json": raw_candidates, "ranking_json": raw_ranking, "binding": binding}
    packet = {"schema": "specaudit.operator-evidence.v1", "items": [], "triage": triage}
    result = prioritize_targets(report=findings, operator_evidence=packet)
    by_id = {t["target_id"]: t for t in result["targets"]}
    assert by_id[target_ids[1]]["review_order"] == 1
    assert by_id[target_ids[0]]["review_order"] == 2
    assert result["targets"][0]["target_id"] == target_ids[1]
    assert by_id[target_ids[0]]["rank"] is not None  # risk ranking stays separate
    ranking.pop()
    triage["ranking_json"] = json.dumps(ranking)
    triage["binding"]["ranking_sha256"] = hashlib.sha256(triage["ranking_json"].encode()).hexdigest()
    with pytest.raises(ValueError, match="ranking must cover"):
        prioritize_targets(report=findings, operator_evidence=packet)


def test_cloud_locator_never_becomes_ip_target_from_prose():
    finding = {"check_id": AWS_T1, "record_locator": "bucket-a / 000000000000 / us-test-1",
               "title": "Cloud note mentions 203.0.113.10", "risk_score": 70}
    result = prioritize_targets(report=[_t3("203.0.113.10", 443, "T1190 - X"), finding])
    assert {t["target_id"] for t in result["targets"]} == {
        "ip:203.0.113.10", finding_id(finding)}
    assert finding["record_locator"] in result["markdown"]
    assert result["targets"][0]["target_id"] == finding_id(finding)
    assert result["targets"][0]["review_priority"] == 1


def test_operational_detection_rejects_contradictory_attempt_and_event():
    from learning.detection_validation import PacketError, evaluate_operational

    target = "203.0.113.7:443 / service:test"
    packet = {"schema": "specaudit.operational-detection.v1", "target": target,
              "technique_id": "T1190", "prerequisite": {"datasource": "web-logs", "collection": "on", "attempt": "allowed"},
              "rule": {"id": "rule", "deployed": True, "event_kind": "request", "outcome": "blocked"},
              "events": [{"id": "e", "datasource": "web-logs", "kind": "request", "outcome": "blocked", "subject": target}],
              "alerts": [{"id": "a", "rule_id": "rule", "event_id": "e"}],
              "actions": [{"id": "d", "alert_id": "a", "decision": "triaged"}],
              "retests": [{"id": "r", "action_id": "d", "result": "effective"}]}
    with pytest.raises(PacketError, match="contradicts"):
        evaluate_operational(packet)


def test_k8s_review_correlates_exact_service_account_subject():
    fixture = PACK_ROOT.parents[1] / "k8s_path_evidence/fixture"
    capture = json.loads((fixture / "capture.json").read_text())
    raw = (fixture / "report.json").read_text()
    finding = {"check_id": "ext_telecom_offsec_technology_t2_validation_gap",
               "record_locator": capture["subject"] + " / cluster:synthetic", "risk_score": 45}
    item = {"finding": {"check_id": finding["check_id"], "record_locator": finding["record_locator"]},
            "kind": "k8s", "input": {"report_json": raw, "capture": capture}}
    packet = {"schema": "specaudit.operator-evidence.v1", "items": [item]}
    result = prioritize_targets(report=[finding], operator_evidence=packet)
    target = result["targets"][0]
    review = target["operational_reviews"]["k8s"][0]["review"]
    assert review["subject"] == capture["subject"]
    assert {case["outcome"] for case in review["cases"]} >= {"unknown-prerequisite"}
    assert target["validation_tasks"][-1]["action"] == "verify-ssar-and-path-prerequisites"
    item["finding"]["record_locator"] = "another-subject / cluster:synthetic"
    with pytest.raises(ValueError, match="orphan"):
        prioritize_targets(report=[finding], operator_evidence=packet)


def test_workpaper_review_checks_real_manifest_and_exact_finding_subject():
    raw = '{"observation":"synthetic capture"}'
    digest = hashlib.sha256(raw.encode()).hexdigest()
    finding = {"check_id": AWS_T1, "record_locator": "bucket-a / 000000000000 / us-test-1",
               "risk_score": 55}
    manifest = {"schema": "specaudit.review-evidence.v1", "evidence": [{
        "id": "ev-1", "file": "evidence.json", "sha256": digest, "producer": "synthetic pack",
        "version": "v1", "captured_at": "2026-10-04T00:00:00Z", "subject": finding["record_locator"],
        "scope": "synthetic lab", "custody": "operator declared", "data_class": "synthetic",
        "transformations": "none", "limitations": "declared capture", "kind": "observed"}]}
    submission = {"schema": "specaudit.review-workpaper.v1", "subject": finding["record_locator"],
                  "version": "v1", "period": "fixture interval", "boundary": "lab", "criterion": "least privilege",
                  "reviewer": "operator", "assets": ["bucket-a"], "trust_boundaries": ["bucket policy"],
                  "attacker_goals": ["read data"], "untested": ["effective access"],
                  "limitations": ["not authenticated"], "recommendation": ["review policy"],
                  "retest": ["verify denied read"], "overall": "inconclusive",
                  "claims": [{"id": "c1", "status": "supported", "hypothesis": "bucket policy issue",
                              "boundary": "bucket policy", "observation": "declared capture", "inference": "review needed",
                              "alternative": "org deny", "validation": "check effective access", "residual_risk": "unknown",
                              "evidence_ids": ["ev-1"]}],
                  "coverage": [{"surface": "bucket policy", "disposition": "inconclusive", "claim_ids": ["c1"]}]}
    item = {"finding": {"check_id": finding["check_id"], "record_locator": finding["record_locator"]},
            "kind": "workpaper", "input": {"manifest": manifest, "submission": submission,
                                           "evidence": {"evidence.json": raw}}}
    packet = {"schema": "specaudit.operator-evidence.v1", "items": [item]}
    target = prioritize_targets(report=[finding], operator_evidence=packet)["targets"][0]
    assert target["operational_reviews"]["workpaper"][0]["review"]["structure_valid"] is True
    assert target["validation_tasks"][-1]["action"] == "review-claim-and-custody"
    submission["subject"] = "another-bucket"
    with pytest.raises(ValueError, match="subject differs"):
        prioritize_targets(report=[finding], operator_evidence=packet)


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


def test_mcp_tools_list_excludes_operator_pipeline():
    srv = mcp.McpServer()
    listed = srv._dispatch("tools/list", {})
    names = [t["name"] for t in listed["tools"]]
    assert names == ["list", "describe", "invoke", "run_range"]


@pytest.mark.parametrize("name,arguments", [
    ("pack_run", {"pack_root": str(PACK_ROOT), "evidence_dir": "/untrusted", "out_dir": "/untrusted"}),
    ("prioritize_targets", {"report_path": "/untrusted", "out_path": "/untrusted"}),
])
def test_attached_mcp_cannot_reach_operator_pipeline(name, arguments):
    # Reject the call before loading the pipeline or touching caller paths.
    response = mcp.McpServer().handle({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    assert response["error"]["code"] == -32602
    assert response["error"]["message"] == f"unknown tool: {name}"
