import copy
import hashlib
import json
from importlib.resources import files
from pathlib import Path

import pytest

from k8s_path_evidence.__main__ import InvalidCapture, main, normalize


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "k8s_path_evidence/fixture"


def case():
    return (FIXTURE / "report.json").read_bytes(), json.loads((FIXTURE / "capture.json").read_text())


def encoded(report, capture):
    raw = json.dumps(report).encode()
    capture["sha256"] = hashlib.sha256(raw).hexdigest()
    return raw, capture


def test_three_branches_are_bounded_candidates_not_access_claims(tmp_path, capsys):
    raw, capture = case()
    result = normalize(raw, capture)
    assert {e["id"]: e["outcome"] for e in result["case_evaluations"]} == {
        "blue-secret-read": "allowed-check-candidate",
        "red-binding-create": "blocked-permission",
        "red-secret-read-unknown": "unknown-prerequisite",
    }
    assert result["case_evaluations"][2]["unknown_prerequisites"] == ["subject-binding-edge-missing", "permission-check-missing"]
    assert result["edges"][-1]["classification"] == "tool-inferred"
    assert result["findings"][0]["classification"] == "tool-reported-hypothesis"
    assert all("effective access" in e["basis"] for e in result["case_evaluations"])
    assert main(["--report", str(FIXTURE / "report.json"), "--capture", str(FIXTURE / "capture.json")]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_hash_and_subject_are_bound():
    raw, capture = case()
    with pytest.raises(InvalidCapture, match="hash mismatch"):
        normalize(raw + b" ", capture)
    capture["subject"] = "system:serviceaccount:red:admin"
    with pytest.raises(InvalidCapture, match="subject differs"):
        normalize(raw, capture)


def test_dangling_or_forged_path_and_duplicate_graph():
    raw, capture = case()
    report = json.loads(raw)
    report["risk_findings"][0]["attack_path"][1]["edge"]["from"] = "sa:red:forged"
    forged, updated = encoded(report, capture)
    with pytest.raises(InvalidCapture, match="unbacked path edge"):
        normalize(forged, updated)
    report = json.loads(raw)
    report["graph"]["edges"].append(copy.deepcopy(report["graph"]["edges"][0]))
    duplicate, updated = encoded(report, capture)
    with pytest.raises(InvalidCapture, match="duplicate"):
        normalize(duplicate, updated)


def test_missing_binding_or_namespace_remains_unknown():
    raw, capture = case()
    capture["test_cases"].extend([
        dict(id="missing-binding", verb="get", resource="secrets", namespace="blue", binding_node="rb:blue:absent"),
        dict(id="missing-namespace", verb="get", resource="secrets", namespace="green", binding_node="rb:blue:read-binding"),
        dict(id="unrelated-binding", verb="get", resource="secrets", namespace="blue", binding_node="rb:red:admin-binding"),
    ])
    evaluations = normalize(raw, capture)["case_evaluations"]
    assert evaluations[-3]["outcome"] == "unknown-prerequisite"
    assert "binding-not-enumerated" in evaluations[-3]["unknown_prerequisites"]
    assert evaluations[-2]["outcome"] == "unknown-prerequisite"
    assert "namespace-not-enumerated" in evaluations[-2]["unknown_prerequisites"]
    assert evaluations[-1]["outcome"] == "unknown-prerequisite"
    assert "subject-binding-edge-missing" in evaluations[-1]["unknown_prerequisites"]
    assert "binding-namespace-mismatch" in evaluations[-1]["unknown_prerequisites"]


def test_fail_closed_schema_duplicate_keys_and_limits():
    raw, capture = case()
    for bad in (b'{"meta":{},"meta":{}}', b'[]', b'not-json', b'A' * (1_048_576 + 1)):
        with pytest.raises(InvalidCapture):
            normalize(bad, capture)
    report = json.loads(raw)
    report["ai_narrative"] = {"summary": "untrusted"}
    changed, updated = encoded(report, capture)
    with pytest.raises(InvalidCapture, match="extra="):
        normalize(changed, updated)
    report = json.loads(raw)
    report["graph"]["nodes"] = report["graph"]["nodes"] * 101
    changed, updated = encoded(report, capture)
    with pytest.raises(InvalidCapture, match="maximum 500"):
        normalize(changed, updated)
    report = json.loads(raw)
    report["graph"]["nodes"][0]["kind"] = []
    changed, updated = encoded(report, capture)
    with pytest.raises(InvalidCapture, match="unknown kind"):
        normalize(changed, updated)
    report = json.loads(raw)
    report["graph"]["nodes"][0]["namespace"] = {}
    changed, updated = encoded(report, capture)
    with pytest.raises(InvalidCapture, match="namespace: text"):
        normalize(changed, updated)
    duplicate_raw = raw.replace(b'"tool": "k8scout",', b'"tool": "k8scout", "tool": "forged",', 1)
    updated["sha256"] = hashlib.sha256(duplicate_raw).hexdigest()
    with pytest.raises(InvalidCapture, match="duplicate JSON key"):
        normalize(duplicate_raw, updated)


def test_packet_excludes_key_and_installed_resources():
    key = ROOT / "challenges/lab-k8s-01-rbac-path/instructor/KEY.md"
    assert "INSTRUCTOR-CANARY-K8S-01" in key.read_text()
    assert not any("INSTRUCTOR-CANARY-K8S-01" in p.read_text() for p in FIXTURE.iterdir() if p.is_file())
    bundled = files("k8s_path_evidence").joinpath("fixture")
    for path in FIXTURE.iterdir():
        if path.is_file():
            assert path.read_bytes() == bundled.joinpath(path.name).read_bytes()
