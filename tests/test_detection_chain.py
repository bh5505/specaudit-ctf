import copy
import json
from pathlib import Path

import pytest

from learning.detection_validation import PacketError, STAGES, evaluate, grade, main


PACKETS = Path(__file__).resolve().parents[1] / "learning/data/detection"


def packet(name):
    return json.loads((PACKETS / f"{name}.json").read_text())


@pytest.mark.parametrize("name,states", [
    ("positive", ("met", "met", "met", "met", "met")),
    ("missing-telemetry", ("met", "not_met", "unknown", "unknown", "unknown")),
    ("benign-near-miss", ("met", "not_met", "unknown", "unknown", "unknown")),
    ("blocked", ("met", "met", "blocked", "unknown", "unknown")),
    ("alert-untriaged", ("met", "met", "met", "not_met", "unknown")),
    ("retest-failed", ("met", "met", "met", "met", "met")),
])
def test_stage_ladder(name, states):
    verdict = evaluate(packet(name))
    assert tuple(verdict["stages"][s]["state"] for s in STAGES) == states
    if name == "retest-failed":
        assert verdict["retest_result"] == "ineffective"


def test_alert_and_action_must_link_to_matching_event():
    p = packet("positive")
    p["events"].append({"id": "evt-benign", "datasource": "identity-audit", "kind": "admin-maintenance", "outcome": "allowed", "subject": "operator"})
    p["alerts"][0]["event_id"] = "evt-benign"
    assert evaluate(p)["stages"]["rule_fired"]["state"] == "not_met"


@pytest.mark.parametrize("change", [
    lambda p: p["technique"].update(source_sha256="0" * 64),
    lambda p: p["events"][0].update(extra="untrusted"),
    lambda p: p["alerts"][0].update(event_id="absent"),
    lambda p: p["events"].append(copy.deepcopy(p["events"][0])),
    lambda p: p["prerequisite"].update(collection="maybe"),
])
def test_malformed_and_unpinned_refused(change):
    p = packet("positive")
    change(p)
    with pytest.raises(PacketError):
        evaluate(p)


def test_grade_requires_exact_five_stages():
    p = packet("missing-telemetry")
    correct = {s: evaluate(p)["stages"][s]["state"] for s in STAGES}
    submission = {"schema": "synthetic-detection-submission/v1", "case_id": p["case_id"], "stages": correct, "retest_result": "unknown"}
    assert grade(p, submission)["pass"]
    submission["stages"]["rule_fired"] = "met"
    assert grade(p, submission)["differences"]["rule_fired"]["expected"] == "unknown"
    del submission["stages"]["rule_fired"]
    with pytest.raises(PacketError):
        grade(p, submission)


def test_ineffective_retest_cannot_pass_as_effective():
    p = packet("retest-failed")
    submission = {"schema": "synthetic-detection-submission/v1", "case_id": p["case_id"],
                  "stages": {s: "met" for s in STAGES}, "retest_result": "effective"}
    result = grade(p, submission)
    assert not result["pass"]
    assert result["differences"]["retest_result"]["expected"] == "ineffective"


def test_cli_json_exit_codes(tmp_path, capsys):
    path = PACKETS / "positive.json"
    assert main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["stages"]["rule_fired"]["state"] == "met"
    submission = tmp_path / "submission.json"
    submission.write_text(json.dumps({"schema": "synthetic-detection-submission/v1", "case_id": "positive", "stages": {s: "unknown" for s in STAGES}, "retest_result": "unknown"}))
    assert main([str(path), "--submission", str(submission)]) == 1
    assert json.loads(capsys.readouterr().out)["pass"] is False
    assert main([str(path), "--submission", str(tmp_path / "missing")]) == 2
    assert json.loads(capsys.readouterr().err)["status"] == "invalid"
