"""Deterministic E1 exercise boundary and evidence tests.

Correctness grading is instructor-held: these tests load the shipped key from
the challenge's instructor directory, an operator-side artifact path.
"""

import json
import uuid
from pathlib import Path

import pytest

from learning import agent_security_harness as h

KEY_PATH = (Path(__file__).resolve().parents[1] / "challenges"
            / "lab-agent-01-tool-boundary" / "instructor" / "answers.json")


def key_document():
    return json.loads(KEY_PATH.read_text(encoding="utf-8"))


def fixture_trace():
    return h.trace(str(uuid.UUID("12345678-1234-4234-8234-123456789abc")))


def submission(evidence):
    key = key_document()
    return {"schema": h.SUBMISSION_SCHEMA, "attempt_id": evidence["attempt_id"],
            "trace_sha256": evidence["trace_sha256"],
            "assessments": [{"event_id": event["event_id"],
                             **key["events"][event["event_id"]]}
                            for event in evidence["events"]]}


def test_admission_monitor_and_report_distinctions():
    evidence = fixture_trace()
    assert h.canonical(evidence) == h.canonical(fixture_trace())
    assert [(e["admission"], e["outcome"], e["monitor"]) for e in evidence["events"]] == [
        ("admitted", "executed", "tool-result"),
        ("denied", "denied", "policy-denial"),
        ("admitted", "unknown", "sensor-unavailable"),
        ("denied", "denied", "policy-denial"),
    ]
    key = key_document()
    assert [key["events"][e["event_id"]]["classification"] for e in evidence["events"]] == [
        "clean", "rejected", "unknown", "rejected"]
    assert h.grade(h.verify_trace(evidence), submission(evidence), key)["passed"]


def test_unsupported_all_clear_and_prose_success_fail():
    evidence = fixture_trace()
    found = submission(evidence)
    found["assessments"][1]["observed_effect"] = "executed"
    found["assessments"][2]["classification"] = "clean"
    result = h.grade(evidence, found, key_document())
    assert result["correct"] == 2 and not result["passed"]
    assert [x["event_id"] for x in result["errors"]] == ["a02", "a03"]


@pytest.mark.parametrize("alter", [
    lambda t: t["events"][1].update(outcome="executed"),
    lambda t: t["events"][3].update(target="fixture://catalog/public"),
    lambda t: t.update(trace_sha256="0" * 64),
    lambda t: t["events"].append(t["events"][0]),
])
def test_trace_tamper_refused(alter):
    evidence = fixture_trace()
    original_submission = submission(evidence)
    alter(evidence)
    with pytest.raises(h.HarnessError):
        h.verify_trace(evidence)
    with pytest.raises(h.HarnessError):
        h.grade(evidence, original_submission, key_document())


def test_duplicate_forged_evidence_and_wrong_attempt_refused():
    evidence = fixture_trace()
    for mutation in (
        lambda s: s["assessments"][1].update(evidence_event_id="a01"),
        lambda s: s["assessments"][2].update(evidence_event_id="fixture://grader/answer-key"),
    ):
        found = submission(evidence)
        mutation(found)
        assert not h.grade(evidence, found, key_document())["passed"]
    found = submission(evidence)
    found["assessments"][1]["event_id"] = "a01"
    with pytest.raises(h.HarnessError):
        h.grade(evidence, found, key_document())
    found = submission(evidence)
    found["attempt_id"] = str(uuid.uuid4())
    with pytest.raises(h.HarnessError):
        h.grade(evidence, found, key_document())


def test_cli_validated_workflow(tmp_path, capsys):
    trace_path = tmp_path / "trace.json"
    key_path = tmp_path / "key.json"
    submission_path = tmp_path / "assessment.json"
    key_path.write_text(KEY_PATH.read_text(encoding="utf-8"))
    assert h.main(["run", "--out", str(trace_path)]) == 0
    assert h.main(["run", "--out", str(trace_path)]) == 2
    evidence = h.verify_trace(json.loads(trace_path.read_text()))
    submission_path.write_text(json.dumps(submission(evidence)))
    assert h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path),
                   "--key", str(key_path)]) == 0
    found = submission(evidence)
    found["assessments"][0]["classification"] = "rejected"
    submission_path.write_text(json.dumps(found))
    assert h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path),
                   "--key", str(key_path)]) == 1
    assert '"passed":false' in capsys.readouterr().out
