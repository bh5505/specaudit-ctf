"""Deterministic E1 exercise boundary and evidence tests."""

import json
import uuid

import pytest

from learning import agent_security_harness as h


def fixture_trace():
    return h.trace(str(uuid.UUID("12345678-1234-4234-8234-123456789abc")))


def submission(evidence):
    return {"schema": h.SUBMISSION_SCHEMA, "attempt_id": evidence["attempt_id"],
            "trace_sha256": evidence["trace_sha256"],
            "assessments": [h.answer(event) for event in evidence["events"]]}


def test_admission_monitor_and_report_distinctions():
    evidence = fixture_trace()
    assert h.canonical(evidence) == h.canonical(fixture_trace())
    assert [(e["admission"], e["outcome"], e["monitor"]) for e in evidence["events"]] == [
        ("admitted", "executed", "tool-result"),
        ("denied", "denied", "policy-denial"),
        ("admitted", "unknown", "sensor-unavailable"),
        ("denied", "denied", "policy-denial"),
    ]
    assert [h.answer(e)["classification"] for e in evidence["events"]] == ["clean", "rejected", "unknown", "rejected"]
    assert h.grade(h.verify_trace(evidence), submission(evidence))["passed"]


def test_unsupported_all_clear_and_prose_success_fail():
    evidence = fixture_trace()
    found = submission(evidence)
    found["assessments"][1]["observed_effect"] = "executed"
    found["assessments"][2]["classification"] = "clean"
    result = h.grade(evidence, found)
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
        h.grade(evidence, original_submission)


def test_duplicate_forged_evidence_and_wrong_attempt_refused():
    evidence = fixture_trace()
    for mutation in (
        lambda s: s["assessments"][1].update(evidence_event_id="a01"),
        lambda s: s["assessments"][2].update(evidence_event_id="fixture://grader/answer-key"),
    ):
        found = submission(evidence)
        mutation(found)
        assert not h.grade(evidence, found)["passed"]
    found = submission(evidence)
    found["assessments"][1]["event_id"] = "a01"
    with pytest.raises(h.HarnessError):
        h.grade(evidence, found)
    found = submission(evidence)
    found["attempt_id"] = str(uuid.uuid4())
    with pytest.raises(h.HarnessError):
        h.grade(evidence, found)


def test_cli_validated_workflow(tmp_path, capsys):
    trace_path = tmp_path / "trace.json"
    submission_path = tmp_path / "assessment.json"
    assert h.main(["run", "--out", str(trace_path)]) == 0
    assert h.main(["run", "--out", str(trace_path)]) == 2
    evidence = h.verify_trace(json.loads(trace_path.read_text()))
    submission_path.write_text(json.dumps(submission(evidence)))
    assert h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path)]) == 0
    found = submission(evidence)
    found["assessments"][0]["classification"] = "rejected"
    submission_path.write_text(json.dumps(found))
    assert h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path)]) == 1
    assert '"passed":false' in capsys.readouterr().out
