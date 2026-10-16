"""Instructor-controlled assessment variant for the detect-01 pilot.

The transparent self-study flow is unchanged; these tests snapshot it and
prove the assessment path: the learner packet strips the verdict-gate
declarations (so the public worksheet refuses it), grading consumes only the
canaried instructor key, and every shape, canary and case-binding violation is
refused.
"""

import copy
import json
from pathlib import Path

import pytest

from learning.detection_validation import (KEY_CANARY, KEY_SCHEMA, STAGES,
                                           PacketError, evaluate,
                                           grade, grade_assessment,
                                           load_expected_key, main)

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKETS = REPO_ROOT / "learning" / "data" / "detection"
INSTRUCTOR = REPO_ROOT / "challenges" / "lab-detect-01-technique-chain" / "instructor"
CASES = ("positive", "missing-telemetry", "benign-near-miss", "blocked",
         "alert-untriaged", "retest-failed")


def key_document() -> dict:
    return json.loads((INSTRUCTOR / "expected.json").read_text(encoding="utf-8"))


def packet(name: str) -> dict:
    return json.loads((PACKETS / f"{name}.json").read_text(encoding="utf-8"))


def assessment_packet(name: str) -> dict:
    return json.loads((INSTRUCTOR / "assessment" / f"{name}.json")
                      .read_text(encoding="utf-8"))


def assessment(key: dict, name: str, **overrides) -> dict:
    row = key["cases"][name]
    return {"schema": "synthetic-detection-submission/v1", "case_id": name,
            "stages": dict(row["stages"]), "retest_result": row["retest_result"],
            **overrides}


# ------------------------------------------- transparent flow unchanged ---

def test_transparent_flow_is_unchanged() -> None:
    # Frozen behavior snapshot: the self-study worksheet derives and prints
    # the same verdicts as before the assessment variant existed.
    frozen = {
        "positive": ("met", "met", "met", "met", "met", "effective"),
        "missing-telemetry": ("met", "not_met", "unknown", "unknown", "unknown", "unknown"),
        "benign-near-miss": ("met", "not_met", "unknown", "unknown", "unknown", "unknown"),
        "blocked": ("met", "met", "blocked", "unknown", "unknown", "unknown"),
        "alert-untriaged": ("met", "met", "met", "not_met", "unknown", "unknown"),
        "retest-failed": ("met", "met", "met", "met", "met", "ineffective"),
    }
    for name, states in frozen.items():
        verdict = evaluate(packet(name))
        assert tuple(verdict["stages"][stage]["state"] for stage in STAGES) == states[:5]
        assert verdict["retest_result"] == states[5]
        assert verdict["schema"] == "synthetic-detection-verdict/v1"
    submission_doc = {"schema": "synthetic-detection-submission/v1", "case_id": "retest-failed",
                      "stages": {stage: "met" for stage in STAGES},
                      "retest_result": "effective"}
    result = grade(packet("retest-failed"), submission_doc)
    assert result["differences"] == {
        "retest_result": {"submitted": "effective", "expected": "ineffective"}}


def test_shipped_expected_key_matches_the_derived_ground_truth() -> None:
    key = key_document()
    assert key["schema"] == KEY_SCHEMA
    assert key["canary"] == KEY_CANARY
    assert set(key["cases"]) == set(CASES)
    for name in CASES:
        verdict = evaluate(packet(name))
        assert key["cases"][name]["stages"] == {
            stage: verdict["stages"][stage]["state"] for stage in STAGES}, name
        assert key["cases"][name]["retest_result"] == verdict["retest_result"], name


# ------------------------------------------------- assessment packet ------

def test_assessment_packet_strips_the_verdict_gate_fields() -> None:
    for name in CASES:
        learner = assessment_packet(name)
        original = packet(name)
        assert learner["schema"] == "synthetic-detection-assessment/v1"
        assert learner["case_id"] == name
        assert isinstance(learner["scenario"], str) and learner["scenario"]
        # The three declarations the worksheet consumes as direct encodings
        # of rule_exists / events_collected / rule_fired are stripped; the
        # scenario prose and ALL evidence records are kept intact.
        assert "deployed" not in learner["rule"]
        assert "collection" not in learner["prerequisite"]
        assert "attempt" not in learner["prerequisite"]
        assert learner["rule"]["id"] == original["rule"]["id"]
        assert learner["events"] == original["events"]
        assert learner["alerts"] == original["alerts"]
        assert learner["actions"] == original["actions"]
        assert learner["retests"] == original["retests"]
        # The public worksheet fail-closes on the learner packet: no shipped
        # code path derives the expected verdicts from learner-held material.
        with pytest.raises(PacketError):
            evaluate(learner)
        with pytest.raises(PacketError):
            grade(learner, assessment(key_document(), name))


def test_assessment_grading_uses_the_instructor_key_only() -> None:
    key = key_document()
    assessments = [assessment(key, name) for name in CASES]
    result = grade_assessment(assessments, key, list(CASES))
    assert result["schema"] == "specaudit.detect-assessment-grade.v1"
    assert result["passed"] is True
    assert all(row["differences"] == {} for row in result["cases"])
    # Wrong stage state and wrong retest outcome are named, never leaked.
    wrong = [assessment(key, name) for name in CASES]
    wrong[CASES.index("blocked")]["stages"]["rule_fired"] = "met"
    wrong[CASES.index("retest-failed")]["retest_result"] = "effective"
    result = grade_assessment(wrong, key, list(CASES))
    assert result["passed"] is False
    by_case = {row["case_id"]: row for row in result["cases"]}
    assert by_case["blocked"]["differences"] == {
        "rule_fired": {"submitted": "met", "expected": "blocked"}}
    assert by_case["retest-failed"]["differences"] == {
        "retest_result": {"submitted": "effective", "expected": "ineffective"}}
    # Grading reads no packet: only the key and the submitted rows matter, and
    # documents outside the requested set are refused.
    assert grade_assessment([assessment(key, "alert-untriaged")], key,
                            ["alert-untriaged"])["passed"] is True
    with pytest.raises(PacketError):
        grade_assessment(assessments, key, ["alert-untriaged"])


def test_assessment_key_and_case_bindings_are_enforced() -> None:
    key = key_document()
    assessments = [assessment(key, name) for name in CASES]
    base = key_document()
    load_refusals = [
        lambda k: k.update(schema="specaudit.detect-key.v2"),
        lambda k: k.pop("canary"),                              # missing canary
        lambda k: k.update(canary="INSTRUCTOR-CANARY-WRONG"),
        lambda k: k.update(rubric="human notes"),               # extra field
        lambda k: k["cases"]["positive"]["stages"].pop("rule_fired"),
        lambda k: k["cases"]["positive"]["stages"].update(nope="met"),
        lambda k: k["cases"]["positive"]["stages"].update(rule_fired="denied"),
        lambda k: k["cases"]["positive"].update(retest_result="pass"),
    ]
    for mutate in load_refusals:
        broken = copy.deepcopy(base)
        mutate(broken)
        with pytest.raises(PacketError):
            load_expected_key(broken)
        with pytest.raises(PacketError):
            grade_assessment(assessments, broken, list(CASES))
    # A key binding FEWER cases is valid on load but cannot grade the popped
    # case; a key binding MORE cases is valid and grades the requested set.
    shorter = copy.deepcopy(base)
    shorter["cases"].pop("blocked")
    assert set(load_expected_key(shorter)) == set(CASES) - {"blocked"}
    with pytest.raises(PacketError):
        grade_assessment(assessments, shorter, list(CASES))
    wider = copy.deepcopy(base)
    wider["cases"]["bonus-case"] = copy.deepcopy(base["cases"]["positive"])
    assert grade_assessment(assessments, wider, list(CASES))["passed"] is True
    with pytest.raises(PacketError):
        grade_assessment(assessments, key, ["not-a-case"])          # unbound case
    with pytest.raises(PacketError):
        grade_assessment([assessment(key, "positive")], key, list(CASES))  # missing doc
    with pytest.raises(PacketError):
        grade_assessment([assessment(key, name) for name in CASES] +
                         [assessment(key, "positive")], key, list(CASES))  # duplicate
    with pytest.raises(PacketError):
        grade_assessment([assessment(key, "positive")], key, ["positive", "blocked"])
    stray = [assessment(key, name) for name in CASES] + [assessment(key, "positive")]
    with pytest.raises(PacketError):
        grade_assessment(stray, key, list(CASES))                   # doc outside set
    with pytest.raises(PacketError):
        grade_assessment(assessments, key, [])                      # empty selection
    with pytest.raises(PacketError):
        grade_assessment([assessment(key, "positive", stages={"rule_fired": "x"})],
                         key, ["positive"])                         # bad state value


def test_cli_assessment_flag_and_unchanged_defaults(tmp_path, capsys) -> None:
    key_path = tmp_path / "expected.json"
    key_path.write_text(json.dumps(key_document()), encoding="utf-8")
    assessments = [assessment(key_document(), name) for name in CASES]
    submission_path = tmp_path / "assessments.json"
    submission_path.write_text(json.dumps(assessments), encoding="utf-8")
    assert main(["--assessment-key", str(key_path), "--submission", str(submission_path)]) == 0
    assert '"passed": true' in capsys.readouterr().out
    assessments[0]["stages"]["rule_fired"] = "not_met"
    submission_path.write_text(json.dumps(assessments), encoding="utf-8")
    assert main(["--assessment-key", str(key_path), "--submission", str(submission_path)]) == 1
    capsys.readouterr()
    broken = key_document()
    broken.pop("canary")
    broken_path = tmp_path / "broken-key.json"
    broken_path.write_text(json.dumps(broken), encoding="utf-8")
    assert main(["--assessment-key", str(broken_path), "--submission", str(submission_path)]) == 2
    assert json.loads(capsys.readouterr().err)["status"] == "invalid"
    # The transparent self-study commands behave exactly as before.
    assert main(["--case", "positive"]) == 0
    assert json.loads(capsys.readouterr().out)["stages"]["rule_fired"]["state"] == "met"
    with pytest.raises(SystemExit) as usage:
        main(["--assessment-key", str(key_path), "--case", "positive",
              str(PACKETS / "positive.json")])
    assert usage.value.code == 2
