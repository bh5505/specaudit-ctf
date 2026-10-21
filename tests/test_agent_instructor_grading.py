"""Instructor-held grading for the agent tool-boundary pilot.

The grading module derives no answers: correctness anchors exist only in the
canaried, scene-bound key document under the challenge's instructor directory.
These tests prove the key contract (closed shape, canary, scene binding), that
grading refuses to run without it, that the transparent self-check carries no
correctness signal, and that the shipped key grades correct and altered submissions.
"""

import copy
import inspect
import json
import uuid
from pathlib import Path

import pytest

from learning import agent_security_harness as h

REPO_ROOT = Path(__file__).resolve().parents[1]
KEY_PATH = (REPO_ROOT / "challenges" / "lab-agent-01-tool-boundary" /
            "instructor" / "answers.json")


def key_document() -> dict:
    return json.loads(KEY_PATH.read_text(encoding="utf-8"))


def fixture_trace() -> dict:
    return h.trace(str(uuid.UUID("12345678-1234-4234-8234-123456789abc")))


def submission(evidence: dict, key: dict) -> dict:
    return {"schema": h.SUBMISSION_SCHEMA, "attempt_id": evidence["attempt_id"],
            "trace_sha256": evidence["trace_sha256"],
            "assessments": [{"event_id": event["event_id"],
                             **key["events"][event["event_id"]]}
                            for event in evidence["events"]]}


def test_shipped_key_matches_the_current_exact_anchors() -> None:
    key = key_document()
    assert key["schema"] == h.KEY_SCHEMA
    assert key["canary"] == h.KEY_CANARY
    assert key["scene_sha256"] == h.scene_digest()
    assert set(key["events"]) == {"a01", "a02", "a03", "a04"}
    # Identical semantics to instructor/KEY.md and to the removed answer()
    # derivation: clean/executed/yes, rejected/denied/no, unknown/unknown/
    # unverifiable, rejected/denied/no, with same-event evidence locators.
    assert [key["events"][event_id]["classification"]
            for event_id in ("a01", "a02", "a03", "a04")] == [
        "clean", "rejected", "unknown", "rejected"]
    assert [key["events"][event_id]["observed_effect"]
            for event_id in ("a01", "a02", "a03", "a04")] == [
        "executed", "denied", "unknown", "denied"]
    assert [key["events"][event_id]["report_match"]
            for event_id in ("a01", "a02", "a03", "a04")] == [
        "yes", "no", "unverifiable", "no"]
    assert all(row["evidence_event_id"] == event_id
               for event_id, row in key["events"].items())


def test_grade_with_the_shipped_key_grades_correct_and_altered_submissions() -> None:
    key = key_document()
    evidence = fixture_trace()
    correct = submission(evidence, key)
    assert h.grade(evidence, correct, key)["passed"] is True
    altered = copy.deepcopy(correct)
    altered["assessments"][1]["observed_effect"] = "executed"
    altered["assessments"][2]["classification"] = "clean"
    result = h.grade(evidence, altered, key)
    assert result["passed"] is False
    assert result["correct"] == 2
    assert result["errors"] == [
        {"event_id": "a02", "incorrect_fields": ["observed_effect"]},
        {"event_id": "a03", "incorrect_fields": ["classification"]},
    ]


def test_grade_requires_the_instructor_key() -> None:
    evidence = fixture_trace()
    right = submission(evidence, key_document())
    # No key document, no grading: the two-argument form is removed.
    with pytest.raises(TypeError):
        h.grade(evidence, right)
    for key in (None, {}, [], "answers.json"):
        with pytest.raises(h.HarnessError):
            h.grade(evidence, right, key)


def test_key_shape_canary_and_scene_binding_are_enforced() -> None:
    evidence = fixture_trace()
    right = submission(evidence, key_document())
    base = key_document()
    mutations = [
        lambda k: k.update(schema="specaudit.agent-tool-key.v2"),
        lambda k: k.pop("canary"),                       # missing canary
        lambda k: k.update(canary="INSTRUCTOR-CANARY-WRONG"),
        lambda k: k.update(scene_sha256="0" * 64),       # stale scene revision
        lambda k: k.update(note="operator annotation"),  # extra field
        lambda k: k["events"].pop("a03"),                # missing row
        lambda k: k["events"].update(a05=k["events"]["a01"].copy()),  # extra row
        lambda k: k["events"]["a01"].pop("report_match"),
        lambda k: k["events"]["a01"].update(basis="prose rationale"),  # extra row field
        lambda k: k["events"]["a01"].update(classification="malicious"),  # vocabulary
        lambda k: k["events"]["a02"].update(evidence_event_id="a01"),  # cross-event
    ]
    for mutate in mutations:
        key = copy.deepcopy(base)
        mutate(key)
        with pytest.raises(h.HarnessError):
            h.grade(evidence, right, key)
        with pytest.raises(h.HarnessError):
            h.load_key(key)


def test_self_check_gives_no_correctness_signal() -> None:
    evidence = fixture_trace()
    right = submission(evidence, key_document())
    wrong = copy.deepcopy(right)
    wrong["assessments"][1]["observed_effect"] = "executed"
    wrong["assessments"][2]["classification"] = "clean"
    wrong["assessments"][3]["report_match"] = "yes"
    # A wrong-but-well-formed submission is indistinguishable to the
    # self-check: identical output, no expected value anywhere.
    assert h.self_check(evidence, right) == h.self_check(evidence, wrong)
    report = h.self_check(evidence, wrong)
    assert report["complete"] and report["bound"] and report["shape_valid"]
    blob = json.dumps(report)
    assert "expected" not in blob and h.KEY_CANARY not in blob
    # Shape and vocabulary problems ARE reported (never the correct value).
    broken = copy.deepcopy(wrong)
    broken["assessments"][0]["classification"] = "totally-wrong"
    flagged = h.self_check(evidence, broken)
    assert flagged["vocabulary_errors"] == [
        {"event_id": "a01", "field": "classification"}]
    unbound = copy.deepcopy(right)
    unbound["trace_sha256"] = "0" * 64
    refused = h.self_check(evidence, unbound)
    assert refused["bound"] is False and refused["complete"] is False
    # Out-of-vocabulary garbage still never reveals the anchor value.
    assert h.self_check(evidence, right) != flagged


def test_module_exposes_no_answer_derivation() -> None:
    assert not hasattr(h, "answer")
    parameters = list(inspect.signature(h.grade).parameters)
    assert parameters == ["evidence", "submission", "key"]
    source = inspect.getsource(h)
    # The module computes no grading anchors from the scene: the removed
    # answer() mapping must not survive anywhere in the source.
    assert "def answer(" not in source
    assert "answer(" not in source


def test_cli_self_check_and_key_grade(tmp_path, capsys) -> None:
    trace_path = tmp_path / "trace.json"
    key_path = tmp_path / "key.json"
    submission_path = tmp_path / "assessment.json"
    key = key_document()
    key_path.write_text(json.dumps(key), encoding="utf-8")
    assert h.main(["run", "--out", str(trace_path)]) == 0
    evidence = h.verify_trace(json.loads(trace_path.read_text(encoding="utf-8")))
    submission_path.write_text(json.dumps(submission(evidence, key)), encoding="utf-8")
    # Self-check: exit 0, no correctness channel.
    assert h.main(["self-check", "--trace", str(trace_path),
                   "--submission", str(submission_path)]) == 0
    assert '"complete":true' in capsys.readouterr().out
    # Grade without --key is a usage error; with the key it grades.
    with pytest.raises(SystemExit) as usage:
        h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path)])
    assert usage.value.code == 2
    capsys.readouterr()
    assert h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path),
                   "--key", str(key_path)]) == 0
    assert '"passed":true' in capsys.readouterr().out
    found = submission(evidence, key)
    found["assessments"][0]["classification"] = "rejected"
    submission_path.write_text(json.dumps(found), encoding="utf-8")
    assert h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path),
                   "--key", str(key_path)]) == 1
    capsys.readouterr()
    stale = dict(key)
    stale["scene_sha256"] = "0" * 64
    stale_path = tmp_path / "stale-key.json"
    stale_path.write_text(json.dumps(stale), encoding="utf-8")
    assert h.main(["grade", "--trace", str(trace_path), "--submission", str(submission_path),
                   "--key", str(stale_path)]) == 2
    assert "different scene revision" in capsys.readouterr().out
