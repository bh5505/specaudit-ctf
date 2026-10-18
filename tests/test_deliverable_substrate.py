"""Causal tests for PACK-01 deliverable substrate."""

from __future__ import annotations

import pytest

from deliverable_substrate import validate_deliverable


def _good():
    return {
        "learner_brief": "Review the synthetic capture and retain uncertainties.",
        "evidence_manifest": {"artifacts": [{
            "artifact_id": "capture-1", "path": "evidence/a.json",
            "digest": "sha256:" + "a" * 64, "media_type": "application/json",
        }]},
        "instructor_key": "instructor/expected-findings.json",
        "benign_control": "controls/scoped-access.json",
        "limitations": ["Synthetic capture does not establish deployed behavior."],
        "rubric": {"dimensions": ["attribution", "supported conclusion"]},
        "reset_retention": "procedures/reset-retention.md",
    }


def test_good_passes():
    r = validate_deliverable(_good())
    assert r.valid is True


def test_missing_fails():
    d = _good()
    del d["rubric"]
    r = validate_deliverable(d)
    assert r.valid is False
    assert "rubric" in r.missing


def test_empty_fails():
    d = _good()
    d["limitations"] = []
    r = validate_deliverable(d)
    assert r.valid is False


def test_empty_manifest_artifacts_fails():
    d = _good()
    d["evidence_manifest"] = {"artifacts": []}
    r = validate_deliverable(d)
    assert r.valid is False


def test_extra_fails():
    d = _good()
    d["extra"] = 1
    r = validate_deliverable(d)
    assert r.valid is False


def test_non_mapping_raises():
    with pytest.raises(Exception):
        validate_deliverable("x")


@pytest.mark.parametrize("value", [
    "x", {"unrelated": None}, {"artifacts": [""]},
    {"artifacts": ["a.json"]}, {"artifacts": [{"path": "a.json"}]},
])
def test_manifest_requires_actual_artifact_bindings(value):
    d = _good()
    d["evidence_manifest"] = value
    r = validate_deliverable(d)
    assert r.valid is False
    assert "evidence_manifest" in r.invalid


@pytest.mark.parametrize("field,value", [
    ("artifact_id", " "), ("path", ""), ("path", "../outside.json"),
    ("path", "/absolute.json"), ("path", "a/../capture.json"),
    ("digest", "sha256:" + "z" * 64), ("digest", "sha256:" + "A" * 64),
    ("media_type", " "), ("media_type", "json"),
])
def test_manifest_rejects_same_shaped_invalid_values(field, value):
    d = _good()
    d["evidence_manifest"]["artifacts"][0][field] = value
    assert validate_deliverable(d).valid is False


def test_manifest_duplicate_artifact_ids_or_paths_fail():
    d = _good()
    d["evidence_manifest"]["artifacts"] *= 2
    assert validate_deliverable(d).valid is False


@pytest.mark.parametrize("field", [
    "learner_brief", "instructor_key", "benign_control", "limitations",
    "rubric", "reset_retention",
])
@pytest.mark.parametrize("value", [False, [None], {"ref": None}, [[""]], {"ref": []}])
def test_component_nested_placeholders_fail(field, value):
    d = _good()
    d[field] = value
    assert validate_deliverable(d).valid is False


def test_concrete_nested_component_and_multiline_prose_pass():
    d = _good()
    d["learner_brief"] = "Review the capture.\nRecord each uncertainty."
    d["rubric"] = {"dimensions": ["attribution", {"support": "cite capture-1"}]}
    assert validate_deliverable(d).valid is True


def test_cyclic_and_deep_components_are_reported_invalid():
    cyclic = []
    cyclic.append(cyclic)
    deep = "content"
    for _ in range(12):
        deep = [deep]
    cyclic_map = {}
    cyclic_map["self"] = cyclic_map
    for value in (cyclic, cyclic_map, deep, ["item"] * 257, [["item"] * 256] * 256):
        d = _good()
        d["rubric"] = value
        assert validate_deliverable(d).valid is False


def test_mixed_type_extra_keys_report_invalid():
    d = _good()
    d.update({1: "invalid key", "extra": "unexpected"})
    assert validate_deliverable(d).valid is False
