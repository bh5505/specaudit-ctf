"""Causal tests for PACK-01 deliverable substrate."""

from __future__ import annotations

import pytest

from deliverable_substrate import validate_deliverable


def _good():
    return {
        "learner_brief": "brief",
        "evidence_manifest": {"artifacts": ["a.json"]},
        "instructor_key": "key",
        "benign_control": "control",
        "limitations": ["l"],
        "rubric": "rubric",
        "reset_retention": "reset",
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
