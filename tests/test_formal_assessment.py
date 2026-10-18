"""Causal tests for U-ASSESS formal assessment validation."""

from __future__ import annotations

import pytest

from formal_assessment import validate_formal_assessment


def _good():
    return {
        "assessment_id": "a1",
        "named_reviews": ["reviewer-1"],
        "learner_context_separation": {"evidence": "separate plane"},
        "calibration": "calibrated",
        "operator_dry_run": {"status": "pass"},
        "answer_key_isolation": {"evidence": "isolated"},
        "challenge_authoring_contract": "contract",
        "reset_retention": "reset",
    }


def test_good_passes():
    r = validate_formal_assessment(_good())
    assert r.valid is True


def test_missing_fails():
    d = _good()
    del d["calibration"]
    r = validate_formal_assessment(d)
    assert r.valid is False
    assert "calibration" in r.missing


def test_dry_run_not_pass_fails():
    d = _good()
    d["operator_dry_run"] = {"status": "fail"}
    r = validate_formal_assessment(d)
    assert r.valid is False


def test_extra_fails():
    d = _good()
    d["extra"] = 1
    r = validate_formal_assessment(d)
    assert r.valid is False


def test_non_mapping_raises():
    with pytest.raises(Exception):
        validate_formal_assessment("x")
