"""Causal tests for GOV-01 promotion verifier."""

from __future__ import annotations

import pytest

from promotion_verifier import verify_promotion


def _digest():
    return "sha256:" + "b" * 64


def _good():
    return {
        "subject_digest": _digest(),
        "contract_digest": _digest(),
        "implementation_revision": "abc12345",
        "reviewer": "operator",
        "exercised_path": "path/to/test",
        "regression_result": "passed",
        "supported_versions": ["1.0"],
        "source_revisions": ["rev1"],
        "accepted_limitations": ["none"],
        "promotion_state": "admitted",
    }


def test_good_passes():
    r = verify_promotion(_good())
    assert r.valid is True


def test_missing_field_fails():
    d = _good()
    del d["reviewer"]
    r = verify_promotion(d)
    assert r.valid is False
    assert "reviewer" in r.missing


def test_failed_regression_fails():
    d = _good()
    d["regression_result"] = "failed"
    r = verify_promotion(d)
    assert r.valid is False


def test_bad_digest_fails():
    d = _good()
    d["subject_digest"] = "not-a-digest"
    r = verify_promotion(d)
    assert r.valid is False
    assert "subject_digest" in r.invalid


def test_invalid_state_fails():
    d = _good()
    d["promotion_state"] = "bogus"
    r = verify_promotion(d)
    assert r.valid is False


def test_extra_field_fails():
    d = _good()
    d["extra"] = 1
    r = verify_promotion(d)
    assert r.valid is False


def test_non_mapping_raises():
    with pytest.raises(Exception):
        verify_promotion("x")
