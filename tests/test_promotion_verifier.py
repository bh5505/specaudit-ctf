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


@pytest.mark.parametrize("field", ["subject_digest", "contract_digest"])
@pytest.mark.parametrize("value", [
    "sha256:" + "g" * 64, "sha256:" + "A" * 64,
    "sha256:" + "b" * 64 + "\n",
])
def test_digest_bytes_are_strict(field, value):
    d = _good()
    d[field] = value
    assert verify_promotion(d).valid is False


@pytest.mark.parametrize("field", [
    "implementation_revision", "reviewer", "exercised_path",
])
@pytest.mark.parametrize("value", ["       ", " xxxxxxx ", "x" * 1025, None])
def test_string_fields_require_bounded_references(field, value):
    d = _good()
    d[field] = value
    assert verify_promotion(d).valid is False


@pytest.mark.parametrize("field", [
    "supported_versions", "source_revisions", "accepted_limitations",
])
@pytest.mark.parametrize("value", [[None], [" "], [[]], ["x" * 1025]])
def test_list_fields_reject_placeholders(field, value):
    d = _good()
    d[field] = value
    assert verify_promotion(d).valid is False


@pytest.mark.parametrize("field", ["regression_result", "promotion_state"])
@pytest.mark.parametrize("value", [[], {}])
def test_unhashable_enums_report_invalid(field, value):
    d = _good()
    d[field] = value
    assert verify_promotion(d).valid is False


def test_no_accepted_limitations_can_be_declared():
    d = _good()
    d["accepted_limitations"] = []
    assert verify_promotion(d).valid is True


def test_mixed_type_extra_keys_report_invalid():
    d = _good()
    d.update({1: "invalid key", "extra": "unexpected"})
    assert verify_promotion(d).valid is False
