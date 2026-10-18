"""Causal tests for U-ASSESS formal assessment validation."""

from __future__ import annotations

import pytest

from formal_assessment import validate_formal_assessment


def _good():
    return {
        "assessment_id": "a1",
        "named_reviews": [{"reviewer": "reviewer-1", "review_ref": "reviews/technical.json"}],
        "learner_context_separation": {"state": "proven", "evidence_refs": ["runs/separation.json"]},
        "calibration": {"reviewer": "reviewer-2", "evidence_refs": ["calibration/human-scoring.json"]},
        "operator_dry_run": {"status": "pass", "result_ref": "runs/dry-run.json", "evidence_refs": ["runs/learner-trace.json"]},
        "answer_key_isolation": {"state": "proven", "evidence_refs": ["runs/key-isolation.json"]},
        "challenge_authoring_contract": "challenges/README.md#validation-and-promotion",
        "reset_retention": "procedures/reset-retention.md",
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


@pytest.mark.parametrize("field", [
    "assessment_id", "challenge_authoring_contract", "reset_retention",
])
@pytest.mark.parametrize("value", [None, False, " ", " x ", "x" * 1025])
def test_identity_contract_and_reset_must_be_concrete_refs(field, value):
    d = _good()
    d[field] = value
    assert validate_formal_assessment(d).valid is False


@pytest.mark.parametrize("value", [
    ["reviewer-1"], [{"reviewer": "reviewer-1", "review_ref": " "}],
    [{"reviewer": None, "review_ref": "reviews/review.json"}], [None],
])
def test_named_reviews_require_name_and_retained_review_reference(value):
    d = _good()
    d["named_reviews"] = value
    assert validate_formal_assessment(d).valid is False


@pytest.mark.parametrize("value", [
    False, "calibrated", {"reviewer": "reviewer-2", "evidence_refs": [None]},
    {"reviewer": "calibration-seed", "evidence_refs": ["calibration/seed.json"]},
    {"reviewer": " ", "evidence_refs": ["calibration/human.json"]},
])
def test_calibration_requires_typed_non_seed_review_evidence(value):
    d = _good()
    d["calibration"] = value
    assert validate_formal_assessment(d).valid is False


@pytest.mark.parametrize("value", [
    {"status": "pass"},
    {"status": "pass", "result_ref": None, "evidence_refs": ["runs/trace.json"]},
    {"status": "pass", "result_ref": "runs/result.json", "evidence_refs": [None]},
    {"status": True, "result_ref": "runs/result.json", "evidence_refs": ["runs/trace.json"]},
])
def test_dry_run_requires_exact_pass_and_retained_result_and_evidence(value):
    d = _good()
    d["operator_dry_run"] = value
    assert validate_formal_assessment(d).valid is False


@pytest.mark.parametrize("field", ["learner_context_separation", "answer_key_isolation"])
@pytest.mark.parametrize("value", [
    {"evidence": None}, {"state": "proven", "evidence_refs": [None]},
    {"state": "not-asserted", "evidence_refs": []},
    {"state": "proven", "evidence_refs": [" "]},
])
def test_isolation_requires_typed_nonempty_evidence(field, value):
    d = _good()
    d[field] = value
    assert validate_formal_assessment(d).valid is False


def test_valid_result_states_its_structural_limits():
    r = validate_formal_assessment(_good())
    assert r.valid is True
    assert any("authenticity" in limit for limit in r.limits)
    assert any("isolation" in limit for limit in r.limits)


@pytest.mark.parametrize("field,nested", [
    ("operator_dry_run", "status"), ("answer_key_isolation", "state"),
    ("learner_context_separation", "state"),
])
@pytest.mark.parametrize("value", [[], {}])
def test_malformed_nested_enums_return_invalid(field, nested, value):
    d = _good()
    d[field][nested] = value
    assert validate_formal_assessment(d).valid is False


def test_mixed_type_extra_keys_report_invalid():
    d = _good()
    d.update({1: "invalid key", "extra": "unexpected"})
    assert validate_formal_assessment(d).valid is False
