"""Causal tests for GOV-01 candidate admission closure."""

from __future__ import annotations

import pytest

from candidate_admission import validate_candidate_admission


def _good():
    return {
        "candidate_id": "R01",
        "pinned_revision": "synthetic-corpus-v1",
        "revision_hashes": ["sha256:" + "c" * 64],
        "code_license": "MIT",
        "data_rights": "open",
        "named_owner": "fixture-reviewer",
        "data_classification": "public",
        "action_surface": "lookup",
        "side_effects": ["local-read"],
        "egress": "none",
        "cost_behavior": "none",
        "cleanup_semantics": "none",
        "offline_tests": ["records/offline-parse.json"],
        "denied_egress_tests": ["records/denied-egress.json"],
        "provenance_semantics": "declared",
        "negative_cases": ["cases/missing-subject.json"],
        "inconclusive_cases": ["cases/unknown-currentness.json"],
        "regression_case": "records/regression.json",
        "promotion_evidence": "reviews/candidate-record.json",
    }


def test_good_passes():
    r = validate_candidate_admission(_good())
    assert r.valid is True


def test_missing_fails():
    d = _good()
    del d["named_owner"]
    r = validate_candidate_admission(d)
    assert r.valid is False
    assert "named_owner" in r.missing


def test_empty_owner_fails():
    d = _good()
    d["named_owner"] = ""
    r = validate_candidate_admission(d)
    assert r.valid is False


def test_empty_revision_hashes_fails():
    d = _good()
    d["revision_hashes"] = []
    r = validate_candidate_admission(d)
    assert r.valid is False


def test_extra_fails():
    d = _good()
    d["extra"] = 1
    r = validate_candidate_admission(d)
    assert r.valid is False


def test_non_mapping_raises():
    with pytest.raises(Exception):
        validate_candidate_admission("x")


@pytest.mark.parametrize("field", [
    "offline_tests", "denied_egress_tests", "negative_cases",
    "inconclusive_cases", "regression_case",
])
@pytest.mark.parametrize("value", [[None], [""], ["  "], [[]], [{"ref": "test"}]])
def test_case_reference_placeholders_fail(field, value):
    d = _good()
    d[field] = value
    r = validate_candidate_admission(d)
    assert r.valid is False
    assert field in r.invalid


@pytest.mark.parametrize("value", [
    "sha256:" + "g" * 64, "sha256:" + "A" * 64,
    "sha256:" + "a" * 64 + "\n", "a" * 64,
])
def test_revision_hashes_are_exact_lowercase_sha256(value):
    d = _good()
    d["revision_hashes"] = [value]
    assert validate_candidate_admission(d).valid is False


@pytest.mark.parametrize("field", ["candidate_id", "pinned_revision", "promotion_evidence"])
@pytest.mark.parametrize("value", [" ", " x ", "x\ny", "x\x85y", "x\ud800y", "x" * 1025])
def test_identity_and_evidence_refs_are_bounded(field, value):
    d = _good()
    d[field] = value
    assert validate_candidate_admission(d).valid is False


def test_single_reference_compatibility_and_empty_side_effects():
    d = _good()
    d["offline_tests"] = "tests/test_candidate_admission.py::test_good_passes"
    d["side_effects"] = []
    assert validate_candidate_admission(d).valid is True


def test_mixed_type_extra_keys_report_invalid():
    d = _good()
    d.update({1: "invalid key", "extra": "unexpected"})
    assert validate_candidate_admission(d).valid is False
