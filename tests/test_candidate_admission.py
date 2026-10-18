"""Causal tests for GOV-01 candidate admission closure."""

from __future__ import annotations

import pytest

from candidate_admission import validate_candidate_admission


def _good():
    return {
        "candidate_id": "R01",
        "pinned_revision": "rev1",
        "revision_hashes": ["sha256:" + "c" * 64],
        "code_license": "MIT",
        "data_rights": "open",
        "named_owner": "owner",
        "data_classification": "public",
        "action_surface": "lookup",
        "side_effects": ["local-read"],
        "egress": "none",
        "cost_behavior": "none",
        "cleanup_semantics": "none",
        "offline_tests": ["t1"],
        "denied_egress_tests": ["t2"],
        "provenance_semantics": "declared",
        "negative_cases": ["n1"],
        "inconclusive_cases": ["i1"],
        "regression_case": "r1",
        "promotion_evidence": "ev",
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
