"""Causal tests for SAFE-01 containment evidence verification."""

from __future__ import annotations

import pytest

from containment_evidence import verify_containment


def _control(evidence="ev"):
    return {"status": "pass", "evidence": evidence}


def _full_bundle():
    controls = {name: _control() for name in [
        "denied_egress", "no_mutation", "sandbox_boundary",
        "ground_truth_isolation", "cleanup", "credential_isolation",
        "resource_limits", "hostile_content_as_data",
    ]}
    controls["ground_truth_isolation"]["grader_plane_separation"] = "separate"
    return {"controls": controls}


def test_full_bundle_satisfied():
    r = verify_containment(_full_bundle())
    assert r.satisfied is True
    assert r.controls_missing == ()
    assert r.controls_failed == ()


def test_missing_control_fails():
    b = _full_bundle()
    del b["controls"]["denied_egress"]
    r = verify_containment(b)
    assert r.satisfied is False
    assert "denied_egress" in r.controls_missing


def test_failed_control_fails():
    b = _full_bundle()
    b["controls"]["no_mutation"]["status"] = "fail"
    r = verify_containment(b)
    assert r.satisfied is False
    assert "no_mutation" in r.controls_failed


def test_missing_evidence_fails():
    b = _full_bundle()
    b["controls"]["cleanup"]["evidence"] = ""
    r = verify_containment(b)
    assert r.satisfied is False


def test_missing_grader_plane_separation_fails():
    b = _full_bundle()
    del b["controls"]["ground_truth_isolation"]["grader_plane_separation"]
    r = verify_containment(b)
    assert r.satisfied is False


def test_non_mapping_bundle_raises():
    with pytest.raises(Exception):
        verify_containment("x")


def test_non_mapping_controls_raises():
    with pytest.raises(Exception):
        verify_containment({"controls": "x"})


def test_failed_extra_control_cannot_be_ignored():
    bundle = _full_bundle()
    bundle["controls"]["redirect_boundary"] = {"status": "fail", "evidence": "run:redirect"}
    result = verify_containment(bundle)
    assert result.satisfied is False
    assert "redirect_boundary" in result.controls_failed


@pytest.mark.parametrize("evidence", [None, False, [], " ", "bad\x00reference"])
def test_placeholder_or_malformed_evidence_cannot_pass(evidence):
    bundle = _full_bundle()
    bundle["controls"]["denied_egress"]["evidence"] = evidence
    result = verify_containment(bundle)
    assert not result.satisfied
    assert "denied_egress" in result.controls_failed


def test_positive_record_result_does_not_claim_safe_01_acceptance():
    result = verify_containment(_full_bundle())
    assert result.satisfied
    assert result.scope == "declared-control-records"
    assert "measurement-and-artifact-references-not-authenticated" in result.limitations
    assert "no-containment-enforcement-or-safe-01-acceptance" in result.limitations
