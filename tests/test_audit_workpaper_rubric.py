"""Structure is deterministic; semantic quality requires declared human review."""

from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from audit_workpaper.rubric import grade_workpaper

EVIDENCE = b"retained synthetic control configuration"


def _statement(key="nf-1", **extra):
    return {"id": key, "statement": "No exception in the stated host configuration",
            "subject": "host A", "population": "host A", "period": "2026",
            "evidence_ids": ["e1"], **extra}


def _review(wp, **extra):
    wp.pop("human_adjudication", None)
    wp["human_adjudication"] = {
        "reviewer": "reviewer-1", "rationale": "Reviewed retained config and bounded inference",
        "decided_on": "2026-10-17", "document_digest": grade_workpaper(wp).review_subject_digest,
        "evidence_sufficient": True, "supportedness": True, **extra,
    }
    return wp


def _good_wp(*, reviewed=True):
    wp = {
        "objective": "Assess control X",
        "scope": {"subject": "host A", "actions": "read", "stop_conditions": "on error"},
        "criteria": ["C1"], "population": "host A", "period": "2026",
        "procedures": ["inspect config"],
        "evidence": [{"id": "e1", "sha256": hashlib.sha256(EVIDENCE).hexdigest(), "kind": "observed",
                      "source": "synthetic-config", "version": "1", "time": "2026-10-17",
                      "scope": "read host A configuration", "subject": "host A", "population": "host A",
                      "period": "2026", "custody": "retained by reviewer-1", "limitations": ["configuration only"]}],
        "findings": [], "non_findings": [_statement()],
        "conclusion": "No exception in host A configuration", "conclusion_evidence_ids": ["e1"],
        "limitations": ["operating effectiveness not tested"], "retest_plan": "retest in 90 days",
    }
    return _review(wp) if reviewed else wp


def test_good_workpaper_passes_with_separate_declared_review():
    result = grade_workpaper(_good_wp(), evidence_bytes={"e1": EVIDENCE})
    assert result.passed is True
    assert result.score == 1.0 and result.unmet == ()
    assert result.structurally_valid and result.machine_verdict == "structurally-valid"
    assert result.human_verdict == "pass"
    assert "reviewer-adjudication-is-caller-declared-unauthenticated-and-uncalibrated" in result.limitations


def test_good_structure_without_human_adjudication_is_pending():
    result = grade_workpaper(_good_wp(reviewed=False))
    assert result.structurally_valid and result.score == 1.0
    assert result.human_verdict == "pending" and result.human_review_required
    assert not result.passed and "human_adjudication" in result.unmet
    assert "evidence-content-not-checked-digests-declared-only" in result.limitations


def test_missing_structure_fails():
    result = grade_workpaper({"objective": "x"})
    assert not result.passed and "structure" in result.unmet


def test_missing_evidence_fails():
    wp = _good_wp()
    wp["evidence"] = []
    assert "evidence_sufficiency" in grade_workpaper(wp).unmet


def test_finding_requires_all_fields():
    wp = _good_wp()
    wp["findings"] = [{"condition": "c"}]
    assert "finding_structure" in grade_workpaper(wp).unmet


def test_evidence_linked_finding_with_four_cs_is_retained():
    wp = _good_wp(reviewed=False)
    wp["findings"] = [_statement("f1", condition="open", criterion="closed",
                                  cause="configuration", consequence="exposure")]
    assert grade_workpaper(_review(wp)).passed


def test_no_nonfinding_fails():
    wp = _good_wp()
    wp.pop("non_findings")
    assert "supported_nonfinding" in grade_workpaper(wp).unmet


def test_missing_limitations_fails():
    wp = _good_wp()
    wp["limitations"] = []
    assert "stated_uncertainty" in grade_workpaper(wp).unmet


def test_missing_retest_fails():
    wp = _good_wp()
    wp.pop("retest_plan")
    assert "follow_through" in grade_workpaper(wp).unmet


def test_non_mapping_raises():
    with pytest.raises(TypeError):
        grade_workpaper("not a mapping")


def test_score_is_ratio_of_structure_only():
    wp = _good_wp()
    wp["evidence"] = []
    result = grade_workpaper(wp)
    assert 0.0 < result.score < 1.0 and not result.passed


def test_inconclusive_area_counts_with_explicit_context_and_references():
    wp = _good_wp(reviewed=False)
    wp["non_findings"] = []
    wp["inconclusive_areas"] = [_statement("i1", statement="Operating effectiveness untested")]
    assert "supported_nonfinding" not in grade_workpaper(wp).unmet


@pytest.mark.parametrize("group", ["non_findings", "inconclusive_areas"])
@pytest.mark.parametrize("entry", [None, "area X untested", False, {}, {"statement": "x"}])
def test_placeholder_nonfindings_and_inconclusive_areas_fail(group, entry):
    wp = _good_wp(reviewed=False)
    wp["non_findings"] = []
    wp[group] = [entry]
    result = grade_workpaper(wp)
    assert not result.passed and "supported_nonfinding" in result.unmet


@pytest.mark.parametrize("field", ["source", "version", "time", "scope", "custody", "limitations", "subject", "population", "period"])
@pytest.mark.parametrize("value", [None, "", False, []])
def test_empty_or_null_evidence_metadata_fails(field, value):
    wp = _good_wp()
    wp["evidence"][0][field] = value
    assert "evidence_sufficiency" in grade_workpaper(wp).unmet


@pytest.mark.parametrize("field,value", [("id", ""), ("id", None), ("sha256", "x" * 64),
                                         ("sha256", None), ("kind", "trusted"), ("kind", {})])
def test_invalid_evidence_identity_digest_or_class_fails(field, value):
    wp = _good_wp()
    wp["evidence"][0][field] = value
    assert "evidence_sufficiency" in grade_workpaper(wp).unmet


@pytest.mark.parametrize("field", ["id", "sha256"])
def test_duplicate_evidence_identity_or_digest_fails(field):
    wp = _good_wp()
    extra = deepcopy(wp["evidence"][0])
    extra["id"] = "e2"
    extra["sha256"] = hashlib.sha256(b"other config").hexdigest()
    extra[field] = wp["evidence"][0][field]
    wp["evidence"].append(extra)
    assert "evidence_sufficiency" in grade_workpaper(wp).unmet


@pytest.mark.parametrize("group", ["claims", "findings", "non_findings", "inconclusive_areas", "conclusion"])
@pytest.mark.parametrize("refs", [[], ["unknown"], ["e1", "e1"], [None]])
def test_every_statement_requires_resolving_unique_evidence_references(group, refs):
    wp = _good_wp(reviewed=False)
    if group == "conclusion":
        wp["conclusion_evidence_ids"] = refs
    else:
        wp[group] = [_statement("x1", status="supported", type="non-finding", evidence_ids=refs)]
    assert "traceability" in grade_workpaper(wp).unmet


def test_evidence_counts_cannot_substitute_for_missing_references():
    wp = _good_wp(reviewed=False)
    wp["non_findings"][0].pop("evidence_ids")
    wp.pop("conclusion_evidence_ids")
    assert "traceability" in grade_workpaper(wp).unmet


def test_statement_ids_must_be_unique():
    wp = _good_wp(reviewed=False)
    wp["claims"] = [_statement(status="supported")]
    assert "traceability" in grade_workpaper(wp).unmet


@pytest.mark.parametrize("field", ["subject", "population", "period"])
def test_claim_context_cannot_exceed_or_change_evidence_context(field):
    wp = _good_wp(reviewed=False)
    wp["non_findings"][0][field] = "different context"
    assert "traceability" in grade_workpaper(wp).unmet


def test_declared_evidence_does_not_become_observed_support():
    wp = _good_wp(reviewed=False)
    wp["evidence"][0]["kind"] = "declared"
    assert "traceability" in grade_workpaper(wp).unmet


def test_content_mismatch_fails_even_with_declared_human_pass():
    result = grade_workpaper(_good_wp(), evidence_bytes={"e1": b"different retained content"})
    assert not result.structurally_valid and not result.passed
    assert result.human_verdict == "pass"  # Sibling assertion never overrides machine failure.
    assert "evidence_sufficiency" in result.unmet


def test_inline_bytes_must_match_manifest_ids_exactly():
    assert not grade_workpaper(_good_wp(), evidence_bytes={}).passed
    with pytest.raises(TypeError):
        grade_workpaper(_good_wp(), evidence_bytes={"e1": "not bytes"})


@pytest.mark.parametrize("field", ["supportedness", "evidence_sufficient"])
def test_semantically_unsupported_or_insufficient_workpaper_fails_review(field):
    wp = _good_wp(reviewed=False)
    wp["conclusion"] = "Every host is effective despite contrary retained observations"
    # Structure does not inspect prose truth; the reviewer must adjudicate it.
    assert grade_workpaper(wp).structurally_valid
    assert not grade_workpaper(wp).passed
    result = grade_workpaper(_review(wp, **{field: False}))
    assert result.structurally_valid and result.human_verdict == "fail" and not result.passed


def test_original_false_assurance_probe_fails_attribution_and_support():
    wp = _good_wp(reviewed=False)
    wp["evidence"] = [{field: None for field in ("source", "version", "time", "scope", "custody", "limitations")}]
    wp["non_findings"] = [None]
    wp["conclusion"] = "All controls operate effectively on every host"
    wp["limitations"] = ["No configuration or control evidence was obtained"]
    result = grade_workpaper(wp)
    assert not result.passed and not result.structurally_valid and result.score < 1.0
    assert {"evidence_sufficiency", "traceability", "supported_nonfinding"} <= set(result.unmet)


def test_adjudication_binds_exact_document():
    wp = _good_wp()
    wp["conclusion"] = "A newly changed conclusion"
    result = grade_workpaper(wp)
    assert result.human_verdict == "invalid" and not result.passed


@pytest.mark.parametrize("field,value", [("reviewer", ""), ("rationale", None), ("decided_on", "x"),
                                         ("supportedness", "pass"), ("evidence_sufficient", 1),
                                         ("document_digest", "sha256:" + "0" * 64)])
def test_invalid_adjudication_cannot_pass(field, value):
    wp = _good_wp()
    wp["human_adjudication"][field] = value
    result = grade_workpaper(wp)
    assert result.human_verdict == "invalid" and not result.passed


def test_explicit_unresolved_conclusion_can_retain_declared_inconclusive_evidence():
    wp = _good_wp(reviewed=False)
    wp["evidence"][0]["kind"] = "declared"
    wp["non_findings"] = []
    wp["inconclusive_areas"] = [_statement("i1", statement="Effective operation remains unestablished")]
    wp["conclusion"] = "Operating effectiveness remains unresolved"
    wp["conclusion_status"] = "unresolved"
    result = grade_workpaper(wp)
    assert result.structurally_valid and result.human_verdict == "pending" and not result.passed
    # The human's bounded-conclusion judgment does not promote declared evidence.
    assert grade_workpaper(_review(wp)).passed
    assert wp["evidence"][0]["kind"] == "declared"


@pytest.mark.parametrize("status", [True, {}, "all-clear"])
def test_invalid_conclusion_status_fails_structure(status):
    wp = _good_wp(reviewed=False)
    wp["conclusion_status"] = status
    assert "traceability" in grade_workpaper(wp).unmet


def test_malformed_finding_type_returns_failed_result():
    wp = _good_wp(reviewed=False)
    wp["findings"] = [_statement("f1", type={})]
    assert not grade_workpaper(wp).structurally_valid
