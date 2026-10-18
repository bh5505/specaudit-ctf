"""Causal tests for AUDIT-01 workpaper rubric."""

from __future__ import annotations

import pytest

from audit_workpaper.rubric import grade_workpaper


def _good_wp():
    return {
        "objective": "Assess control X",
        "scope": {"subject": "host A", "actions": "read", "stop_conditions": "on error"},
        "criteria": ["C1"],
        "population": "all hosts",
        "period": "2026",
        "procedures": ["inspect config"],
        "evidence": [
            {"source": "s", "version": "1", "time": "t", "scope": "sc",
             "custody": "c", "limitations": ["none"]},
        ],
        "findings": [],
        "non_findings": ["no issue found"],
        "conclusion": "Control operates effectively",
        "limitations": ["sampling"],
        "retest_plan": "retest in 90 days",
    }


def test_good_workpaper_passes():
    r = grade_workpaper(_good_wp())
    assert r.passed is True
    assert r.score == 1.0
    assert r.unmet == ()


def test_missing_structure_fails():
    r = grade_workpaper({"objective": "x"})
    assert r.passed is False
    assert "structure" in r.unmet


def test_missing_evidence_fails():
    wp = _good_wp()
    wp["evidence"] = []
    r = grade_workpaper(wp)
    assert "evidence_sufficiency" in r.unmet


def test_finding_requires_all_fields():
    wp = _good_wp()
    wp["findings"] = [{"condition": "c"}]
    r = grade_workpaper(wp)
    assert "finding_structure" in r.unmet


def test_no_nonfinding_fails():
    wp = _good_wp()
    wp["non_findings"] = []
    wp.pop("non_findings", None)
    r = grade_workpaper(wp)
    assert "supported_nonfinding" in r.unmet


def test_missing_limitations_fails():
    wp = _good_wp()
    wp["limitations"] = []
    r = grade_workpaper(wp)
    assert "stated_uncertainty" in r.unmet


def test_missing_retest_fails():
    wp = _good_wp()
    wp.pop("retest_plan")
    r = grade_workpaper(wp)
    assert "follow_through" in r.unmet


def test_non_mapping_raises():
    with pytest.raises(TypeError):
        grade_workpaper("not a mapping")  # type: ignore[arg-type]


def test_score_is_ratio():
    wp = _good_wp()
    wp["evidence"] = []
    r = grade_workpaper(wp)
    assert 0.0 < r.score < 1.0


def test_inconclusive_area_counts():
    wp = _good_wp()
    wp["non_findings"] = []
    wp["inconclusive_areas"] = ["area X untested"]
    r = grade_workpaper(wp)
    assert "supported_nonfinding" not in r.unmet
