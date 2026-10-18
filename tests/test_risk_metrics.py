"""Causal tests for EVAL-01 risk-sensitive metrics."""

from __future__ import annotations

import pytest

from attempt_ledger.ledger import append_row, verify_ledger
from attempt_ledger.risk_metrics import (
    AttemptLabel,
    RiskSensitiveMetrics,
    compute_risk_sensitive_metrics,
)


def _row(attempt_id, lane="fixture-backed", attempt_class="completion",
         assistance="first-pass", subject="s1", detail_digest=None):
    if detail_digest is None:
        detail_digest = "sha256:" + "0" * 64
    return {
        "attempt_id": attempt_id,
        "lane": lane,
        "subject": subject,
        "attempt_class": attempt_class,
        "assistance": assistance,
        "detail_digest": detail_digest,
        "recorded_at": "2026-01-01T00:00:00",
        "outcome": "ok" if attempt_class == "completion" else None,
    }


def _build(rows):
    out = []
    chain = ()
    head = None
    for r in rows:
        chain, head = append_row(chain, r)
    assert verify_ledger(chain).ok
    return list(chain)


def test_empty_ledger():
    m = compute_risk_sensitive_metrics([])
    assert m.total == 0
    assert m.completions == 0
    assert m.critical_misses == 0
    assert m.false_review_burden == 0


def test_all_rows_retained_in_denominator():
    rows = _build([
        _row("attempt-1", attempt_class="completion"),
        _row("attempt-2", attempt_class="refusal"),
        _row("attempt-3", attempt_class="timeout"),
        _row("attempt-4", attempt_class="abstention"),
    ])
    m = compute_risk_sensitive_metrics(rows)
    assert m.total == 4
    assert m.completions == 1


def test_critical_miss_counted():
    rows = _build([
        _row("attempt-1", attempt_class="refusal", subject="CVE-1"),
    ])
    labels = [AttemptLabel("attempt-1", severity="critical", is_true_finding=True)]
    m = compute_risk_sensitive_metrics(rows, labels)
    assert m.critical_misses == 1
    assert m.critical_misses_by_lane["fixture-backed"] == 1


def test_completed_true_finding_is_not_a_miss():
    rows = _build([_row("attempt-1", attempt_class="completion", subject="CVE-1")])
    labels = [AttemptLabel("attempt-1", severity="critical", is_true_finding=True)]
    m = compute_risk_sensitive_metrics(rows, labels)
    assert m.critical_misses == 0
    assert m.completions == 1


def test_false_review_burden():
    rows = _build([_row("attempt-1", attempt_class="completion", subject="benign-1")])
    labels = [AttemptLabel("attempt-1", severity="low", is_true_finding=False)]
    m = compute_risk_sensitive_metrics(rows, labels)
    assert m.false_review_burden == 1


def test_unknown_label_does_not_contribute():
    rows = _build([_row("attempt-1", attempt_class="refusal", subject="CVE-1")])
    m = compute_risk_sensitive_metrics(rows)  # no labels
    assert m.critical_misses == 0
    assert m.false_review_burden == 0
    assert m.total == 1


def test_lanes_never_compared_as_equivalent():
    rows = _build([
        _row("attempt-1", lane="fixture-backed", attempt_class="completion"),
        _row("attempt-2", lane="live-service", attempt_class="completion"),
    ])
    m = compute_risk_sensitive_metrics(rows)
    assert set(m.by_lane) == {"fixture-backed", "live-service"}
    assert m.by_lane["fixture-backed"] == 1
    assert m.by_lane["live-service"] == 1
    assert m.completions_by_lane["fixture-backed"] == 1
    assert m.completions_by_lane["live-service"] == 1


def test_assistance_separation():
    rows = _build([
        _row("attempt-1", assistance="first-pass", attempt_class="completion"),
        _row("attempt-2", assistance="assisted", attempt_class="completion"),
    ])
    m = compute_risk_sensitive_metrics(rows)
    assert m.by_assistance["first-pass"] == 1
    assert m.by_assistance["assisted"] == 1


def test_saturated_subjects_labelled():
    rows = _build([_row("attempt-1", attempt_class="completion", subject="xbow-task-1")])
    labels = [AttemptLabel("attempt-1", benchmark_saturated=True)]
    m = compute_risk_sensitive_metrics(rows, labels)
    assert "xbow-task-1" in m.saturated_subjects
    assert m.saturated_label == "regression-only"


def test_duplicate_label_rejected():
    with pytest.raises(ValueError):
        compute_risk_sensitive_metrics(
            _build([_row("attempt-1")]),
            [AttemptLabel("attempt-1"), AttemptLabel("attempt-1")],
        )


def test_unknown_lane_rejected():
    bad = [_row("attempt-1")]
    bad[0]["lane"] = "not-a-lane"
    with pytest.raises(ValueError):
        compute_risk_sensitive_metrics(bad)


def test_rows_must_be_sequence():
    with pytest.raises(TypeError):
        compute_risk_sensitive_metrics("not-a-list")  # type: ignore[arg-type]


def test_high_severity_set():
    from attempt_ledger.risk_metrics import HIGH_SEVERITIES
    assert "critical" in HIGH_SEVERITIES
    assert "high" in HIGH_SEVERITIES
    assert "medium" not in HIGH_SEVERITIES
