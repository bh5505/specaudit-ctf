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
    labels = [AttemptLabel("attempt-1", severity="critical", is_true_finding=True,
                           adjudicated_disposition="absent")]
    m = compute_risk_sensitive_metrics(rows, labels)
    assert m.critical_misses == 1
    assert m.critical_misses_by_lane["fixture-backed"] == 1


def test_completed_true_finding_is_not_a_miss():
    rows = _build([_row("attempt-1", attempt_class="completion", subject="CVE-1")])
    labels = [AttemptLabel("attempt-1", severity="critical", is_true_finding=True,
                           adjudicated_disposition="present")]
    m = compute_risk_sensitive_metrics(rows, labels)
    assert m.critical_misses == 0
    assert m.completions == 1


def test_false_review_burden():
    rows = _build([_row("attempt-1", attempt_class="completion", subject="benign-1")])
    labels = [AttemptLabel("attempt-1", severity="low", is_true_finding=False,
                           adjudicated_disposition="present")]
    m = compute_risk_sensitive_metrics(rows, labels)
    assert m.false_review_burden == 1


def test_unknown_label_does_not_contribute():
    rows = _build([_row("attempt-1", attempt_class="refusal", subject="CVE-1")])
    m = compute_risk_sensitive_metrics(rows)  # no labels
    assert m.critical_misses == 0
    assert m.false_review_burden == 0
    assert m.total == 1
    assert m.unknown_disposition == 1
    assert m.unknown_truth == 1
    assert m.adjudicated_attempts == 0


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


def _label(attempt_id, disposition="unknown", **extra):
    return AttemptLabel(attempt_id, adjudicated_disposition=disposition, **extra)


def test_every_execution_class_retained_including_failures_and_stops():
    from attempt_ledger.ledger import ATTEMPT_CLASSES
    rows = _build([_row(f"attempt-{i}", attempt_class=kind)
                   for i, kind in enumerate(sorted(ATTEMPT_CLASSES))])
    metrics = compute_risk_sensitive_metrics(rows)
    assert metrics.total == len(ATTEMPT_CLASSES) == 10
    assert metrics.completions == 1 and metrics.unknown_disposition == 10
    assert sum(metrics.by_lane.values()) == 10


def test_verified_completed_grade_with_real_critical_miss_and_correct_benign():
    import hashlib
    import json
    from score.grading import grade

    critical = {"finding_key": "critical-missed", "severity": "critical", "control": "C1",
                "rationale": "synthetic planted critical condition", "traces_to": "fixture.json#/critical"}
    result = grade({"track": "test", "findings": []}, {"track": "test", "findings": [critical]})
    assert result["passed"] is False and result["misses"] == ["critical-missed"]
    missed = _row("attempt-missed", subject="critical-missed")
    missed["outcome"] = "failed"
    missed["detail_digest"] = "sha256:" + hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    benign = _row("attempt-benign", subject="benign-no-finding")
    benign["outcome"] = "passed"
    rows = _build([missed, benign])
    assert verify_ledger(rows).ok
    metrics = compute_risk_sensitive_metrics(rows, [
        _label("attempt-missed", "absent", severity="critical", is_true_finding=True),
        _label("attempt-benign", "absent", severity="low", is_true_finding=False),
    ])
    assert metrics.total == 2 and metrics.completions == 2
    assert metrics.critical_misses == 1 and metrics.false_review_burden == 0
    assert metrics.adjudicated_attempts == 2 and metrics.unknown_disposition == 0


def test_failed_grade_may_mean_extras_and_never_implies_absent_prediction():
    from score.grading import grade
    expected = {"finding_key": "expected", "severity": "critical", "control": "C1",
                "rationale": "synthetic expected", "traces_to": "fixture.json#/expected"}
    extra = {**expected, "finding_key": "extra"}
    report = grade({"track": "test", "findings": [expected, extra]},
                   {"track": "test", "findings": [expected]})
    assert not report["passed"] and report["misses"] == [] and report["extras"] == ["extra"]
    row = _row("attempt-extras")
    row["outcome"] = "graded-failed"
    rows = _build([row])
    unknown = compute_risk_sensitive_metrics(rows, [AttemptLabel("attempt-extras", "critical", True)])
    assert unknown.critical_misses == 0 and unknown.unknown_critical_disposition == 1
    assert unknown.evaluable_critical_subjects == 0 and unknown.unknown_disposition == 1
    known = compute_risk_sensitive_metrics(rows, [_label("attempt-extras", "present", severity="critical", is_true_finding=True)])
    assert known.critical_misses == 0 and known.evaluable_critical_subjects == 1


def test_noncompletion_does_not_override_explicit_adjudication():
    rows = _build([_row("attempt-1", attempt_class="timeout")])
    metrics = compute_risk_sensitive_metrics(rows, [_label("attempt-1", "present", severity="high", is_true_finding=True)])
    assert metrics.total == 1 and metrics.completions == 0 and metrics.critical_misses == 0
    assert metrics.adjudicated_attempts == 1


def test_missing_disposition_reports_unknown_even_when_truth_label_exists():
    rows = _build([_row("attempt-1")])
    metrics = compute_risk_sensitive_metrics(rows, [AttemptLabel("attempt-1", "critical", True)])
    assert metrics.critical_misses == 0 and metrics.labelled_attempts == 1
    assert metrics.unknown_disposition == 1 and metrics.unknown_critical_disposition == 1
    assert metrics.adjudicated_attempts == 0


def test_joint_strata_distinguish_reversed_cells_with_identical_marginals():
    rows_a, rows_b, labels = [], [], []
    cells = [("fixture-backed", "first-pass"), ("fixture-backed", "assisted"),
             ("live-service", "first-pass"), ("live-service", "assisted")]
    for i, (lane, assistance) in enumerate(cells):
        completion_a = i in {0, 3}
        rows_a.append(_row(f"attempt-{i}", lane, "completion" if completion_a else "refusal", assistance))
        rows_b.append(_row(f"attempt-{i}", lane, "refusal" if completion_a else "completion", assistance))
        labels.append(_label(f"attempt-{i}", "absent" if completion_a else "present", severity="critical", is_true_finding=True))
    a = compute_risk_sensitive_metrics(_build(rows_a), labels)
    b = compute_risk_sensitive_metrics(_build(rows_b), labels)
    assert a.by_lane == b.by_lane and a.by_assistance == b.by_assistance
    assert a.completions_by_lane == b.completions_by_lane
    assert a.completions_by_assistance == b.completions_by_assistance
    assert a.completions_by_lane_assistance != b.completions_by_lane_assistance
    assert a.by_lane_assistance == {lane: {"assisted": 1, "first-pass": 1} for lane in {"fixture-backed", "live-service"}}
    assert a.critical_misses_by_lane_assistance["fixture-backed"]["first-pass"] == 1
    assert a.critical_misses_by_lane_assistance["live-service"]["assisted"] == 1


def test_joint_adjudication_and_false_burden_coverage():
    rows = _build([_row("attempt-1", assistance="assisted"), _row("attempt-2", assistance="first-pass")])
    result = compute_risk_sensitive_metrics(rows, [_label("attempt-1", "present", is_true_finding=False)])
    assert result.false_review_burden_by_lane_assistance == {"fixture-backed": {"assisted": 1}}
    assert result.adjudicated_by_lane_assistance == {"fixture-backed": {"assisted": 1}}
    assert result.unknown_disposition_by_lane_assistance == {"fixture-backed": {"first-pass": 1}}


def test_evaluation_split_is_separate_from_assistance():
    rows = _build([_row("attempt-1", assistance="assisted"), _row("attempt-2", assistance="first-pass")])
    result = compute_risk_sensitive_metrics(rows, [_label("attempt-1", evaluation_split="held-out"),
                                                  _label("attempt-2", evaluation_split="held-out")])
    assert result.by_evaluation_split == {"held-out": 2}
    assert result.by_assistance == {"assisted": 1, "first-pass": 1}


@pytest.mark.parametrize("field,value", [
    ("attempt_id", ""), ("attempt_id", True), ("attempt_id", "orphan-attempt"),
    ("severity", "Critical"), ("severity", False), ("severity", []),
    ("is_true_finding", 1), ("is_true_finding", "false"), ("benchmark_saturated", "false"),
    ("adjudicated_disposition", True), ("adjudicated_disposition", "passed"),
    ("adjudicated_disposition", None), ("evaluation_split", []), ("evaluation_split", "test"),
    ("row_digest", "sha256:" + "x" * 64), ("row_digest", "sha256:" + "1" * 64),
])
def test_invalid_or_orphan_labels_rejected(field, value):
    from dataclasses import replace
    label = replace(AttemptLabel("attempt-1"), **{field: value})
    with pytest.raises(ValueError):
        compute_risk_sensitive_metrics(_build([_row("attempt-1")]), [label])


@pytest.mark.parametrize("field,value", [("attempt_id", None), ("attempt_id", "bad"), ("subject", ""),
                                         ("lane", []), ("assistance", False), ("attempt_class", {}),
                                         ("row_digest", "x")])
def test_invalid_row_labels_rejected(field, value):
    row = _row("attempt-1")
    row[field] = value
    with pytest.raises(ValueError):
        compute_risk_sensitive_metrics([row])


def test_duplicate_row_is_rejected_instead_of_double_counting():
    rows = _build([_row("attempt-1")])
    with pytest.raises(ValueError):
        compute_risk_sensitive_metrics(rows + rows)


def test_legitimate_retries_remain_in_denominator_and_need_row_specific_labels():
    rows = _build([_row("attempt-1"), _row("attempt-1")])
    assert len(rows) == 2 and rows[0]["row_digest"] != rows[1]["row_digest"]
    assert compute_risk_sensitive_metrics(rows).total == 2
    with pytest.raises(ValueError, match="retry labels require"):
        compute_risk_sensitive_metrics(rows, [_label("attempt-1", "absent")])
    metrics = compute_risk_sensitive_metrics(rows, [
        _label("attempt-1", "absent", severity="critical", is_true_finding=True, row_digest=rows[0]["row_digest"]),
        _label("attempt-1", "present", severity="critical", is_true_finding=True, row_digest=rows[1]["row_digest"]),
    ])
    assert metrics.total == 2 and metrics.critical_misses == 1 and metrics.adjudicated_attempts == 2


def test_overlapping_id_and_digest_label_are_duplicates():
    rows = _build([_row("attempt-1")])
    with pytest.raises(ValueError, match="duplicate label"):
        compute_risk_sensitive_metrics(rows, [_label("attempt-1"), _label("attempt-1", row_digest=rows[0]["row_digest"])])


def test_saturated_label_cannot_be_changed_into_generalization_claim():
    with pytest.raises(ValueError):
        compute_risk_sensitive_metrics([], saturated_benchmark_label="generalization")


def test_score_grading_none_severity_is_valid_and_not_critical():
    result = compute_risk_sensitive_metrics(_build([_row("attempt-1")]),
                                            [_label("attempt-1", "absent", severity="none", is_true_finding=True)])
    assert result.unknown_severity == 0 and result.critical_misses == 0
