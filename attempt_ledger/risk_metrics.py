"""Risk-sensitive metrics over an all-attempt ledger (EVAL-01).

This module computes audit-relevant metrics from an attempt ledger without
dropping any row from the denominator: failures, refusals, timeouts and
abstentions remain counted.  Lanes (fixture-backed, live-service,
planted-code, self-study, operator-rehearsal) and assistance states
(first-pass, assisted, tuned, held-out, none) are never compared as
equivalent; per-lane and per-assistance numerators are reported against
their own denominators.

Risk-sensitive semantics (THOR-style, re-implemented independently):
- A "critical miss" is a high-severity TRUE finding that was not completed
  (missed).  Severity and truth are caller-supplied labels; this module
  never infers them from tool output.
- "False review burden" is the count of completed attempts whose subject is
  labelled benign / non-finding, i.e. work spent reviewing non-issues.
- Saturated public benchmarks must be labelled ``regression-only`` and are
  never presented as generalization evidence.

No network, no subprocess, no clock reads, no stored module state.  The
caller owns all labels and timestamps.  This module does not authenticate
the ledger (call ``verify_ledger`` first) and does not mutate it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .ledger import ATTEMPT_CLASSES, ASSISTANCE, COMPLETION, LANES

HIGH_SEVERITIES = frozenset({"critical", "high"})
SATURATED_BENCHMARK_LABEL = "regression-only"


@dataclass(frozen=True)
class AttemptLabel:
    """Caller-supplied labels for one attempt (by attempt_id).

    ``severity`` is the caller's severity label for the subject (e.g.
    "critical"/"high"/"medium"/"low"/"informational"); ``None`` means
    unlabelled.  ``is_true_finding`` is True/False/None (unknown).
    ``benchmark_saturated`` marks a subject drawn from a saturated public
    benchmark so it can be labelled regression-only.
    """

    attempt_id: str
    severity: str | None = None
    is_true_finding: bool | None = None
    benchmark_saturated: bool = False


@dataclass(frozen=True)
class RiskSensitiveMetrics:
    total: int
    completions: int
    critical_misses: int
    false_review_burden: int
    by_lane: dict[str, int]
    by_assistance: dict[str, int]
    completions_by_lane: dict[str, int]
    completions_by_assistance: dict[str, int]
    critical_misses_by_lane: dict[str, int]
    false_review_burden_by_lane: dict[str, int]
    lanes_present: tuple[str, ...]
    assistance_present: tuple[str, ...]
    saturated_subjects: tuple[str, ...]
    saturated_label: str


def _label_index(labels: Sequence[AttemptLabel] | None) -> dict[str, AttemptLabel]:
    index: dict[str, AttemptLabel] = {}
    if not labels:
        return index
    for label in labels:
        if not isinstance(label, AttemptLabel):
            raise TypeError("labels must be AttemptLabel instances")
        if label.attempt_id in index:
            raise ValueError(f"duplicate label for attempt_id {label.attempt_id!r}")
        index[label.attempt_id] = label
    return index


def _is_high_severity(label: AttemptLabel | None) -> bool:
    return label is not None and label.severity in HIGH_SEVERITIES


def compute_risk_sensitive_metrics(
    rows: Sequence[Mapping[str, object]],
    labels: Sequence[AttemptLabel] | None = None,
    *,
    saturated_benchmark_label: str = SATURATED_BENCHMARK_LABEL,
) -> RiskSensitiveMetrics:
    """Compute risk-sensitive metrics over ``rows`` (all attempts retained).

    ``labels`` optionally supplies per-attempt severity/truth/benchmark flags
    keyed by attempt_id.  Attempts without a label contribute to the
    denominator and to lane/assistance counts but not to critical-miss or
    false-review-burden numerators (unknown stays unknown, never an all-clear).
    """
    if not isinstance(rows, (list, tuple)) or any(
        not isinstance(item, Mapping) for item in rows
    ):
        raise TypeError("rows must be a list or tuple of row objects")

    label_index = _label_index(labels)

    total = len(rows)
    completions = 0
    critical_misses = 0
    false_review_burden = 0

    by_lane: Counter[str] = Counter()
    by_assistance: Counter[str] = Counter()
    completions_by_lane: Counter[str] = Counter()
    completions_by_assistance: Counter[str] = Counter()
    critical_misses_by_lane: Counter[str] = Counter()
    false_review_burden_by_lane: Counter[str] = Counter()

    saturated_subjects: list[str] = []

    for row in rows:
        lane = row.get("lane")
        assistance = row.get("assistance")
        attempt_class = row.get("attempt_class")
        attempt_id = row.get("attempt_id")
        subject = row.get("subject")

        if lane not in LANES:
            raise ValueError(f"unknown lane {lane!r}")
        if assistance not in ASSISTANCE:
            raise ValueError(f"unknown assistance {assistance!r}")
        if attempt_class not in ATTEMPT_CLASSES:
            raise ValueError(f"unknown attempt_class {attempt_class!r}")

        by_lane[lane] += 1
        by_assistance[assistance] += 1

        completed = attempt_class == COMPLETION
        if completed:
            completions += 1
            completions_by_lane[lane] += 1
            completions_by_assistance[assistance] += 1

        label = label_index.get(attempt_id) if isinstance(attempt_id, str) else None

        # Critical miss: high-severity TRUE finding not completed.
        if (
            label is not None
            and label.is_true_finding is True
            and _is_high_severity(label)
            and not completed
        ):
            critical_misses += 1
            critical_misses_by_lane[lane] += 1

        # False review burden: completed attempt on a benign/non-finding subject.
        if completed and label is not None and label.is_true_finding is False:
            false_review_burden += 1
            false_review_burden_by_lane[lane] += 1

        if label is not None and label.benchmark_saturated and isinstance(
            subject, str
        ):
            saturated_subjects.append(subject)

    return RiskSensitiveMetrics(
        total=total,
        completions=completions,
        critical_misses=critical_misses,
        false_review_burden=false_review_burden,
        by_lane=dict(sorted(by_lane.items())),
        by_assistance=dict(sorted(by_assistance.items())),
        completions_by_lane=dict(sorted(completions_by_lane.items())),
        completions_by_assistance=dict(sorted(completions_by_assistance.items())),
        critical_misses_by_lane=dict(sorted(critical_misses_by_lane.items())),
        false_review_burden_by_lane=dict(sorted(false_review_burden_by_lane.items())),
        lanes_present=tuple(sorted(by_lane)),
        assistance_present=tuple(sorted(by_assistance)),
        saturated_subjects=tuple(sorted(set(saturated_subjects))),
        saturated_label=saturated_benchmark_label,
    )


__all__ = [
    "AttemptLabel",
    "HIGH_SEVERITIES",
    "RiskSensitiveMetrics",
    "SATURATED_BENCHMARK_LABEL",
    "compute_risk_sensitive_metrics",
]
