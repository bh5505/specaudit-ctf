"""Caller-adjudicated risk metrics over every ledger row (EVAL-01).

Completion describes execution, never correctness. Critical misses are true
high/critical subjects adjudicated ``absent``; false review burden is benign
subjects adjudicated ``present``. ``unknown`` (the default) contributes to
explicit unknown coverage, never either numerator. Neither attempt_class nor
outcome (including failed grades, which can mean extra findings) supplies a
prediction. Truth, severity and disposition are independent caller labels;
this module authenticates none of them. Verify the ledger separately first.

Every failure, refusal, timeout, stop and completion remains in the denominator.
Lane/assistance marginals and joint strata are reported. Optional evaluation_split
is a label separate from the frozen ledger's historical assistance enum; legacy
``tuned``/``held-out`` assistance values are retained without reinterpretation.
Repeated attempt ids are legitimate ledger retries only with distinct row_digest
bindings. Labels for those retries must identify a row_digest, so one outcome
cannot silently label every retry. No I/O, clock reads, ledger changes or gates.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
from typing import Mapping, Sequence

from .ledger import ATTEMPT_CLASSES, ASSISTANCE, COMPLETION, LANES

HIGH_SEVERITIES = frozenset({"critical", "high"})
SEVERITIES = HIGH_SEVERITIES | {"medium", "low", "informational", "none"}
DISPOSITIONS = frozenset({"present", "absent", "unknown"})
EVALUATION_SPLITS = frozenset({"development", "tuned", "held-out", "regression-only", "unknown"})
SATURATED_BENCHMARK_LABEL = "regression-only"
_ATTEMPT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{7,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AttemptLabel:
    """Unauthenticated per-row labels, independent of execution outcome.

    is_true_finding and severity supply ground truth. adjudicated_disposition
    supplies the finding prediction (present / absent / unknown), not a grade
    pass/fail. row_digest is required when attempt_id has multiple ledger rows.
    evaluation_split independently labels development/tuned/held-out/regression-
    only/unknown; omitting it reports unknown rather than inferring from assistance.
    """

    attempt_id: str
    severity: str | None = None
    is_true_finding: bool | None = None
    benchmark_saturated: bool = False
    adjudicated_disposition: str = "unknown"
    evaluation_split: str = "unknown"
    row_digest: str | None = None


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
    labelled_attempts: int
    adjudicated_attempts: int
    unknown_disposition: int
    unknown_truth: int
    unknown_severity: int
    evaluable_critical_subjects: int
    unknown_critical_disposition: int
    evaluable_benign_subjects: int
    unknown_benign_disposition: int
    by_lane_assistance: dict[str, dict[str, int]]
    completions_by_lane_assistance: dict[str, dict[str, int]]
    critical_misses_by_lane_assistance: dict[str, dict[str, int]]
    false_review_burden_by_lane_assistance: dict[str, dict[str, int]]
    adjudicated_by_lane_assistance: dict[str, dict[str, int]]
    unknown_disposition_by_lane_assistance: dict[str, dict[str, int]]
    by_evaluation_split: dict[str, int]
    limitations: tuple[str, ...]


def _enum(value: object, choices: frozenset[str], label: str) -> None:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"unknown {label} {value!r}")


def _id(value: object) -> None:
    if not isinstance(value, str) or not _ATTEMPT_ID.fullmatch(value):
        raise ValueError("attempt_id must match ledger identity format")


def _digest(value: object) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("row_digest must be sha256:<64 lowercase hex>")


def _label_index(labels, rows):
    index = {}
    rows_by_id = {}
    row_keys = set()
    for row in rows:
        rows_by_id.setdefault(row["attempt_id"], []).append(row.get("row_digest"))
        row_keys.add((row["attempt_id"], row.get("row_digest")))
    if labels is None:
        return index
    if not isinstance(labels, (list, tuple)):
        raise TypeError("labels must be a list or tuple of AttemptLabel instances")
    for label in labels:
        if not isinstance(label, AttemptLabel):
            raise TypeError("labels must be AttemptLabel instances")
        _id(label.attempt_id)
        if label.severity is not None:
            _enum(label.severity, SEVERITIES, "severity")
        if label.is_true_finding is not None and type(label.is_true_finding) is not bool:
            raise ValueError("is_true_finding must be True, False or None")
        if type(label.benchmark_saturated) is not bool:
            raise ValueError("benchmark_saturated must be a boolean")
        _enum(label.adjudicated_disposition, DISPOSITIONS, "adjudicated_disposition")
        _enum(label.evaluation_split, EVALUATION_SPLITS, "evaluation_split")
        if label.row_digest is not None:
            _digest(label.row_digest)
        key = (label.attempt_id, label.row_digest)
        if label.attempt_id not in rows_by_id or (label.row_digest is not None and key not in row_keys):
            raise ValueError(f"orphan label for {label.attempt_id!r}")
        if len(rows_by_id[label.attempt_id]) > 1 and label.row_digest is None:
            raise ValueError("retry labels require a row_digest")
        # A digest-specific label and an id-only label for the same unique row
        # are duplicates too; do not silently choose either one.
        resolved_digest = label.row_digest if label.row_digest is not None else rows_by_id[label.attempt_id][0]
        resolved = (label.attempt_id, resolved_digest)
        if resolved in index:
            raise ValueError(f"duplicate label for {label.attempt_id!r}")
        index[resolved] = label
    return index


def _joint(counter):
    out: dict[str, dict[str, int]] = {}
    for (lane, assistance), count in sorted(counter.items()):
        out.setdefault(lane, {})[assistance] = count
    return out


def compute_risk_sensitive_metrics(
    rows: Sequence[Mapping[str, object]],
    labels: Sequence[AttemptLabel] | None = None,
    *,
    saturated_benchmark_label: str = SATURATED_BENCHMARK_LABEL,
) -> RiskSensitiveMetrics:
    """Compute descriptive counts; unknown labels remain visible and unevaluated.

    Risk numerators need truth AND explicit disposition (plus high/critical
    severity for misses). A zero with unknown coverage is not an all-clear.
    All counts, including coverage, use rows rather than distinct subjects.
    saturated_benchmark_label must remain regression-only.
    """
    if not isinstance(rows, (list, tuple)) or any(not isinstance(row, Mapping) for row in rows):
        raise TypeError("rows must be a list or tuple of row objects")
    if saturated_benchmark_label != SATURATED_BENCHMARK_LABEL:
        raise ValueError("saturated benchmarks must be labelled regression-only")
    identities = set()
    ids = Counter()
    for row in rows:
        _id(row.get("attempt_id"))
        for key, choices in (("lane", LANES), ("assistance", ASSISTANCE), ("attempt_class", ATTEMPT_CLASSES)):
            _enum(row.get(key), choices, key)
        if not isinstance(row.get("subject"), str) or not row["subject"].strip():
            raise ValueError("subject must be nonempty text")
        if row.get("row_digest") is not None:
            _digest(row["row_digest"])
        identity = (row["attempt_id"], row.get("row_digest"))
        if identity in identities:
            raise ValueError("duplicate row identity; retries require distinct row digests")
        identities.add(identity)
        ids[row["attempt_id"]] += 1
    if any(ids[row["attempt_id"]] > 1 and row.get("row_digest") is None for row in rows):
        raise ValueError("retry rows require distinct row digests")
    label_index = _label_index(labels, rows)
    counters = {name: Counter() for name in (
        "lane", "assistance", "complete_lane", "complete_assistance", "miss_lane", "false_lane",
        "joint", "complete_joint", "miss_joint", "false_joint", "adjudicated_joint", "unknown_joint", "split",
    )}
    completions = critical_misses = false_review_burden = 0
    labelled = adjudicated = unknown_truth = unknown_severity = 0
    evaluable_critical = unknown_critical = evaluable_benign = unknown_benign = 0
    saturated_subjects = set()
    for row in rows:
        lane, assistance = row["lane"], row["assistance"]
        joint = (lane, assistance)
        counters["lane"][lane] += 1
        counters["assistance"][assistance] += 1
        counters["joint"][joint] += 1
        if row["attempt_class"] == COMPLETION:
            completions += 1
            counters["complete_lane"][lane] += 1
            counters["complete_assistance"][assistance] += 1
            counters["complete_joint"][joint] += 1
        label = label_index.get((row["attempt_id"], row.get("row_digest")))
        labelled += label is not None
        disposition = label.adjudicated_disposition if label is not None else "unknown"
        known_disposition = disposition != "unknown"
        adjudicated += known_disposition
        counters["adjudicated_joint" if known_disposition else "unknown_joint"][joint] += 1
        unknown_truth += label is None or label.is_true_finding is None
        unknown_severity += label is None or label.severity is None
        counters["split"][label.evaluation_split if label else "unknown"] += 1
        if label is not None and label.is_true_finding is True and label.severity in HIGH_SEVERITIES:
            evaluable_critical += known_disposition
            unknown_critical += not known_disposition
            if disposition == "absent":
                critical_misses += 1
                counters["miss_lane"][lane] += 1
                counters["miss_joint"][joint] += 1
        if label is not None and label.is_true_finding is False:
            evaluable_benign += known_disposition
            unknown_benign += not known_disposition
            if disposition == "present":
                false_review_burden += 1
                counters["false_lane"][lane] += 1
                counters["false_joint"][joint] += 1
        if label is not None and label.benchmark_saturated:
            saturated_subjects.add(row["subject"])
    ordered = lambda name: dict(sorted(counters[name].items()))
    return RiskSensitiveMetrics(
        total=len(rows), completions=completions, critical_misses=critical_misses,
        false_review_burden=false_review_burden, by_lane=ordered("lane"), by_assistance=ordered("assistance"),
        completions_by_lane=ordered("complete_lane"), completions_by_assistance=ordered("complete_assistance"),
        critical_misses_by_lane=ordered("miss_lane"), false_review_burden_by_lane=ordered("false_lane"),
        lanes_present=tuple(sorted(counters["lane"])), assistance_present=tuple(sorted(counters["assistance"])),
        saturated_subjects=tuple(sorted(saturated_subjects)), saturated_label=saturated_benchmark_label,
        labelled_attempts=labelled, adjudicated_attempts=adjudicated, unknown_disposition=len(rows) - adjudicated,
        unknown_truth=unknown_truth, unknown_severity=unknown_severity,
        evaluable_critical_subjects=evaluable_critical, unknown_critical_disposition=unknown_critical,
        evaluable_benign_subjects=evaluable_benign, unknown_benign_disposition=unknown_benign,
        by_lane_assistance=_joint(counters["joint"]), completions_by_lane_assistance=_joint(counters["complete_joint"]),
        critical_misses_by_lane_assistance=_joint(counters["miss_joint"]),
        false_review_burden_by_lane_assistance=_joint(counters["false_joint"]),
        adjudicated_by_lane_assistance=_joint(counters["adjudicated_joint"]),
        unknown_disposition_by_lane_assistance=_joint(counters["unknown_joint"]), by_evaluation_split=ordered("split"),
        limitations=("caller-labels-are-unauthenticated", "execution-completion-is-not-correctness",
                     "unknown-label-coverage-is-not-an-all-clear", "ledger-integrity-not-verified-here"),
    )


__all__ = ["AttemptLabel", "HIGH_SEVERITIES", "RiskSensitiveMetrics", "SATURATED_BENCHMARK_LABEL",
           "compute_risk_sensitive_metrics", "DISPOSITIONS", "EVALUATION_SPLITS", "SEVERITIES"]
