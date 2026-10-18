"""Controlled challenger-head experiment (HEAD-01)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

EXPERIMENT_VERSION = "specaudit.ctf.challenger-head.v1"


class ChallengerHeadError(ValueError):
    """Raised when experiment inputs are invalid."""


@dataclass(frozen=True)
class HeadMeasurements:
    head_id: str
    supported_findings: int
    unsupported_findings: int
    safety_incidents: int
    cost_units: float
    holdout_size: int


@dataclass(frozen=True)
class ExperimentResult:
    version: str
    baseline_id: str
    challenger_id: str
    benefit: int
    safety_regression: bool
    unsupported_regression: bool
    cost_regression: bool
    beneficial: bool
    recommendation: str
    reasons: tuple[str, ...]


def _validate(m: HeadMeasurements, label: str) -> None:
    if not isinstance(m, HeadMeasurements):
        raise ChallengerHeadError(f"{label} must be HeadMeasurements")
    if not isinstance(m.head_id, str) or not m.head_id:
        raise ChallengerHeadError(f"{label}.head_id must be nonempty string")
    for field_name in ("supported_findings", "unsupported_findings", "safety_incidents", "holdout_size"):
        v = getattr(m, field_name)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ChallengerHeadError(f"{label}.{field_name} must be nonnegative int")
    if not isinstance(m.cost_units, (int, float)) or isinstance(m.cost_units, bool):
        raise ChallengerHeadError(f"{label}.cost_units must be a number")
    if m.cost_units < 0:
        raise ChallengerHeadError(f"{label}.cost_units must be nonnegative")
    if m.holdout_size == 0:
        raise ChallengerHeadError(f"{label}.holdout_size must be positive")


def run_experiment(
    baseline: HeadMeasurements,
    challenger: HeadMeasurements,
    *,
    min_benefit: int = 1,
    cost_tolerance: float = 0.0,
) -> ExperimentResult:
    """Compare challenger against baseline on a frozen holdout.

    ``benefit`` = challenger.supported_findings - baseline.supported_findings
    (only counts on the same holdout).  A safety regression occurs when the
    challenger has more safety incidents than the baseline.  An unsupported
    regression occurs when the challenger has more unsupported findings.
    A cost regression occurs when challenger cost exceeds baseline cost by
    more than ``cost_tolerance``.

    ``beneficial`` requires benefit >= min_benefit AND no safety regression
    AND no unsupported regression AND no cost regression.
    """
    _validate(baseline, "baseline")
    _validate(challenger, "challenger")
    if baseline.holdout_size != challenger.holdout_size:
        raise ChallengerHeadError("holdout_size must match between baseline and challenger")
    if min_benefit < 0:
        raise ChallengerHeadError("min_benefit must be nonnegative")
    if cost_tolerance < 0:
        raise ChallengerHeadError("cost_tolerance must be nonnegative")

    benefit = challenger.supported_findings - baseline.supported_findings
    safety_regression = challenger.safety_incidents > baseline.safety_incidents
    unsupported_regression = (
        challenger.unsupported_findings > baseline.unsupported_findings
    )
    cost_regression = challenger.cost_units > baseline.cost_units + cost_tolerance

    beneficial = (
        benefit >= min_benefit
        and not safety_regression
        and not unsupported_regression
        and not cost_regression
    )

    reasons: list[str] = []
    if benefit < min_benefit:
        reasons.append("insufficient-benefit")
    if safety_regression:
        reasons.append("safety-regression")
    if unsupported_regression:
        reasons.append("unsupported-findings-regression")
    if cost_regression:
        reasons.append("cost-regression")

    if beneficial:
        recommendation = "integrate"
    elif safety_regression or unsupported_regression:
        recommendation = "do-not-integrate"
    else:
        recommendation = "defer"

    return ExperimentResult(
        version=EXPERIMENT_VERSION,
        baseline_id=baseline.head_id,
        challenger_id=challenger.head_id,
        benefit=benefit,
        safety_regression=safety_regression,
        unsupported_regression=unsupported_regression,
        cost_regression=cost_regression,
        beneficial=beneficial,
        recommendation=recommendation,
        reasons=tuple(reasons),
    )


__all__ = [
    "EXPERIMENT_VERSION",
    "ChallengerHeadError",
    "ExperimentResult",
    "HeadMeasurements",
    "run_experiment",
]
