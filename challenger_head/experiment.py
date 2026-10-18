"""Comparison-only arithmetic over caller measurements (HEAD-01 scaffold).

The historical run_experiment name is retained, but this function executes no
experiment. Inputs are unauthenticated caller measurements and frozen-holdout
assertions. Both heads must name the same nonempty holdout_id and valid
sha256:<64 lowercase hex> holdout_digest, the same positive holdout_size, and
holdout_frozen=True. Equal sizes alone establish no identity. These checks do
not prove unused holdout status, provenance, prerequisites or budget equality.

The retained recommendation vocabulary (integrate / do-not-integrate / defer)
is a numeric comparison suggestion only. Every result explicitly carries
comparison_only=True and recommendation_authority='none'; it grants no runtime,
experiment, integration, deployment or promotion authority and closes no gate.
No network, subprocess, persistence, clock reads or automatic promotion.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re

EXPERIMENT_VERSION = "specaudit.ctf.challenger-head.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ChallengerHeadError(ValueError):
    """Raised when comparison inputs are invalid."""


@dataclass(frozen=True)
class HeadMeasurements:
    head_id: str
    supported_findings: int
    unsupported_findings: int
    safety_incidents: int
    cost_units: float
    holdout_size: int
    holdout_id: str | None = None
    holdout_digest: str | None = None
    holdout_frozen: bool = False


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
    comparison_only: bool
    recommendation_authority: str
    measurement_source: str
    holdout_id: str
    holdout_digest: str
    limitations: tuple[str, ...]


def _text(value: object) -> bool:
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 256
            and not any(ord(char) < 32 for char in value))


def _nonnegative_number(value: object, label: str) -> None:
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or value < 0):
        raise ChallengerHeadError(f"{label} must be a finite nonnegative number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ChallengerHeadError(f"{label} must be a finite nonnegative number")


def _validate(m: HeadMeasurements, label: str) -> None:
    if not isinstance(m, HeadMeasurements):
        raise ChallengerHeadError(f"{label} must be HeadMeasurements")
    if not _text(m.head_id):
        raise ChallengerHeadError(f"{label}.head_id must be nonempty bounded text")
    for field_name in ("supported_findings", "unsupported_findings", "safety_incidents", "holdout_size"):
        value = getattr(m, field_name)
        if type(value) is not int or value < 0:
            raise ChallengerHeadError(f"{label}.{field_name} must be nonnegative int")
    _nonnegative_number(m.cost_units, f"{label}.cost_units")
    if m.holdout_size == 0:
        raise ChallengerHeadError(f"{label}.holdout_size must be positive")
    if not _text(m.holdout_id):
        raise ChallengerHeadError(f"{label}.holdout_id must be nonempty bounded text")
    if not isinstance(m.holdout_digest, str) or not _DIGEST.fullmatch(m.holdout_digest):
        raise ChallengerHeadError(f"{label}.holdout_digest must be sha256:<64 lowercase hex>")
    if type(m.holdout_frozen) is not bool or not m.holdout_frozen:
        raise ChallengerHeadError(f"{label}.holdout_frozen must be True")


def run_experiment(
    baseline: HeadMeasurements,
    challenger: HeadMeasurements,
    *,
    min_benefit: int = 1,
    cost_tolerance: float = 0.0,
) -> ExperimentResult:
    """Compare declared measurements; do not execute or authorize an experiment.

    Benefit is the difference in supported-finding counts. beneficial means
    this declared numeric threshold is met with no higher safety incidents,
    unsupported findings or cost beyond the finite nonnegative tolerance.
    Prerequisite and empirical gates remain outside this comparison helper.
    """
    _validate(baseline, "baseline")
    _validate(challenger, "challenger")
    if baseline.holdout_size != challenger.holdout_size:
        raise ChallengerHeadError("holdout_size must match between baseline and challenger")
    if (baseline.holdout_id, baseline.holdout_digest) != (challenger.holdout_id, challenger.holdout_digest):
        raise ChallengerHeadError("both heads must bind the same frozen holdout identity and digest")
    if type(min_benefit) is not int or min_benefit < 0:
        raise ChallengerHeadError("min_benefit must be a nonnegative int")
    _nonnegative_number(cost_tolerance, "cost_tolerance")
    benefit = challenger.supported_findings - baseline.supported_findings
    safety_regression = challenger.safety_incidents > baseline.safety_incidents
    unsupported_regression = challenger.unsupported_findings > baseline.unsupported_findings
    cost_regression = challenger.cost_units > baseline.cost_units + cost_tolerance
    beneficial = (benefit >= min_benefit and not safety_regression
                  and not unsupported_regression and not cost_regression)
    reasons = []
    if benefit < min_benefit:
        reasons.append("insufficient-benefit")
    if safety_regression:
        reasons.append("safety-regression")
    if unsupported_regression:
        reasons.append("unsupported-findings-regression")
    if cost_regression:
        reasons.append("cost-regression")
    recommendation = ("integrate" if beneficial else "do-not-integrate"
                      if safety_regression or unsupported_regression else "defer")
    return ExperimentResult(
        version=EXPERIMENT_VERSION, baseline_id=baseline.head_id, challenger_id=challenger.head_id,
        benefit=benefit, safety_regression=safety_regression, unsupported_regression=unsupported_regression,
        cost_regression=cost_regression, beneficial=beneficial, recommendation=recommendation,
        reasons=tuple(reasons), comparison_only=True, recommendation_authority="none",
        measurement_source="caller-supplied-unauthenticated", holdout_id=baseline.holdout_id,
        holdout_digest=baseline.holdout_digest,
        limitations=("numeric-comparison-only-no-experiment-executed", "no-integration-or-promotion-authority",
                     "caller-measurements-and-frozen-holdout-assertions-not-authenticated",
                     "prerequisites-unused-holdout-status-and-equal-capabilities-budget-not-established"),
    )


__all__ = ["EXPERIMENT_VERSION", "ChallengerHeadError", "ExperimentResult", "HeadMeasurements", "run_experiment"]
