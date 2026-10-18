"""Controlled challenger-head experiment harness (HEAD-01).

Compares a baseline head against a challenger head on a frozen holdout and
reports benefit, safety regressions, unsupported findings and cost.  Pure
and deterministic: the caller supplies all measurements.  No network, no
subprocess, no clock reads, no stored module state.

An experiment is only "beneficial" when benefit is demonstrated WITHOUT
worse safety, unsupported findings, or cost.  Otherwise the recommendation
is "do not integrate" (deferral is a valid, recorded outcome).
"""

from .experiment import (
    ChallengerHeadError,
    ExperimentResult,
    HeadMeasurements,
    run_experiment,
    EXPERIMENT_VERSION,
)

__all__ = [
    "ChallengerHeadError",
    "ExperimentResult",
    "HeadMeasurements",
    "run_experiment",
    "EXPERIMENT_VERSION",
]
