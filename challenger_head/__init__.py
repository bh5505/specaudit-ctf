"""Comparison-only challenger measurements, with no experiment authority.

The retained run_experiment API computes from caller-supplied measurements on
one declared frozen holdout identity/digest. It executes nothing and grants no
integration or promotion authority; recommendations are numeric suggestions.
See :mod:`challenger_head.experiment` for input and limitation details.
"""

from .experiment import (
    ChallengerHeadError,
    ExperimentResult,
    HeadMeasurements,
    run_experiment,
    EXPERIMENT_VERSION,
)

__all__ = [
    "ChallengerHeadError", "ExperimentResult", "HeadMeasurements", "run_experiment", "EXPERIMENT_VERSION",
]
