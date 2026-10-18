"""Causal tests for HEAD-01 challenger-head experiment."""

from __future__ import annotations

import pytest

from challenger_head import ChallengerHeadError, HeadMeasurements, run_experiment


def _h(head_id, supported=5, unsupported=1, safety=0, cost=1.0, holdout=10):
    return HeadMeasurements(head_id, supported, unsupported, safety, cost, holdout,
                            "frozen-holdout-1", "sha256:" + "1" * 64, True)


def test_beneficial():
    r = run_experiment(_h("base", supported=3), _h("chall", supported=6))
    assert r.beneficial is True
    assert r.recommendation == "integrate"
    assert r.benefit == 3


def test_safety_regression_blocks():
    r = run_experiment(_h("base", safety=0), _h("chall", supported=6, safety=2))
    assert r.beneficial is False
    assert r.safety_regression is True
    assert r.recommendation == "do-not-integrate"


def test_unsupported_regression_blocks():
    r = run_experiment(_h("base", unsupported=1), _h("chall", supported=6, unsupported=3))
    assert r.beneficial is False
    assert r.unsupported_regression is True


def test_cost_regression_defers():
    r = run_experiment(_h("base", cost=1.0), _h("chall", supported=6, cost=5.0), cost_tolerance=0.0)
    assert r.beneficial is False
    assert r.cost_regression is True
    assert r.recommendation == "defer"


def test_insufficient_benefit_defers():
    r = run_experiment(_h("base", supported=5), _h("chall", supported=5), min_benefit=1)
    assert r.beneficial is False
    assert "insufficient-benefit" in r.reasons


def test_holdout_mismatch_raises():
    with pytest.raises(ChallengerHeadError):
        run_experiment(_h("base", holdout=10), _h("chall", holdout=5))


def test_negative_cost_raises():
    with pytest.raises(ChallengerHeadError):
        run_experiment(_h("base"), _h("chall", cost=-1.0))


def test_zero_holdout_raises():
    with pytest.raises(ChallengerHeadError):
        run_experiment(_h("base", holdout=0), _h("chall", holdout=0))


def test_comparison_is_explicitly_caller_declared_without_experiment_authority():
    result = run_experiment(_h("base", supported=3), _h("chall", supported=6))
    assert result.beneficial and result.recommendation == "integrate"
    assert result.comparison_only is True and result.recommendation_authority == "none"
    assert result.measurement_source == "caller-supplied-unauthenticated"
    assert result.holdout_id == "frozen-holdout-1" and result.holdout_digest == "sha256:" + "1" * 64
    assert "numeric-comparison-only-no-experiment-executed" in result.limitations
    assert "no-integration-or-promotion-authority" in result.limitations


@pytest.mark.parametrize("cost", [float("nan"), float("inf"), float("-inf"), True, "1", None, -1, 10 ** 1000])
@pytest.mark.parametrize("side", ["baseline", "challenger"])
def test_nonfinite_invalid_or_negative_costs_rejected(cost, side):
    base, challenger = _h("base"), _h("chall", supported=6)
    if side == "baseline":
        base = _h("base", cost=cost)
    else:
        challenger = _h("chall", cost=cost, supported=6)
    with pytest.raises(ChallengerHeadError):
        run_experiment(base, challenger)


@pytest.mark.parametrize("tolerance", [float("nan"), float("inf"), float("-inf"), True, "1", None, -1, 10 ** 1000])
def test_invalid_tolerance_cannot_bypass_cost_requirement(tolerance):
    with pytest.raises(ChallengerHeadError):
        run_experiment(_h("base"), _h("chall", supported=6, cost=1_000_000), cost_tolerance=tolerance)


@pytest.mark.parametrize("threshold", [True, False, 1.0, "1", None, -1, float("nan"), float("inf")])
def test_invalid_benefit_threshold_rejected(threshold):
    with pytest.raises(ChallengerHeadError):
        run_experiment(_h("base"), _h("chall"), min_benefit=threshold)


@pytest.mark.parametrize("field", ["supported_findings", "unsupported_findings", "safety_incidents", "holdout_size"])
@pytest.mark.parametrize("value", [True, 1.0, -1, None])
def test_measurement_counts_require_nonnegative_integers(field, value):
    from dataclasses import replace
    with pytest.raises(ChallengerHeadError):
        run_experiment(_h("base"), replace(_h("chall"), **{field: value}))


@pytest.mark.parametrize("field,value", [
    ("head_id", ""), ("head_id", " "), ("head_id", True),
    ("holdout_id", ""), ("holdout_id", None), ("holdout_id", "different"),
    ("holdout_digest", None), ("holdout_digest", "sha256:" + "x" * 64),
    ("holdout_digest", "sha256:" + "2" * 64), ("holdout_digest", "1" * 64),
    ("holdout_frozen", False), ("holdout_frozen", 1), ("holdout_frozen", "true"),
])
def test_unknown_unfrozen_or_different_holdout_rejected_despite_equal_size(field, value):
    from dataclasses import replace
    with pytest.raises(ChallengerHeadError):
        run_experiment(_h("base"), replace(_h("chall"), **{field: value}))


def test_legacy_size_only_measurements_leave_comparison_unmet():
    with pytest.raises(ChallengerHeadError, match="holdout_id"):
        run_experiment(HeadMeasurements("base", 3, 0, 0, 1.0, 10),
                       HeadMeasurements("chall", 6, 0, 0, 1.0, 10))


def test_finite_cost_tolerance_is_still_supported():
    result = run_experiment(_h("base", cost=1.0), _h("chall", supported=6, cost=1.5), cost_tolerance=0.5)
    assert result.beneficial and not result.cost_regression
