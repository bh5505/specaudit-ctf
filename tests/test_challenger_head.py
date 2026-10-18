"""Causal tests for HEAD-01 challenger-head experiment."""

from __future__ import annotations

import pytest

from challenger_head import HeadMeasurements, run_experiment


def _h(head_id, supported=5, unsupported=1, safety=0, cost=1.0, holdout=10):
    return HeadMeasurements(head_id, supported, unsupported, safety, cost, holdout)


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
    with pytest.raises(Exception):
        run_experiment(_h("base", holdout=10), _h("chall", holdout=5))


def test_negative_cost_raises():
    with pytest.raises(Exception):
        run_experiment(_h("base"), _h("chall", cost=-1.0))


def test_zero_holdout_raises():
    with pytest.raises(Exception):
        run_experiment(_h("base", holdout=0), _h("chall", holdout=0))
