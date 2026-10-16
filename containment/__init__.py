"""Operator-side containment rehearsal for repo arms (SAFE-01, empirical).

This package is deliberately OUT of the installed wheel (like ``safety/``):
it is a development/research surface, not a shipping claim. It rehearses,
against the repo's own reader arms, the two-layer containment an operator
needs before pointing any arm at hostile inputs:

* the trusted acquisition gate (:mod:`reader_evidence`) applied before
  dispatch, and
* a PEP 578 audit-hook enforcement plane (:mod:`containment.enforcer`)
  installed in a child interpreter before target code runs.

This is NOT an OS sandbox; see ``containment/enforcer.py`` and
``containment/README.md`` for the honest residual-risk statement.
"""
from __future__ import annotations

from containment.profile import OperatorProfile, ProfileError
from containment.harness import (
    CaseResult,
    RosterEntry,
    run_case,
    run_matrix,
    snapshot_scratch,
    stop_case,
)

__all__ = [
    "OperatorProfile",
    "ProfileError",
    "CaseResult",
    "RosterEntry",
    "run_case",
    "run_matrix",
    "snapshot_scratch",
    "stop_case",
]
