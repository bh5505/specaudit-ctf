"""Containment evidence verification (SAFE-01).

Validates an evidence bundle recording empirical containment test outcomes
(denied egress, no mutation, sandbox boundaries, ground-truth isolation,
cleanup) and reports whether SAFE-01 acceptance criteria are satisfied.
Pure and fail-closed: missing or failed controls are not satisfied.  No
network, no subprocess, no clock reads, no stored module state.
"""

from .verify import (
    ContainmentEvidenceError,
    ContainmentResult,
    verify_containment,
    CONTAINMENT_VERSION,
)

__all__ = [
    "ContainmentEvidenceError",
    "ContainmentResult",
    "verify_containment",
    "CONTAINMENT_VERSION",
]
