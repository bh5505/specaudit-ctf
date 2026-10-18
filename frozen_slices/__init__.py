"""Frozen local intelligence slices (DATA-01 / DATA-02).

Validates that a candidate frozen vulnerability- or rule-intelligence slice
carries the required admission, provenance, read-only and denied-egress
evidence.  Pure and fail-closed: missing or inconsistent evidence is a
validation failure, never an all-clear.  No network, no subprocess, no
clock reads, no stored module state.
"""

from .slices import (
    FrozenSliceError,
    FrozenSliceResult,
    validate_vuln_slice,
    validate_rule_slice,
    SLICE_VERSION,
)

__all__ = [
    "FrozenSliceError",
    "FrozenSliceResult",
    "validate_vuln_slice",
    "validate_rule_slice",
    "SLICE_VERSION",
]
