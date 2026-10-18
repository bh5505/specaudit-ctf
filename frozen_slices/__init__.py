"""Frozen local intelligence slices (DATA-01 / DATA-02).

Structural-only: validates that a candidate frozen vulnerability- or
rule-intelligence slice carries the required admission, provenance,
read-only and denied-egress evidence within digest, stable-id, reference,
and timestamp bounds. Pure and fail-closed: missing or inconsistent
evidence is a validation failure, never an all-clear. No network, no
subprocess, no clock reads, no stored module state. Frozen timestamps may
be old: no freshness or currentness claim is made, and source
provenance/declared restrictions remain structural assertions only.
"""

from .slices import (
    FrozenSliceError,
    FrozenSliceResult,
    validate_vuln_slice,
    validate_rule_slice,
    FROZEN_SLICE_LIMITS,
    SLICE_VERSION,
)

__all__ = [
    "FrozenSliceError",
    "FrozenSliceResult",
    "validate_vuln_slice",
    "validate_rule_slice",
    "FROZEN_SLICE_LIMITS",
    "SLICE_VERSION",
]
