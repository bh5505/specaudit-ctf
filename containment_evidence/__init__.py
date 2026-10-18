"""Structural checks for declared containment-result records.

Checks required control names, reference fields and reported outcomes. A
positive result means those declared records satisfy this helper's format;
it does not authenticate measurements, enforce containment, or satisfy SAFE-01.
Run and retain the existing containment suite separately. No network,
subprocess, clock reads or stored module state.
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
