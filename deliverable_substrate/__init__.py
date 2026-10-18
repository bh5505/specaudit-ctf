"""Structural component and artifact-reference validation.

A valid result does not establish PACK-01 admission, asset custody, bytes,
learner/key access isolation, reset execution or assessment completion.
"""

from .substrate import (
    DeliverableError,
    DeliverableResult,
    validate_deliverable,
    DELIVERABLE_VERSION,
    REQUIRED_COMPONENTS,
)

__all__ = [
    "DeliverableError",
    "DeliverableResult",
    "validate_deliverable",
    "DELIVERABLE_VERSION",
    "REQUIRED_COMPONENTS",
]
