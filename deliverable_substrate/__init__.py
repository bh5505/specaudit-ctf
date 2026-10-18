"""Deliverable substrate validation (PACK-01 exit intent).

Validates that a learning-pack deliverable carries all required components:
learner brief, evidence manifest, instructor key, benign control, limitations,
rubric, and reset/retention instructions.  Pure and fail-closed.
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
