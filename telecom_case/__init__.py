"""Telecom assurance case validation (TEL-01..TEL-09).

Validates that a telecom assurance case document carries the required
structure for a governed telecom specialization case.  Pure and fail-closed.
"""

from .case import (
    TelecomCaseError,
    TelecomCaseResult,
    validate_telecom_case,
    TELECOM_CASE_VERSION,
    REQUIRED_TEL_FIELDS,
    TEL_MODULES,
)

__all__ = [
    "TelecomCaseError",
    "TelecomCaseResult",
    "validate_telecom_case",
    "TELECOM_CASE_VERSION",
    "REQUIRED_TEL_FIELDS",
    "TEL_MODULES",
]
