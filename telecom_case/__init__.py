"""Structural telecom assurance case validation for TEL-01..TEL-09.

A valid result verifies bounded section shapes only, without establishing
control effectiveness, actual governed case delivery or telecom activation.
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
