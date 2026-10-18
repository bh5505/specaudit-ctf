"""Structural typed assessment-reference validation.

A valid result does not authenticate named human reviews, verify calibration,
prove learner/key isolation or execute a dry-run. Existing qualification and
isolation machinery remains authoritative for those separate gates.
"""

from .assessment import (
    FormalAssessmentError,
    FormalAssessmentResult,
    validate_formal_assessment,
    FORMAL_ASSESSMENT_VERSION,
    REQUIRED_ASSESSMENT_FIELDS,
)

__all__ = [
    "FormalAssessmentError",
    "FormalAssessmentResult",
    "validate_formal_assessment",
    "FORMAL_ASSESSMENT_VERSION",
    "REQUIRED_ASSESSMENT_FIELDS",
]
