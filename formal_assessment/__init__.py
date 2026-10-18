"""Formal assessment validation (U-ASSESS).

Validates that a formal (instructor-hidden) assessment package carries the
required components: named reviews, learner-context separation, calibration,
operator dry-run evidence, and answer-key isolation.  Pure and fail-closed.
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
