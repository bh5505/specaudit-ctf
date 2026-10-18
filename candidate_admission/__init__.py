"""Per-candidate admission closure validation (GOV-01).

Validates that a candidate-admission record carries the required evidence
fields (pinned revision/hashes, license/data rights, named owner, data
classification, exact action surface, side effects/egress/cost/cleanup,
offline/denied-egress tests, provenance/uncertainty, negative/inconclusive
cases, regression case, promotion evidence).  Pure and fail-closed.
"""

from .admission import (
    CandidateAdmissionError,
    CandidateAdmissionResult,
    validate_candidate_admission,
    CANDIDATE_ADMISSION_VERSION,
    REQUIRED_ADMISSION_FIELDS,
)

__all__ = [
    "CandidateAdmissionError",
    "CandidateAdmissionResult",
    "validate_candidate_admission",
    "CANDIDATE_ADMISSION_VERSION",
    "REQUIRED_ADMISSION_FIELDS",
]
