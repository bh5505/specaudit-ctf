"""Formal assessment validation (U-ASSESS)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

FORMAL_ASSESSMENT_VERSION = "specaudit.ctf.formal-assessment.v1"

REQUIRED_ASSESSMENT_FIELDS = frozenset(
    {
        "assessment_id",
        "named_reviews",
        "learner_context_separation",
        "calibration",
        "operator_dry_run",
        "answer_key_isolation",
        "challenge_authoring_contract",
        "reset_retention",
    }
)


class FormalAssessmentError(ValueError):
    """Raised when an assessment document is structurally invalid."""


@dataclass(frozen=True)
class FormalAssessmentResult:
    version: str
    valid: bool
    missing: tuple[str, ...]
    invalid: tuple[str, ...]
    reasons: tuple[str, ...]


def _nonempty(v: Any) -> bool:
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, (list, tuple, Mapping)):
        return len(v) > 0
    return v is not None


def validate_formal_assessment(doc: Any) -> FormalAssessmentResult:
    reasons: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []

    if not isinstance(doc, Mapping):
        raise FormalAssessmentError("assessment must be a mapping")

    for f in REQUIRED_ASSESSMENT_FIELDS:
        if f not in doc:
            missing.append(f)
            reasons.append(f"missing field: {f}")

    extra = set(doc) - REQUIRED_ASSESSMENT_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(extra)}")

    # named_reviews must be a nonempty list of nonempty strings.
    nr = doc.get("named_reviews")
    if "named_reviews" in doc:
        if not isinstance(nr, (list, tuple)) or not nr or any(
            not isinstance(x, str) or not x.strip() for x in nr
        ):
            invalid.append("named_reviews")
            reasons.append("named_reviews must be nonempty list of nonempty strings")

    # learner_context_separation must be a mapping with evidence.
    lcs = doc.get("learner_context_separation")
    if "learner_context_separation" in doc:
        if not isinstance(lcs, Mapping) or not lcs:
            invalid.append("learner_context_separation")
            reasons.append("learner_context_separation must be nonempty mapping")
        elif not any(isinstance(v, str) and v.strip() for v in lcs.values()):
            invalid.append("learner_context_separation")
            reasons.append("learner_context_separation must carry evidence")

    # calibration must be nonempty.
    cal = doc.get("calibration")
    if "calibration" in doc and not _nonempty(cal):
        invalid.append("calibration")
        reasons.append("calibration must be nonempty")

    # operator_dry_run must be a mapping with status pass.
    dr = doc.get("operator_dry_run")
    if "operator_dry_run" in doc:
        if not isinstance(dr, Mapping) or dr.get("status") != "pass":
            invalid.append("operator_dry_run")
            reasons.append("operator_dry_run must be mapping with status 'pass'")

    # answer_key_isolation must be a mapping with evidence.
    aki = doc.get("answer_key_isolation")
    if "answer_key_isolation" in doc:
        if not isinstance(aki, Mapping) or not aki:
            invalid.append("answer_key_isolation")
            reasons.append("answer_key_isolation must be nonempty mapping")

    valid = not missing and not invalid and not extra and len(reasons) == 0
    return FormalAssessmentResult(
        version=FORMAL_ASSESSMENT_VERSION,
        valid=valid,
        missing=tuple(sorted(missing)),
        invalid=tuple(sorted(set(invalid))),
        reasons=tuple(reasons),
    )


__all__ = [
    "FORMAL_ASSESSMENT_VERSION",
    "FormalAssessmentError",
    "FormalAssessmentResult",
    "REQUIRED_ASSESSMENT_FIELDS",
    "validate_formal_assessment",
]
