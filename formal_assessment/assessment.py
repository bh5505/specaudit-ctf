"""Validate structural assessment references, not U-ASSESS completion.

Named reviews are {reviewer, review_ref} records. Calibration is a named,
non-seed reviewer plus evidence_refs. A dry-run needs status="pass", result_ref
and evidence_refs. Both isolation records need state="proven" and evidence_refs;
that state is a caller declaration, not a verified isolation result. The
qualification vocabulary is reused without replacing its loaders or gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from capability_records import is_reference, is_reference_list, is_stable_id

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
    limits: tuple[str, ...] = (
        "Structural references only; named reviewer identity and evidence authenticity are unverified.",
        "Declared isolation, calibration and dry-run outcomes are not verified execution or assessment completion.",
    )


def _closed_record(value: Any, fields: set[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == fields


def _named_reviews(value: Any) -> bool:
    return (
        isinstance(value, (list, tuple))
        and 0 < len(value) <= 256
        and all(
            _closed_record(review, {"reviewer", "review_ref"})
            and is_reference(review["reviewer"])
            and is_reference(review["review_ref"])
            for review in value
        )
    )


def _isolation(value: Any) -> bool:
    return (
        _closed_record(value, {"state", "evidence_refs"})
        and value["state"] == "proven"
        and is_reference_list(value["evidence_refs"])
    )


def _calibration(value: Any) -> bool:
    return (
        _closed_record(value, {"reviewer", "evidence_refs"})
        and is_reference(value["reviewer"])
        and value["reviewer"] != "calibration-seed"
        and is_reference_list(value["evidence_refs"])
    )


def _dry_run(value: Any) -> bool:
    return (
        _closed_record(value, {"status", "result_ref", "evidence_refs"})
        and value["status"] == "pass"
        and is_reference(value["result_ref"])
        and is_reference_list(value["evidence_refs"])
    )


def validate_formal_assessment(doc: Any) -> FormalAssessmentResult:
    """Validate bounded typed references without resolving their artifacts."""
    if not isinstance(doc, Mapping):
        raise FormalAssessmentError("assessment must be a mapping")
    missing = sorted(REQUIRED_ASSESSMENT_FIELDS - set(doc))
    reasons = [f"missing field: {field}" for field in missing]
    invalid: list[str] = []
    extra = set(doc) - REQUIRED_ASSESSMENT_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(map(repr, extra))}")
    validators = {
        "assessment_id": is_stable_id,
        "named_reviews": _named_reviews,
        "learner_context_separation": _isolation,
        "calibration": _calibration,
        "operator_dry_run": _dry_run,
        "answer_key_isolation": _isolation,
        "challenge_authoring_contract": is_reference,
        "reset_retention": is_reference,
    }
    for field in sorted(REQUIRED_ASSESSMENT_FIELDS & set(doc)):
        if not validators[field](doc[field]):
            invalid.append(field)
            reasons.append(f"{field} does not meet its bounded structural contract")
    return FormalAssessmentResult(
        version=FORMAL_ASSESSMENT_VERSION,
        valid=not reasons,
        missing=tuple(missing),
        invalid=tuple(invalid),
        reasons=tuple(reasons),
    )


__all__ = [
    "FORMAL_ASSESSMENT_VERSION",
    "FormalAssessmentError",
    "FormalAssessmentResult",
    "REQUIRED_ASSESSMENT_FIELDS",
    "validate_formal_assessment",
]
