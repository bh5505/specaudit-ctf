"""Per-candidate admission closure validation (GOV-01).

Structural-only check: validates the shape and completeness of a
candidate-admission record (required fields, digest/reference/list bounds).
It establishes no authenticity, execution, or promotion claim about the
candidate itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from capability_records import (
    is_reference,
    is_reference_list,
    is_sha256_digest,
    is_stable_id,
)

CANDIDATE_ADMISSION_VERSION = "specaudit.ctf.candidate-admission.v1"

REQUIRED_ADMISSION_FIELDS = frozenset(
    {
        "candidate_id",
        "pinned_revision",
        "revision_hashes",
        "code_license",
        "data_rights",
        "named_owner",
        "data_classification",
        "action_surface",
        "side_effects",
        "egress",
        "cost_behavior",
        "cleanup_semantics",
        "offline_tests",
        "denied_egress_tests",
        "provenance_semantics",
        "negative_cases",
        "inconclusive_cases",
        "regression_case",
        "promotion_evidence",
    }
)

CANDIDATE_ADMISSION_LIMITS: tuple[str, ...] = (
    "Structural completeness only; references, rights and test outcomes are unverified.",
    "No governance admission, maintained capability or execution authority is established.",
)

_STABLE_ID_FIELDS = ("candidate_id",)

_REFERENCE_FIELDS = (
    "pinned_revision",
    "code_license",
    "data_rights",
    "named_owner",
    "data_classification",
    "action_surface",
    "egress",
    "cost_behavior",
    "cleanup_semantics",
    "provenance_semantics",
    "promotion_evidence",
)

_CASE_FIELDS = (
    "offline_tests",
    "denied_egress_tests",
    "negative_cases",
    "inconclusive_cases",
    "regression_case",
)


class CandidateAdmissionError(ValueError):
    """Raised when a candidate-admission record is structurally invalid."""


@dataclass(frozen=True)
class CandidateAdmissionResult:
    version: str
    valid: bool
    missing: tuple[str, ...]
    invalid: tuple[str, ...]
    reasons: tuple[str, ...]
    limits: tuple[str, ...] = CANDIDATE_ADMISSION_LIMITS


def _is_digest_list(v: Any) -> bool:
    return (
        isinstance(v, (list, tuple))
        and 1 <= len(v) <= 256
        and all(is_sha256_digest(x) for x in v)
    )


def _is_case_value(v: Any) -> bool:
    # Scalar-or-reference-list compatibility: one bounded reference string,
    # or a nonempty bounded list of bounded references. Placeholders
    # (None, empty, nested, untrimmed, overlong, control-bearing) fail.
    if isinstance(v, str):
        return is_reference(v)
    return is_reference_list(v, allow_empty=False)


def validate_candidate_admission(record: Any) -> CandidateAdmissionResult:
    """Validate a candidate-admission record's shape and completeness.

    Structural-only: fail-closed on missing fields, unexpected fields,
    non-digest hashes, non-stable candidate id, unbounded references, or
    placeholder case entries. Proves nothing about the candidate beyond
    record shape.
    """
    reasons: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []

    if not isinstance(record, Mapping):
        raise CandidateAdmissionError("record must be a mapping")

    for f in sorted(REQUIRED_ADMISSION_FIELDS):
        if f not in record:
            missing.append(f)
            reasons.append(f"missing field: {f}")

    extra = set(record) - REQUIRED_ADMISSION_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(map(repr, extra))}")

    for f in _STABLE_ID_FIELDS:
        if f in record and not is_stable_id(record.get(f)):
            invalid.append(f)
            reasons.append(f"{f} must be a bounded stable id")

    for f in _REFERENCE_FIELDS:
        if f in record and not is_reference(record.get(f)):
            invalid.append(f)
            reasons.append(f"{f} must be a bounded reference")

    if "revision_hashes" in record:
        if not _is_digest_list(record.get("revision_hashes")):
            invalid.append("revision_hashes")
            reasons.append(
                "revision_hashes must be a bounded nonempty list "
                "of exact lowercase sha256 digests"
            )

    if "side_effects" in record:
        if not is_reference_list(record.get("side_effects"), allow_empty=True):
            invalid.append("side_effects")
            reasons.append(
                "side_effects must be a (possibly empty) bounded list "
                "of bounded references"
            )

    for f in _CASE_FIELDS:
        if f in record and not _is_case_value(record.get(f)):
            invalid.append(f)
            reasons.append(
                f"{f} must be a bounded reference or a bounded nonempty "
                "list of bounded references"
            )

    valid = not missing and not invalid and not extra and len(reasons) == 0
    return CandidateAdmissionResult(
        version=CANDIDATE_ADMISSION_VERSION,
        valid=valid,
        missing=tuple(sorted(missing)),
        invalid=tuple(sorted(set(invalid))),
        reasons=tuple(reasons),
    )


__all__ = [
    "CANDIDATE_ADMISSION_VERSION",
    "CANDIDATE_ADMISSION_LIMITS",
    "CandidateAdmissionError",
    "CandidateAdmissionResult",
    "REQUIRED_ADMISSION_FIELDS",
    "validate_candidate_admission",
]
