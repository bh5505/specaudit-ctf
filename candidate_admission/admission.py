"""Per-candidate admission closure validation (GOV-01)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

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


class CandidateAdmissionError(ValueError):
    """Raised when a candidate-admission record is structurally invalid."""


@dataclass(frozen=True)
class CandidateAdmissionResult:
    version: str
    valid: bool
    missing: tuple[str, ...]
    invalid: tuple[str, ...]
    reasons: tuple[str, ...]


def _nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _nonempty_list(v: Any) -> bool:
    return isinstance(v, (list, tuple)) and len(v) > 0


def validate_candidate_admission(record: Any) -> CandidateAdmissionResult:
    reasons: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []

    if not isinstance(record, Mapping):
        raise CandidateAdmissionError("record must be a mapping")

    for f in REQUIRED_ADMISSION_FIELDS:
        if f not in record:
            missing.append(f)
            reasons.append(f"missing field: {f}")

    extra = set(record) - REQUIRED_ADMISSION_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(extra)}")

    # String fields.
    for f in ("candidate_id", "pinned_revision", "code_license", "data_rights",
              "named_owner", "data_classification", "action_surface", "egress",
              "cost_behavior", "cleanup_semantics", "provenance_semantics",
              "promotion_evidence"):
        if f in record and not _nonempty_str(record.get(f)):
            invalid.append(f)
            reasons.append(f"{f} must be nonempty string")

    # Hash list.
    if "revision_hashes" in record:
        v = record.get("revision_hashes")
        if not _nonempty_list(v) or not all(_nonempty_str(x) for x in v):
            invalid.append("revision_hashes")
            reasons.append("revision_hashes must be nonempty list of nonempty strings")

    # Side effects: list.
    if "side_effects" in record:
        v = record.get("side_effects")
        if not isinstance(v, (list, tuple)):
            invalid.append("side_effects")
            reasons.append("side_effects must be a list")
        elif any(not _nonempty_str(x) for x in v):
            invalid.append("side_effects")
            reasons.append("side_effects entries must be nonempty strings")

    # Tests/cases: nonempty lists.
    for f in ("offline_tests", "denied_egress_tests", "negative_cases",
              "inconclusive_cases", "regression_case"):
        if f in record:
            v = record.get(f)
            if isinstance(v, str):
                if not v.strip():
                    invalid.append(f)
                    reasons.append(f"{f} must be nonempty")
            elif isinstance(v, (list, tuple)):
                if not v:
                    invalid.append(f)
                    reasons.append(f"{f} must be nonempty")
            else:
                invalid.append(f)
                reasons.append(f"{f} must be string or nonempty list")

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
    "CandidateAdmissionError",
    "CandidateAdmissionResult",
    "REQUIRED_ADMISSION_FIELDS",
    "validate_candidate_admission",
]
