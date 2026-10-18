"""Structural telecom case records for TEL-01..TEL-09.

case_id is a bounded stable ID. Trust zones, criteria, evidence references and
limitations are nonempty flat reference lists. Narrative sections are bounded
nonempty recursive text/list/mapping content. No case assets, evidence truth,
control effectiveness, governed admission or telecom activation are verified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from capability_records import is_concrete_content, is_reference_list, is_stable_id

TELECOM_CASE_VERSION = "specaudit.ctf.telecom-case.v1"

TEL_MODULES = frozenset(
    {
        "TEL-01", "TEL-02", "TEL-03", "TEL-04", "TEL-05",
        "TEL-06", "TEL-07", "TEL-08", "TEL-09",
    }
)

REQUIRED_TEL_FIELDS = frozenset(
    {
        "case_id",
        "tel_module",
        "architecture",
        "trust_zones",
        "management_plane",
        "telemetry",
        "criteria",
        "threat_model",
        "procedure",
        "evidence",
        "limitations",
        "conclusion",
    }
)


class TelecomCaseError(ValueError):
    """Raised when a telecom case document is structurally invalid."""


@dataclass(frozen=True)
class TelecomCaseResult:
    version: str
    valid: bool
    missing: tuple[str, ...]
    invalid: tuple[str, ...]
    reasons: tuple[str, ...]
    limits: tuple[str, ...] = (
        "Structural case completeness only; evidence truth and control effectiveness are unverified.",
        "No governed TEL case delivery, admission or telecom activation is established.",
    )


_REFERENCE_LIST_FIELDS = frozenset({"trust_zones", "criteria", "evidence", "limitations"})


def validate_telecom_case(doc: Any) -> TelecomCaseResult:
    """Check section values without interpreting a case's assurance conclusion."""
    if not isinstance(doc, Mapping):
        raise TelecomCaseError("case must be a mapping")
    missing = sorted(REQUIRED_TEL_FIELDS - set(doc))
    reasons = [f"missing field: {field}" for field in missing]
    invalid: list[str] = []
    extra = set(doc) - REQUIRED_TEL_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(map(repr, extra))}")
    for field in sorted(REQUIRED_TEL_FIELDS & set(doc)):
        value = doc[field]
        if field == "case_id":
            accepted = is_stable_id(value)
        elif field == "tel_module":
            accepted = isinstance(value, str) and value in TEL_MODULES
        elif field in _REFERENCE_LIST_FIELDS:
            accepted = is_reference_list(value)
        else:
            accepted = is_concrete_content(value)
        if not accepted:
            invalid.append(field)
            reasons.append(f"{field} does not meet its bounded structural contract")
    return TelecomCaseResult(
        version=TELECOM_CASE_VERSION,
        valid=not reasons,
        missing=tuple(missing),
        invalid=tuple(invalid),
        reasons=tuple(reasons),
    )


__all__ = [
    "REQUIRED_TEL_FIELDS",
    "TELECOM_CASE_VERSION",
    "TEL_MODULES",
    "TelecomCaseError",
    "TelecomCaseResult",
    "validate_telecom_case",
]
