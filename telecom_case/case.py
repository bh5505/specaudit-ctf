"""Telecom assurance case validation (TEL-01..TEL-09)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

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


def _nonempty(v: Any) -> bool:
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, (list, tuple, Mapping)):
        return len(v) > 0
    return v is not None


def validate_telecom_case(doc: Any) -> TelecomCaseResult:
    reasons: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []

    if not isinstance(doc, Mapping):
        raise TelecomCaseError("case must be a mapping")

    for f in REQUIRED_TEL_FIELDS:
        if f not in doc:
            missing.append(f)
            reasons.append(f"missing field: {f}")

    extra = set(doc) - REQUIRED_TEL_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(extra)}")

    if "tel_module" in doc:
        tm = doc.get("tel_module")
        if tm not in TEL_MODULES:
            invalid.append("tel_module")
            reasons.append(f"tel_module must be one of {sorted(TEL_MODULES)}")

    for f in ("architecture", "trust_zones", "management_plane", "telemetry",
              "criteria", "threat_model", "procedure", "evidence", "limitations",
              "conclusion"):
        if f in doc and not _nonempty(doc.get(f)):
            invalid.append(f)
            reasons.append(f"{f} must be nonempty")

    if "criteria" in doc and isinstance(doc.get("criteria"), (list, tuple)):
        if not all(isinstance(x, str) and x.strip() for x in doc["criteria"]):
            invalid.append("criteria")
            reasons.append("criteria entries must be nonempty strings")

    valid = not missing and not invalid and not extra and len(reasons) == 0
    return TelecomCaseResult(
        version=TELECOM_CASE_VERSION,
        valid=valid,
        missing=tuple(sorted(missing)),
        invalid=tuple(sorted(set(invalid))),
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
