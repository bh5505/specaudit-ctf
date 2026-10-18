"""Promotion verifier (GOV-01).

Structural-only check: validates a promotion-event record's shape and
completeness (digests, bounded references, list bounds, enum values, passed
regression). It authenticates no reviewer, executes no regression, verifies
no artifact/path existence, and grants no admission authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from capability_records import (
    is_reference,
    is_reference_list,
    is_sha256_digest,
)

PROMOTION_VERSION = "specaudit.ctf.promotion-verifier.v1"

REQUIRED_PROMOTION_FIELDS = frozenset(
    {
        "subject_digest",
        "contract_digest",
        "implementation_revision",
        "reviewer",
        "exercised_path",
        "regression_result",
        "supported_versions",
        "source_revisions",
        "accepted_limitations",
        "promotion_state",
    }
)

VALID_PROMOTION_STATES = frozenset({"selected", "admitted", "shipped"})
VALID_REGRESSION_RESULTS = frozenset({"passed", "failed"})

PROMOTION_LIMITS: tuple[str, ...] = (
    "Structural completeness only; reviewer authenticity and declared regression execution are unverified.",
    "Artifact/path existence and governance promotion authority are unverified.",
)


class PromotionVerifierError(ValueError):
    """Raised when a promotion record is structurally invalid."""


@dataclass(frozen=True)
class PromotionResult:
    version: str
    valid: bool
    missing: tuple[str, ...]
    invalid: tuple[str, ...]
    reasons: tuple[str, ...]
    limits: tuple[str, ...] = PROMOTION_LIMITS


def _safe_enum(value: Any, allowed: frozenset) -> bool:
    # Enums refuse unhashable values without raising: only an exact string
    # member is accepted.
    return isinstance(value, str) and value in allowed


def verify_promotion(record: Any) -> PromotionResult:
    """Verify a promotion-event record's shape and completeness.

    Structural-only and fail-closed: any missing field, unexpected field,
    non-digest hash, unbounded reference, placeholder list entry, invalid
    enum, or non-passed regression makes the record invalid. Records no
    judgement about author authenticity, regression execution, path
    existence, or admission proof.
    """
    reasons: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []

    if not isinstance(record, Mapping):
        raise PromotionVerifierError("promotion record must be a mapping")

    missing = sorted(REQUIRED_PROMOTION_FIELDS - set(record))
    if missing:
        reasons.append(f"missing fields: {sorted(missing)}")

    extra = set(record) - REQUIRED_PROMOTION_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(map(repr, extra))}")

    def check(field, cond, msg):
        nonlocal reasons, invalid
        if field in record and not cond(record.get(field)):
            invalid.append(field)
            reasons.append(msg)

    check(
        "subject_digest",
        is_sha256_digest,
        "subject_digest must be sha256:<64 lowercase hex>",
    )
    check(
        "contract_digest",
        is_sha256_digest,
        "contract_digest must be sha256:<64 lowercase hex>",
    )
    check(
        "implementation_revision",
        lambda v: is_reference(v) and len(v) >= 7,
        "implementation_revision must be a bounded reference (>=7 chars)",
    )
    check(
        "reviewer",
        is_reference,
        "reviewer must be a bounded reference",
    )
    check(
        "exercised_path",
        is_reference,
        "exercised_path must be a bounded reference",
    )
    check(
        "regression_result",
        lambda v: _safe_enum(v, VALID_REGRESSION_RESULTS),
        f"regression_result must be one of {sorted(VALID_REGRESSION_RESULTS)}",
    )
    check(
        "supported_versions",
        lambda v: is_reference_list(v, allow_empty=False),
        "supported_versions must be a nonempty bounded list "
        "of bounded references",
    )
    check(
        "source_revisions",
        lambda v: is_reference_list(v, allow_empty=False),
        "source_revisions must be a nonempty bounded list "
        "of bounded references",
    )
    check(
        "accepted_limitations",
        lambda v: is_reference_list(v, allow_empty=True),
        "accepted_limitations must be a (possibly empty) bounded list "
        "of bounded references",
    )
    check(
        "promotion_state",
        lambda v: _safe_enum(v, VALID_PROMOTION_STATES),
        f"promotion_state must be one of {sorted(VALID_PROMOTION_STATES)}",
    )

    # A promotion is valid only when the recorded regression result passed.
    if record.get("regression_result") == "failed":
        if "regression_result" not in invalid:
            invalid.append("regression_result")
        reasons.append("regression_result must be 'passed' for a valid promotion")

    valid = (
        not missing
        and not invalid
        and not extra
        and not reasons
    )
    return PromotionResult(
        version=PROMOTION_VERSION,
        valid=valid,
        missing=tuple(sorted(missing)),
        invalid=tuple(sorted(set(invalid))),
        reasons=tuple(reasons),
    )


__all__ = [
    "PROMOTION_VERSION",
    "PROMOTION_LIMITS",
    "REQUIRED_PROMOTION_FIELDS",
    "PromotionResult",
    "PromotionVerifierError",
    "verify_promotion",
]
