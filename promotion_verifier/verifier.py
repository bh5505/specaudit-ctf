"""Promotion verifier (GOV-01)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

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


class PromotionVerifierError(ValueError):
    """Raised when a promotion record is structurally invalid."""


@dataclass(frozen=True)
class PromotionResult:
    version: str
    valid: bool
    missing: tuple[str, ...]
    invalid: tuple[str, ...]
    reasons: tuple[str, ...]


def _is_digest(v: Any) -> bool:
    return isinstance(v, str) and v.startswith("sha256:") and len(v) == 71


def verify_promotion(record: Any) -> PromotionResult:
    """Verify a promotion-event record's shape and completeness.

    Fail-closed: any missing field, invalid digest, empty reviewer/path, or
    invalid state/regression result makes the record invalid.
    """
    reasons: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []

    if not isinstance(record, Mapping):
        raise PromotionVerifierError("promotion record must be a mapping")

    missing = [f for f in REQUIRED_PROMOTION_FIELDS if f not in record]
    if missing:
        reasons.append(f"missing fields: {sorted(missing)}")

    extra = set(record) - REQUIRED_PROMOTION_FIELDS
    if extra:
        reasons.append(f"unexpected fields: {sorted(extra)}")

    # If missing, still try to validate present fields.
    def check(field, cond, msg):
        nonlocal reasons, invalid
        if field in record and not cond(record.get(field)):
            invalid.append(field)
            reasons.append(msg)

    if "subject_digest" in record:
        check("subject_digest", _is_digest, "subject_digest must be sha256:<64 hex>")
    if "contract_digest" in record:
        check("contract_digest", _is_digest, "contract_digest must be sha256:<64 hex>")
    if "implementation_revision" in record:
        check(
            "implementation_revision",
            lambda v: isinstance(v, str) and len(v) >= 7,
            "implementation_revision must be nonempty string (>=7 chars)",
        )
    if "reviewer" in record:
        check(
            "reviewer",
            lambda v: isinstance(v, str) and bool(v.strip()),
            "reviewer must be nonempty string",
        )
    if "exercised_path" in record:
        check(
            "exercised_path",
            lambda v: isinstance(v, str) and bool(v.strip()),
            "exercised_path must be nonempty string",
        )
    if "regression_result" in record:
        check(
            "regression_result",
            lambda v: v in VALID_REGRESSION_RESULTS,
            f"regression_result must be one of {sorted(VALID_REGRESSION_RESULTS)}",
        )
    if "supported_versions" in record:
        check(
            "supported_versions",
            lambda v: isinstance(v, (list, tuple)) and len(v) > 0
            and all(isinstance(x, str) and x for x in v),
            "supported_versions must be nonempty list of nonempty strings",
        )
    if "source_revisions" in record:
        check(
            "source_revisions",
            lambda v: isinstance(v, (list, tuple)) and len(v) > 0
            and all(isinstance(x, str) and x for x in v),
            "source_revisions must be nonempty list of nonempty strings",
        )
    if "accepted_limitations" in record:
        check(
            "accepted_limitations",
            lambda v: isinstance(v, (list, tuple)),
            "accepted_limitations must be a list",
        )
    if "promotion_state" in record:
        check(
            "promotion_state",
            lambda v: v in VALID_PROMOTION_STATES,
            f"promotion_state must be one of {sorted(VALID_PROMOTION_STATES)}",
        )

    # Regression result must be "passed" for a valid promotion.
    if record.get("regression_result") == "failed":
        invalid.append("regression_result")
        reasons.append("regression_result must be 'passed' for a valid promotion")

    # accepted_limitations entries must be strings.
    al = record.get("accepted_limitations")
    if isinstance(al, (list, tuple)) and any(not isinstance(x, str) for x in al):
        invalid.append("accepted_limitations")
        reasons.append("accepted_limitations entries must be strings")

    valid = not missing and not invalid and not extra and not reasons
    # reasons may include missing/extra already; recompute valid cleanly
    valid = (
        not missing
        and not invalid
        and not extra
        and len(reasons) == 0
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
    "REQUIRED_PROMOTION_FIELDS",
    "PromotionResult",
    "PromotionVerifierError",
    "verify_promotion",
]
