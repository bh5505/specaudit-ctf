"""Frozen slice validation for DATA-01 (vuln) and DATA-02 (rule).

Structural-only check: validates shape, digest/reference/timestamp bounds,
and declared read-only/denied-egress restriction flags. Source provenance
and declared restrictions are structural assertions only. Frozen timestamps
may be old: this module reads no clock and makes no freshness or
currentness claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from capability_records import (
    is_reference,
    is_reference_list,
    is_sha256_digest,
    is_source_timestamp,
    is_stable_id,
)

SLICE_VERSION = "specaudit.ctf.frozen-slice.v1"

FROZEN_SLICE_LIMITS: tuple[str, ...] = (
    "Structural declarations only; source bytes, record counts and empirical read/egress restrictions are unverified.",
    "No clock is read; old source timestamps can be structurally valid without establishing freshness.",
    "Stale and unknown behavior is declared text; no source admission or fallback authority is established.",
)

_REQUIRED_VULN_KEYS = frozenset(
    {
        "slice_id",
        "source_id",
        "source_revision",
        "source_timestamp",
        "snapshot_digest",
        "record_count",
        "records_digest",
        "read_only",
        "denied_egress_proof",
        "stale_semantics",
        "unknown_semantics",
        "negative_controls",
        "hosted_fallback",
    }
)
_REQUIRED_RULE_KEYS = frozenset(
    {
        "slice_id",
        "source_id",
        "source_revision",
        "source_timestamp",
        "snapshot_digest",
        "record_count",
        "records_digest",
        "read_only",
        "no_generation",
        "no_index_mutation",
        "no_deployment",
        "no_hosted_fallback",
        "missing_telemetry_cases",
        "negative_controls",
    }
)


class FrozenSliceError(ValueError):
    """Raised when a slice fails validation."""


@dataclass(frozen=True)
class FrozenSliceResult:
    kind: str
    valid: bool
    reasons: tuple[str, ...]
    limits: tuple[str, ...] = FROZEN_SLICE_LIMITS


def _validate_common(slice_doc: Any, kind: str) -> list[str]:
    reasons: list[str] = []
    if not isinstance(slice_doc, Mapping):
        return ["slice must be a mapping"]
    required = _REQUIRED_VULN_KEYS if kind == "vuln" else _REQUIRED_RULE_KEYS
    missing = required - set(slice_doc)
    if missing:
        reasons.append(f"missing keys: {sorted(missing)}")
    extra = set(slice_doc) - required
    if extra:
        reasons.append(f"unexpected keys: {sorted(map(repr, extra))}")
    if reasons:
        return reasons

    if not is_stable_id(slice_doc["slice_id"]):
        reasons.append("slice_id must be a bounded stable id")
    if not is_stable_id(slice_doc["source_id"]):
        reasons.append("source_id must be a bounded stable id")
    if not is_reference(slice_doc["source_revision"]):
        reasons.append("source_revision must be a bounded reference")
    if not is_source_timestamp(slice_doc["source_timestamp"]):
        reasons.append(
            "source_timestamp must be a strict RFC3339 timestamp "
            "with an explicit zone"
        )
    if not is_sha256_digest(slice_doc["snapshot_digest"]):
        reasons.append("snapshot_digest must be sha256:<64 lowercase hex>")
    if not is_sha256_digest(slice_doc["records_digest"]):
        reasons.append("records_digest must be sha256:<64 lowercase hex>")
    rc = slice_doc["record_count"]
    if not isinstance(rc, int) or isinstance(rc, bool) or rc < 1:
        reasons.append("record_count must be positive int")
    return reasons


def validate_vuln_slice(slice_doc: Any) -> FrozenSliceResult:
    """Validate a frozen vuln slice's shape and declared restrictions.

    Structural-only: no clock read, no freshness claim (old timestamps are
    structurally valid), and provenance/restriction fields are checked as
    bounded text, not as proof of the underlying property.
    """
    reasons = _validate_common(slice_doc, "vuln")
    if reasons:
        return FrozenSliceResult("vuln", False, tuple(reasons))
    d = slice_doc
    if d["read_only"] is not True:
        reasons.append("read_only must be true")
    if not is_reference(d["denied_egress_proof"]):
        reasons.append("denied_egress_proof must be a bounded reference")
    if not is_reference(d["stale_semantics"]):
        reasons.append("stale_semantics must be a bounded reference")
    if not is_reference(d["unknown_semantics"]):
        reasons.append("unknown_semantics must be a bounded reference")
    if not is_reference_list(d["negative_controls"], allow_empty=False):
        reasons.append(
            "negative_controls must be a nonempty bounded list "
            "of bounded references"
        )
    if d["hosted_fallback"] is not False:
        reasons.append("hosted_fallback must be false")
    return FrozenSliceResult("vuln", not reasons, tuple(reasons))


def validate_rule_slice(slice_doc: Any) -> FrozenSliceResult:
    """Validate a frozen rule slice's shape and declared restrictions.

    Structural-only: no clock read, no freshness claim (old timestamps are
    structurally valid), and provenance/restriction fields are checked as
    bounded text, not as proof of the underlying property.
    """
    reasons = _validate_common(slice_doc, "rule")
    if reasons:
        return FrozenSliceResult("rule", False, tuple(reasons))
    d = slice_doc
    for flag in ("read_only", "no_generation", "no_index_mutation", "no_deployment", "no_hosted_fallback"):
        if d[flag] is not True:
            reasons.append(f"{flag} must be true")
    if not is_reference_list(d["missing_telemetry_cases"], allow_empty=False):
        reasons.append(
            "missing_telemetry_cases must be a nonempty bounded list "
            "of bounded references"
        )
    if not is_reference_list(d["negative_controls"], allow_empty=False):
        reasons.append(
            "negative_controls must be a nonempty bounded list "
            "of bounded references"
        )
    return FrozenSliceResult("rule", not reasons, tuple(reasons))


__all__ = [
    "FROZEN_SLICE_LIMITS",
    "FrozenSliceError",
    "FrozenSliceResult",
    "SLICE_VERSION",
    "validate_rule_slice",
    "validate_vuln_slice",
]
