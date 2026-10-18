"""Frozen slice validation for DATA-01 (vuln) and DATA-02 (rule)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

SLICE_VERSION = "specaudit.ctf.frozen-slice.v1"

_DIGEST_RE_PREFIX = "sha256:"
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


def _is_digest(v: Any) -> bool:
    return isinstance(v, str) and v.startswith(_DIGEST_RE_PREFIX) and len(v) == 71


def _validate_common(slice_doc: Mapping[str, Any], kind: str) -> list[str]:
    reasons: list[str] = []
    if not isinstance(slice_doc, Mapping):
        return ["slice must be a mapping"]
    required = _REQUIRED_VULN_KEYS if kind == "vuln" else _REQUIRED_RULE_KEYS
    missing = required - set(slice_doc)
    if missing:
        reasons.append(f"missing keys: {sorted(missing)}")
    extra = set(slice_doc) - required
    if extra:
        reasons.append(f"unexpected keys: {sorted(extra)}")
    if reasons:
        return reasons

    if not isinstance(slice_doc["slice_id"], str) or not slice_doc["slice_id"]:
        reasons.append("slice_id must be nonempty string")
    if not isinstance(slice_doc["source_id"], str) or not slice_doc["source_id"]:
        reasons.append("source_id must be nonempty string")
    if not isinstance(slice_doc["source_revision"], str) or not slice_doc[
        "source_revision"
    ]:
        reasons.append("source_revision must be nonempty string")
    ts = slice_doc["source_timestamp"]
    if ts is not None and (not isinstance(ts, str) or not ts):
        reasons.append("source_timestamp must be string or null")
    if not _is_digest(slice_doc["snapshot_digest"]):
        reasons.append("snapshot_digest must be sha256:<64 hex>")
    if not _is_digest(slice_doc["records_digest"]):
        reasons.append("records_digest must be sha256:<64 hex>")
    rc = slice_doc["record_count"]
    if not isinstance(rc, int) or isinstance(rc, bool) or rc < 1:
        reasons.append("record_count must be positive int")
    return reasons


def validate_vuln_slice(slice_doc: Any) -> FrozenSliceResult:
    reasons = _validate_common(slice_doc, "vuln")
    if reasons:
        return FrozenSliceResult("vuln", False, tuple(reasons))
    d = slice_doc
    if d["read_only"] is not True:
        reasons.append("read_only must be true")
    if not isinstance(d["denied_egress_proof"], str) or not d["denied_egress_proof"]:
        reasons.append("denied_egress_proof must be nonempty string")
    if not isinstance(d["stale_semantics"], str) or not d["stale_semantics"]:
        reasons.append("stale_semantics must be nonempty string")
    if not isinstance(d["unknown_semantics"], str) or not d["unknown_semantics"]:
        reasons.append("unknown_semantics must be nonempty string")
    nc = d["negative_controls"]
    if not isinstance(nc, (list, tuple)) or not nc:
        reasons.append("negative_controls must be nonempty list")
    elif not all(isinstance(x, str) and x for x in nc):
        reasons.append("negative_controls entries must be nonempty strings")
    if d["hosted_fallback"] is not False:
        reasons.append("hosted_fallback must be false")
    if d["source_timestamp"] is None:
        reasons.append("source_timestamp must be known for a frozen slice")
    return FrozenSliceResult("vuln", not reasons, tuple(reasons))


def validate_rule_slice(slice_doc: Any) -> FrozenSliceResult:
    reasons = _validate_common(slice_doc, "rule")
    if reasons:
        return FrozenSliceResult("rule", False, tuple(reasons))
    d = slice_doc
    for flag in ("read_only", "no_generation", "no_index_mutation", "no_deployment", "no_hosted_fallback"):
        if d[flag] is not True:
            reasons.append(f"{flag} must be true")
    mt = d["missing_telemetry_cases"]
    if not isinstance(mt, (list, tuple)) or not mt:
        reasons.append("missing_telemetry_cases must be nonempty list")
    elif not all(isinstance(x, str) and x for x in mt):
        reasons.append("missing_telemetry_cases entries must be nonempty strings")
    nc = d["negative_controls"]
    if not isinstance(nc, (list, tuple)) or not nc:
        reasons.append("negative_controls must be nonempty list")
    elif not all(isinstance(x, str) and x for x in nc):
        reasons.append("negative_controls entries must be nonempty strings")
    if d["source_timestamp"] is None:
        reasons.append("source_timestamp must be known for a frozen slice")
    return FrozenSliceResult("rule", not reasons, tuple(reasons))


__all__ = [
    "FrozenSliceError",
    "FrozenSliceResult",
    "SLICE_VERSION",
    "validate_rule_slice",
    "validate_vuln_slice",
]
