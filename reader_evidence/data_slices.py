"""First-party synthetic demo data slices (DATA-01/02).

A slice is a pinned snapshot with a bounded lifetime. Provenance is
first-party synthetic demo content. Since the 2026-10-14 operator
authorization (docs/governance/promotion-authorization-2026-10-14.md), R01
and R43 are admitted sources and these two slices carry ``admitted``
upstream admission for their narrow scope: the pinned first-party synthetic
slice bytes and format only. The upstream vulnify aggregate database and the
upstream rule corpora are NOT admitted and no upstream material is bundled.
Semantics fail closed: unknown lookups stay unknown, slices go stale after
``review_due``, and generation, mutation, and hosted fallback are each
refused. No ``extension.*`` imports: this package stays independent of the
runtime adapter surface.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json

# Computed over the shipped file bytes at authoring time; the test suite
# re-derives both digests from disk and fails if the pins drift.
_VULNIFY_SNAPSHOT_SHA256 = "sha256:a9a42f040c4a3c6fb761f9019736107e96ff6948c3f291f26ddb749026bcf62b"
_DETECTION_RULES_SHA256 = "sha256:c148a5185543f1d7c7c4d4c8bbd9f1659612f9e5b2844cba9822bbc4a2581fcf"

_SCHEMA_RULES = "specaudit.ctf.detection-rules.v1"
_RULE_FIELDS = {"rule_id", "name", "severity", "log_fields_required", "false_positive_notes"}
_SEVERITIES = ("info", "low", "medium", "high", "critical")


class DataSliceError(ValueError):
    """Typed slice refusal; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class DataSliceRecord:
    """Pin for one shipped demo slice, plus its fail-closed contract booleans."""

    slice_id: str
    purpose: str
    provenance: str
    upstream_admission: str
    pinned_path: str
    pinned_sha256: str
    as_of: str
    review_due: str
    unknown_lookup_stays_unknown: bool
    stale_after_review_due: bool
    no_generation: bool
    no_mutation: bool
    no_hosted_fallback: bool


_ADMITTED = "admitted"


def _demo_record(slice_id: str, purpose: str, pinned_path: str,
                 pinned_sha256: str, *, upstream_admission: str) -> DataSliceRecord:
    return DataSliceRecord(
        slice_id=slice_id,
        purpose=purpose,
        provenance="first-party-synthetic-demo",
        upstream_admission=upstream_admission,
        pinned_path=pinned_path,
        pinned_sha256=pinned_sha256,
        as_of="2026-10-13",
        review_due="2027-01-11",
        unknown_lookup_stays_unknown=True,
        stale_after_review_due=True,
        no_generation=True,
        no_mutation=True,
        no_hosted_fallback=True,
    )


def vulnify_demo_slice() -> DataSliceRecord:
    """Pin the shipped vulnify demo snapshot (DATA-01).

    Admitted under the 2026-10-14 operator authorization for the pinned
    first-party synthetic slice only; the upstream aggregate database stays
    outside the admission (see the R01 anchor in governance/check.py).
    """
    return _demo_record("vulnify-demo-snapshot", "offline vulnify.lookup demo input",
                        "extension/arms/vulnify/data/demo-vulnerability-snapshot.json",
                        _VULNIFY_SNAPSHOT_SHA256,
                        upstream_admission=_ADMITTED)


def detections_demo_slice() -> DataSliceRecord:
    """Pin the synthetic detection-rule index shipped in this package (DATA-02).

    Admitted under the 2026-10-14 operator authorization for the pinned
    first-party synthetic rules only; upstream rule corpora stay outside the
    admission (see the R43 anchor in governance/check.py).
    """
    return _demo_record("detections-demo-index", "offline detections demo rule index",
                        "reader_evidence/data/demo-detection-rules.json",
                        _DETECTION_RULES_SHA256,
                        upstream_admission=_ADMITTED)


def verify_slice_bytes(record: DataSliceRecord, data: bytes) -> None:
    """Digest gate: refuse bytes that do not match the pinned digest."""
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if digest != record.pinned_sha256:
        raise DataSliceError(
            "digest-mismatch",
            f"slice {record.slice_id} bytes do not match the pinned digest "
            f"{record.pinned_sha256}")


def check_freshness(record: DataSliceRecord, *, as_of: date) -> None:
    """Refuse a slice consulted after its review_due date; the boundary is fresh."""
    try:
        due = date.fromisoformat(record.review_due)
    except ValueError as exc:
        raise DataSliceError("stale-slice",
                             f"slice {record.slice_id} has an unparsable review_due") from exc
    if as_of > due:
        raise DataSliceError("stale-slice",
                             f"slice {record.slice_id} went stale on {record.review_due}")


def require_upstream_admission(record: DataSliceRecord) -> None:
    """Refuse any use that would treat a demo slice as admitted upstream data."""
    if record.upstream_admission != "admitted":
        raise DataSliceError(
            "admission-required",
            f"slice {record.slice_id} is {record.upstream_admission!r} upstream; "
            "an operator decision is required first")


def synthetic_rule_index(raw: bytes) -> tuple[dict, ...]:
    """Parse the pinned synthetic detection-rule fixture; malformed structure is
    ValueError (the digest gate above is the typed byte-level refusal). Lookups
    against the result are advisory demo data: unknown stays unknown."""
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("detection-rule index is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {"schema", "rules"}:
        raise ValueError("detection-rule index requires exactly schema and rules")
    if document["schema"] != _SCHEMA_RULES or not isinstance(document["rules"], list):
        raise ValueError("unsupported detection-rule schema or rules shape")
    rules: list[dict] = []
    seen: set[str] = set()
    for rule in document["rules"]:
        if not isinstance(rule, dict) or set(rule) != _RULE_FIELDS:
            raise ValueError("rule requires exactly the closed field set")
        for key in ("rule_id", "name", "false_positive_notes"):
            if not isinstance(rule[key], str) or not rule[key] or len(rule[key]) > 256:
                raise ValueError(f"rule {key} must be a nonempty bounded string")
        if rule["rule_id"] in seen:
            raise ValueError(f"duplicate rule id: {rule['rule_id']}")
        seen.add(rule["rule_id"])
        if rule["severity"] not in _SEVERITIES:
            raise ValueError(f"rule severity must be one of {_SEVERITIES}")
        fields = rule["log_fields_required"]
        if (not isinstance(fields, list) or not fields or len(fields) > 16
                or any(not isinstance(f, str) or not f for f in fields)):
            raise ValueError("rule log_fields_required must be a nonempty string list")
        rules.append(dict(rule))
    if not rules:
        raise ValueError("detection-rule index must ship at least one rule")
    return tuple(rules)


def rule_lookup(index: tuple[dict, ...], *, rule_id: str) -> dict:
    """Return one rule or refuse with unknown-lookup; never an all-clear."""
    for rule in index:
        if rule["rule_id"] == rule_id:
            return rule
    raise DataSliceError("unknown-lookup",
                         f"rule id {rule_id!r} is unknown in this demo index; "
                         "unknown stays unknown")
