"""Deliverable substrate validation (PACK-01)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

DELIVERABLE_VERSION = "specaudit.ctf.deliverable-substrate.v1"

REQUIRED_COMPONENTS = frozenset(
    {
        "learner_brief",
        "evidence_manifest",
        "instructor_key",
        "benign_control",
        "limitations",
        "rubric",
        "reset_retention",
    }
)


class DeliverableError(ValueError):
    """Raised when a deliverable document is structurally invalid."""


@dataclass(frozen=True)
class DeliverableResult:
    version: str
    valid: bool
    missing: tuple[str, ...]
    invalid: tuple[str, ...]
    reasons: tuple[str, ...]


def validate_deliverable(doc: Any) -> DeliverableResult:
    """Validate a learning-pack deliverable document.

    ``doc`` must be a mapping.  Each required component must be present and
    nonempty (string or nonempty list/mapping).  Fail-closed.
    """
    reasons: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []

    if not isinstance(doc, Mapping):
        raise DeliverableError("deliverable must be a mapping")

    for comp in REQUIRED_COMPONENTS:
        if comp not in doc:
            missing.append(comp)
            reasons.append(f"missing component: {comp}")
            continue
        val = doc[comp]
        if isinstance(val, str):
            if not val.strip():
                invalid.append(comp)
                reasons.append(f"empty component: {comp}")
        elif isinstance(val, (list, tuple)):
            if not val:
                invalid.append(comp)
                reasons.append(f"empty component: {comp}")
        elif isinstance(val, Mapping):
            if not val:
                invalid.append(comp)
                reasons.append(f"empty component: {comp}")
        else:
            invalid.append(comp)
            reasons.append(f"invalid component type: {comp}")

    extra = set(doc) - REQUIRED_COMPONENTS
    if extra:
        reasons.append(f"unexpected components: {sorted(extra)}")

    # Evidence manifest must reference at least one artifact digest.
    em = doc.get("evidence_manifest")
    if isinstance(em, Mapping) and "artifacts" in em:
        arts = em.get("artifacts")
        if not isinstance(arts, (list, tuple)) or not arts:
            invalid.append("evidence_manifest")
            reasons.append("evidence_manifest.artifacts must be nonempty")

    valid = not missing and not invalid and not extra and not reasons
    # recompute cleanly: reasons already includes missing/invalid/extra
    valid = (not missing and not invalid and not extra and len(reasons) == 0)
    return DeliverableResult(
        version=DELIVERABLE_VERSION,
        valid=valid,
        missing=tuple(sorted(missing)),
        invalid=tuple(sorted(set(invalid))),
        reasons=tuple(reasons),
    )


__all__ = [
    "DELIVERABLE_VERSION",
    "DeliverableError",
    "DeliverableResult",
    "REQUIRED_COMPONENTS",
    "validate_deliverable",
]
