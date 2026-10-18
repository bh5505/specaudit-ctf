"""Structural deliverable records, without PACK-01 admission or asset proof.

A manifest is exactly {"artifacts": [...]}; each artifact is exactly
{"artifact_id": stable ID, "path": relative POSIX path, "digest": SHA256,
"media_type": type/subtype}. IDs and paths must be unique. Other components
are concrete recursive prose/reference content, never booleans/numbers/nulls.
The validator resolves no paths, hashes no files and checks no asset access.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

from capability_records import (
    is_concrete_content,
    is_reference,
    is_sha256_digest,
    is_stable_id,
)

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
    limits: tuple[str, ...] = (
        "Structural completeness only; artifact bytes, existence and authenticity are unverified.",
        "No pack admission, learner/key access isolation, reset execution or assessment completion is established.",
    )


_ARTIFACT_FIELDS = frozenset({"artifact_id", "path", "digest", "media_type"})
_MEDIA_TYPE = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+")


def _relative_artifact_path(value: Any) -> bool:
    return (
        is_reference(value)
        and not value.startswith("/")
        and "\\" not in value
        and ":" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _manifest_valid(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {"artifacts"}:
        return False
    artifacts = value["artifacts"]
    if not isinstance(artifacts, (list, tuple)) or not 0 < len(artifacts) <= 256:
        return False
    ids: set[str] = set()
    paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or set(artifact) != _ARTIFACT_FIELDS:
            return False
        if not (
            is_stable_id(artifact["artifact_id"])
            and _relative_artifact_path(artifact["path"])
            and is_sha256_digest(artifact["digest"])
            and is_reference(artifact["media_type"])
            and len(artifact["media_type"]) <= 255
            and _MEDIA_TYPE.fullmatch(artifact["media_type"]) is not None
        ):
            return False
        if artifact["artifact_id"] in ids or artifact["path"] in paths:
            return False
        ids.add(artifact["artifact_id"])
        paths.add(artifact["path"])
    return True


def validate_deliverable(doc: Any) -> DeliverableResult:
    """Check the bounded component/manifest contract without reading assets."""
    if not isinstance(doc, Mapping):
        raise DeliverableError("deliverable must be a mapping")
    missing = sorted(REQUIRED_COMPONENTS - set(doc))
    reasons = [f"missing component: {field}" for field in missing]
    invalid: list[str] = []
    extra = set(doc) - REQUIRED_COMPONENTS
    if extra:
        reasons.append(f"unexpected components: {sorted(map(repr, extra))}")
    for component in sorted(REQUIRED_COMPONENTS & set(doc)):
        check = _manifest_valid if component == "evidence_manifest" else is_concrete_content
        if not check(doc[component]):
            invalid.append(component)
            reasons.append(f"{component} does not meet its bounded structural contract")
    return DeliverableResult(
        version=DELIVERABLE_VERSION,
        valid=not reasons,
        missing=tuple(missing),
        invalid=tuple(invalid),
        reasons=tuple(reasons),
    )


__all__ = [
    "DELIVERABLE_VERSION",
    "DeliverableError",
    "DeliverableResult",
    "REQUIRED_COMPONENTS",
    "validate_deliverable",
]
