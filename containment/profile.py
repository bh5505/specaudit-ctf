"""Operator containment profile: the operator-approved boundaries.

The profile is the operator's statement of where repo code may read
(``approved_root``), where mutation verbs are even arguable
(``scratch_root``), whether the child may read its own Python runtime and
checkout (``allow_python_runtime``), and which canary strings must never
surface in a guarded child's output. It is plain data: JSON in, JSON out,
no environment reads, no clock reads.

Deliberately not an OS-sandbox definition: the profile polices the
audit-hook plane only (see ``containment/enforcer.py`` for the threat
model and residual bypasses).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from typing import Any, Mapping


class ProfileError(ValueError):
    """Typed profile refusal; ``reason`` is a stable machine-readable code."""


def _root(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProfileError("malformed", f"{label} must be a nonempty path string")
    absolute = os.path.abspath(value)
    if not os.path.isabs(absolute):
        raise ProfileError("malformed", f"{label} must resolve to an absolute path")
    return absolute


@dataclass(frozen=True)
class OperatorProfile:
    """Where a guarded child may read, and where mutation is arguable.

    ``approved_root`` is the operator-input boundary for the acquisition
    gate and the enforcer's read gate. ``scratch_root`` is the only place
    mutation verbs (rename/link/remove/...) are not denied outright; open()
    with write intent is denied everywhere (the arms under containment are
    read-only). ``allow_python_runtime`` admits reads of the interpreter
    tree and the checkout that hosts the imported packages; set it False
    only for children that need no repo imports at all. ``canaries`` are
    operator-chosen marker strings the harness must never observe in a
    guarded child's output.
    """

    approved_root: str
    scratch_root: str
    allow_python_runtime: bool = True
    canaries: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        _root(self.approved_root, label="approved_root")
        _root(self.scratch_root, label="scratch_root")
        if not isinstance(self.allow_python_runtime, bool):
            raise ProfileError("malformed", "allow_python_runtime must be a boolean")
        for canary in self.canaries:
            if not isinstance(canary, str) or not canary.strip():
                raise ProfileError("malformed", "canaries must be nonempty strings")

    def to_dict(self) -> dict[str, Any]:
        """JSON-shaped plain mapping (the form the child receives)."""
        return {
            "approved_root": self.approved_root,
            "scratch_root": self.scratch_root,
            "allow_python_runtime": self.allow_python_runtime,
            "canaries": list(self.canaries),
        }

    def to_json(self) -> str:
        """Canonical compact JSON text, stable for env transport."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, row: Mapping[str, Any]) -> "OperatorProfile":
        if not isinstance(row, Mapping):
            raise ProfileError("malformed", "profile must be a JSON object")
        unknown = set(row) - {
            "approved_root", "scratch_root", "allow_python_runtime", "canaries"
        }
        if unknown:
            raise ProfileError("malformed", f"unknown profile keys: {sorted(unknown)}")
        canaries = row.get("canaries", ())
        if not isinstance(canaries, (list, tuple)) or any(
            not isinstance(item, str) for item in canaries
        ):
            raise ProfileError("malformed", "canaries must be a list of strings")
        return cls(
            approved_root=_root(row.get("approved_root"), label="approved_root"),
            scratch_root=_root(row.get("scratch_root"), label="scratch_root"),
            allow_python_runtime=row.get("allow_python_runtime", True),
            canaries=tuple(canaries),
        )

    @classmethod
    def from_json(cls, text: str) -> "OperatorProfile":
        try:
            row = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProfileError("malformed", f"profile json is not valid: {exc}") from exc
        return cls.from_dict(row)
