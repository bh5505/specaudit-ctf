"""Strict rubric loading for the public scorer.

A rubric can require capabilities and allow named envelopes to pass
AS DEGRADED — waiving exactly the status/limitations gate pair
(``status_complete`` and ``limitations_empty``) for them. It can never
relax evidence, cleanup, budget, scope, approval, or required-arm
gates, and it can never turn ``failed`` into a pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_ALLOWED_KEYS = {"name", "required_capabilities", "allowed_degraded"}


@dataclass(frozen=True)
class Rubric:
    """Run-level scoring constraints; every field optional."""

    name: str = "default"
    required_capabilities: tuple[str, ...] = ()
    allowed_degraded: tuple[str, ...] = ()


class RubricError(ValueError):
    """A rubric file is malformed or uses unknown keys (exit 2)."""


def load_rubric(path: Path) -> Rubric:
    """Load a strict rubric; any surprise raises RubricError."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RubricError(f"rubric unreadable: {path}") from exc
    except yaml.YAMLError as exc:
        raise RubricError(f"rubric is not valid YAML: {path}") from exc
    if raw is None:
        return Rubric()
    if not isinstance(raw, dict):
        raise RubricError("rubric must be a YAML mapping")
    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise RubricError(f"rubric has unknown keys: {', '.join(unknown)}")
    name = raw.get("name", "default")
    if not isinstance(name, str) or not name.strip():
        raise RubricError("rubric name must be a non-empty string")

    def _id_list(key: str) -> tuple[str, ...]:
        value = raw.get(key, [])
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            raise RubricError(f"rubric {key} must be a list of non-empty strings")
        return tuple(dict.fromkeys(value))

    return Rubric(
        name=name.strip(),
        required_capabilities=_id_list("required_capabilities"),
        allowed_degraded=_id_list("allowed_degraded"),
    )
