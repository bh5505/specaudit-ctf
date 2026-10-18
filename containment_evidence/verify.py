"""Containment evidence verification (SAFE-01)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

CONTAINMENT_VERSION = "specaudit.ctf.containment-evidence.v1"

_REQUIRED_CONTROLS = frozenset(
    {
        "denied_egress",
        "no_mutation",
        "sandbox_boundary",
        "ground_truth_isolation",
        "cleanup",
        "credential_isolation",
        "resource_limits",
        "hostile_content_as_data",
    }
)


class ContainmentEvidenceError(ValueError):
    """Raised when an evidence bundle is structurally invalid."""


@dataclass(frozen=True)
class ContainmentResult:
    version: str
    satisfied: bool
    controls_present: tuple[str, ...]
    controls_missing: tuple[str, ...]
    controls_failed: tuple[str, ...]
    reasons: tuple[str, ...]


def verify_containment(bundle: Any) -> ContainmentResult:
    """Verify a containment evidence bundle.

    ``bundle`` must be a mapping with a ``controls`` mapping whose keys are
    control names and values are mappings with at least ``status`` in
    {``pass``, ``fail``} and ``evidence`` (nonempty string).  All of
    ``_REQUIRED_CONTROLS`` must be present and passing.  Any missing or
    failing control means not satisfied (fail-closed).
    """
    reasons: list[str] = []
    controls_present: list[str] = []
    controls_missing: list[str] = []
    controls_failed: list[str] = []

    if not isinstance(bundle, Mapping):
        raise ContainmentEvidenceError("bundle must be a mapping")
    controls = bundle.get("controls")
    if not isinstance(controls, Mapping):
        raise ContainmentEvidenceError("controls must be a mapping")
    for name in _REQUIRED_CONTROLS:
        entry = controls.get(name)
        if not isinstance(entry, Mapping):
            controls_missing.append(name)
            reasons.append(f"missing control: {name}")
            continue
        controls_present.append(name)
        status = entry.get("status")
        evidence = entry.get("evidence")
        if status not in ("pass", "fail"):
            controls_failed.append(name)
            reasons.append(f"invalid status for {name}: {status!r}")
            continue
        if not isinstance(evidence, str) or not evidence.strip():
            controls_failed.append(name)
            reasons.append(f"missing evidence for {name}")
            continue
        if status != "pass":
            controls_failed.append(name)
            reasons.append(f"control failed: {name}")

    # Reject unknown controls? No — allow extra, but record none.
    # Ground-truth isolation additionally requires grader-plane separation evidence.
    gti = controls.get("ground_truth_isolation")
    if isinstance(gti, Mapping) and gti.get("status") == "pass":
        if not isinstance(gti.get("grader_plane_separation"), str) or not gti.get(
            "grader_plane_separation"
        ).strip():
            controls_failed.append("ground_truth_isolation")
            reasons.append("ground_truth_isolation missing grader_plane_separation evidence")

    satisfied = (
        not controls_missing
        and not controls_failed
        and set(controls_present) >= _REQUIRED_CONTROLS
    )
    return ContainmentResult(
        version=CONTAINMENT_VERSION,
        satisfied=satisfied,
        controls_present=tuple(sorted(controls_present)),
        controls_missing=tuple(sorted(controls_missing)),
        controls_failed=tuple(sorted(set(controls_failed))),
        reasons=tuple(reasons),
    )


__all__ = [
    "CONTAINMENT_VERSION",
    "ContainmentEvidenceError",
    "ContainmentResult",
    "verify_containment",
]
