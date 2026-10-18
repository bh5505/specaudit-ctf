"""Check declared result records without authenticating containment evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from capability_records import is_reference, is_stable_id

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
    scope: str = "declared-control-records"
    limitations: tuple[str, ...] = (
        "measurement-and-artifact-references-not-authenticated",
        "no-containment-enforcement-or-safe-01-acceptance",
    )


def verify_containment(bundle: Any) -> ContainmentResult:
    """Validate a bundle's declared control records and reported outcomes.

    ``bundle`` must be a mapping with a ``controls`` mapping whose keys are
    control names and values are mappings with at least ``status`` in
    {``pass``, ``fail``} and ``evidence`` (a bounded reference string). All of
    ``_REQUIRED_CONTROLS`` must be present and passing.  Any missing or
    failing control means not satisfied. Extra declared controls are also
    checked, so a failing additional control cannot disappear from the result.
    References are not dereferenced and outcomes are not independently proven.
    ``satisfied`` applies only to these declared records, never to SAFE-01.
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
    if len(controls) > 64:
        raise ContainmentEvidenceError("controls exceeds the 64-record cap")
    if any(not is_stable_id(name) for name in controls):
        raise ContainmentEvidenceError("control names must be bounded stable identifiers")
    for name in sorted(_REQUIRED_CONTROLS | set(controls)):
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
            reasons.append(f"invalid status for {name}")
            continue
        if not is_reference(evidence):
            controls_failed.append(name)
            reasons.append(f"missing evidence for {name}")
            continue
        if status != "pass":
            controls_failed.append(name)
            reasons.append(f"control failed: {name}")

    # A separation reference is required structurally; it is not proof of access
    # separation in the actual learner context.
    gti = controls.get("ground_truth_isolation")
    if isinstance(gti, Mapping) and gti.get("status") == "pass":
        if not is_reference(gti.get("grader_plane_separation")):
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
