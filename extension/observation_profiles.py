"""Frozen profiles for the opt-in trusted-observation sidecar.

This registry is deliberately separate from ``INVOKE_PROFILES``.  It neither
admits an action nor changes dispatch; it says which already-admitted result
shape a trusted caller may turn into an observation after independently
holding the source and Mode-A result bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class ObservationProfile:
    capability_id: str
    arm_id: str
    action: str
    tool_name: str
    tool_version: str
    source_schema_id: str
    source_schema_version: int
    subject_kind: str
    scope_kind: str
    artifact_kind: str
    artifact_redaction: str
    evidence_class: str


_VULNIFY_LOOKUP = ObservationProfile(
    capability_id="vulnify.lookup",
    arm_id="vulnify",
    action="lookup",
    tool_name="specaudit-ctf",
    tool_version="0.1.0",
    source_schema_id="specaudit.ctf.vulnify-feed-projection.v1",
    source_schema_version=1,
    subject_kind="cve-record",
    scope_kind="vulnerability-record",
    artifact_kind="policy-report",
    artifact_redaction="credentials-stripped",
    evidence_class="declared",
)

OBSERVATION_PROFILES: Mapping[str, ObservationProfile] = MappingProxyType(
    {_VULNIFY_LOOKUP.capability_id: _VULNIFY_LOOKUP}
)


def observation_profile(capability_id: str) -> ObservationProfile | None:
    """Return the exact profile for an observation-capable result, if any."""
    return OBSERVATION_PROFILES.get(capability_id)


__all__ = ["OBSERVATION_PROFILES", "ObservationProfile", "observation_profile"]
