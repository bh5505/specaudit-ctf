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
    contract_version: int = 1
    source_formats: tuple[str, ...] = ()
    subject_id_field: str = ""
    scope_prefix: str = ""
    report_record_key: str = ""
    replay_adapter_id: str = ""
    derived_limitations: tuple[str, ...] = ()


_GENERAL_DERIVED_LIMITATIONS = (
    "applicability-not-assessed",
    "source-admission-is-not-governance-promotion",
    "upstream-equivalence-not-established",
)


_VULNIFY_LOOKUP = ObservationProfile(
    contract_version=1,
    capability_id="vulnify.lookup",
    arm_id="vulnify",
    action="lookup",
    tool_name="specaudit-ctf",
    tool_version="0.1.0",
    source_schema_id="specaudit.ctf.vulnify-feed-projection.v1",
    source_schema_version=1,
    source_formats=("json", "jsonl", "yaml"),
    subject_kind="cve-record",
    subject_id_field="cve_id",
    scope_kind="vulnerability-record",
    scope_prefix="cve",
    report_record_key="vulnerability",
    replay_adapter_id="vulnify-feed-v1",
    artifact_kind="policy-report",
    artifact_redaction="credentials-stripped",
    evidence_class="declared",
    derived_limitations=_GENERAL_DERIVED_LIMITATIONS,
)

_SECURITY_DETECTIONS_GET_RULE = ObservationProfile(
    contract_version=2,
    capability_id="security-detections-mcp.get_rule",
    arm_id="security-detections-mcp",
    action="get_rule",
    tool_name="specaudit-ctf",
    tool_version="0.1.0",
    source_schema_id="specaudit.ctf.security-detections-index-projection.v1",
    source_schema_version=1,
    source_formats=("json", "yaml", "yml"),
    subject_kind="detection-rule",
    subject_id_field="rule_id",
    scope_kind="detection-rule-record",
    scope_prefix="rule",
    report_record_key="rule",
    replay_adapter_id="security-detections-index-v1",
    artifact_kind="policy-report",
    artifact_redaction="credentials-stripped",
    evidence_class="declared",
    derived_limitations=(
        *_GENERAL_DERIVED_LIMITATIONS,
        "rule-deployment-not-established",
        "operating-effectiveness-not-assessed",
    ),
)

_RUBEUS_TELEMETRY = ObservationProfile(
    contract_version=2,
    capability_id="rubeus.telemetry",
    arm_id="rubeus",
    action="telemetry",
    tool_name="specaudit-ctf",
    tool_version="0.1.0",
    source_schema_id="specaudit.ctf.rubeus-telemetry-projection.v1",
    source_schema_version=1,
    source_formats=("json", "jsonl"),
    subject_kind="telemetry-event",
    subject_id_field="event_id",
    scope_kind="telemetry-event-record",
    scope_prefix="event",
    report_record_key="telemetry",
    replay_adapter_id="rubeus-telemetry-v1",
    artifact_kind="policy-report",
    artifact_redaction="credentials-stripped",
    evidence_class="declared",
    derived_limitations=(
        *_GENERAL_DERIVED_LIMITATIONS,
        "event-authenticity-not-established",
        "event-time-not-established",
        "compromise-not-inferred",
    ),
)

_GPOHOUND_POLICY = ObservationProfile(
    contract_version=3,
    capability_id="gpohound.policy",
    arm_id="gpohound",
    action="policy",
    tool_name="specaudit-ctf",
    tool_version="0.1.0",
    source_schema_id="specaudit.ctf.gpohound-policy-evidence-projection.v1",
    source_schema_version=1,
    source_formats=("json", "yaml", "yml"),
    subject_kind="gpo-policy",
    subject_id_field="policy_id",
    scope_kind="gpo-policy-record",
    scope_prefix="policy",
    report_record_key="policy",
    replay_adapter_id="gpohound-policy-evidence-v1",
    artifact_kind="policy-report",
    artifact_redaction="credentials-stripped",
    evidence_class="declared",
    derived_limitations=(
        *_GENERAL_DERIVED_LIMITATIONS,
        "policy-application-not-established",
        "effective-access-not-inferred",
        "security-filter-applicability-not-assessed",
        "wmi-filter-applicability-not-assessed",
        "item-level-targeting-not-represented",
        "policy-conflicts-not-simulated",
    ),
)

OBSERVATION_PROFILES: Mapping[str, ObservationProfile] = MappingProxyType(
    {
        profile.capability_id: profile
        for profile in (
            _VULNIFY_LOOKUP,
            _SECURITY_DETECTIONS_GET_RULE,
            _RUBEUS_TELEMETRY,
            _GPOHOUND_POLICY,
        )
    }
)


def observation_profile(capability_id: str) -> ObservationProfile | None:
    """Return the exact profile for an observation-capable result, if any."""
    return OBSERVATION_PROFILES.get(capability_id)


__all__ = ["OBSERVATION_PROFILES", "ObservationProfile", "observation_profile"]
