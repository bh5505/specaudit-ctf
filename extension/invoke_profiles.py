"""Authoritative X2-PUB profiles for the bounded CLI invoke surface.

Only actions listed here may run through ``python -m extension invoke`` while
X2-PUB is limited to in-process, read-only policy discovery.  In particular,
the registry intentionally excludes every action that spawns a subprocess,
touches a caller-selected path, reaches a network, spends model tokens, or
mutates state.

Capability manifests for these profiles are encoded from this registry.
A child-returned or caller-constructed document is not authority.
"""

from __future__ import annotations

from dataclasses import dataclass

PACKAGE_NAME = "specaudit-ctf"
PACKAGE_VERSION = "0.1.0"


@dataclass(frozen=True)
class InvokeProfile:
    """Result-envelope metadata for one admitted read-only action."""

    arm_id: str
    action: str
    capability_id: str
    tool_name: str
    tool_version: str
    authorized_scope: tuple[str, ...]
    touched_scope: tuple[str, ...]
    safety_class: str
    side_effects: tuple[str, ...]
    timeout_ms: int
    max_output_bytes: int
    max_tool_steps: int
    max_spend: float | int | None
    cleanup_required: bool
    approval_ref: str | None
    roe_ref: str | None
    # Support tier carried into the capability manifest. X5-PROMOTE: the
    # agent-wiz read tier is the catalog's only maintained capability.
    tier: str = "research"


_STATIC_POLICY_ARMS = (
    "agent-wiz",
    "ai-deep-sast",
    "dark-moon",
    "deepsec",
    "nmap",
    "pyrit",
    "routersploit",
    "sniper",
    "vvah",
    "zgrab2",
)


def _policy_profile(arm_id: str, tier: str = "research") -> InvokeProfile:
    capability_id = f"{arm_id}.list_tools"
    scope = (f"policy://extension/arms/{arm_id}",)
    return InvokeProfile(
        arm_id=arm_id,
        action="list_tools",
        capability_id=capability_id,
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope,
        safety_class="R0",
        side_effects=("local-read",),
        timeout_ms=30_000,
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        approval_ref=None,
        roe_ref=None,
        tier=tier,
    )


# X5-PROMOTE: agent-wiz's read tier is promoted to maintained (doc 13
# evidence gate; dossier on AuditPack issue #5). No adjacent row moves.
_POLICY_ARM_TIERS = {arm_id: "research" for arm_id in _STATIC_POLICY_ARMS}
_POLICY_ARM_TIERS["agent-wiz"] = "maintained"

INVOKE_PROFILES = {
    profile.capability_id: profile
    for profile in (
        _policy_profile(arm_id, tier)
        for arm_id, tier in _POLICY_ARM_TIERS.items()
    )
}
INVOKE_CAPABILITY_IDS = frozenset(INVOKE_PROFILES)


def invoke_profile(arm_id: str, action: str) -> InvokeProfile | None:
    """Return an admitted profile without deriving trust from caller input."""

    profile = INVOKE_PROFILES.get(f"{arm_id}.{action}")
    if profile is None or profile.arm_id != arm_id or profile.action != action:
        return None
    return profile
