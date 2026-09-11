"""MCP annotations must conservatively cover admitted action effects."""

from __future__ import annotations

from extension import mcp_server
from extension.invoke_profiles import INVOKE_PROFILES


def test_invoke_annotations_cannot_contradict_any_admitted_arm() -> None:
    annotations = mcp_server._INVOKE_TOOL_DEF["annotations"]
    profiles = tuple(INVOKE_PROFILES.values())
    assert profiles

    effectful = [
        profile
        for profile in profiles
        if set(profile.side_effects) - {"none", "local-read"}
        or profile.safety_class != "R0"
    ]
    open_world = [
        profile for profile in profiles if "network-egress" in profile.side_effects
    ]
    assert effectful, "test inventory lost every R1/R2 or side-effecting arm"
    assert open_world, "test inventory lost every network-egress arm"

    # A single generic invoke descriptor must advertise the riskiest admitted
    # dispatch. Otherwise a client can trust readOnlyHint and skip confirmation.
    assert annotations["readOnlyHint"] is False
    assert annotations["openWorldHint"] is True

    for profile in effectful:
        assert annotations["readOnlyHint"] is False, profile.capability_id
    for profile in open_world:
        assert annotations["openWorldHint"] is True, profile.capability_id


def test_range_subprocess_descriptor_is_not_read_only_or_open_world() -> None:
    annotations = mcp_server._RUN_RANGE_TOOL_DEF["annotations"]
    assert annotations == {"readOnlyHint": False, "openWorldHint": False}
