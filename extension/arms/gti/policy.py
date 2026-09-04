"""Allowlist rules for the google-mcp-security (GTI) arm."""

from __future__ import annotations

import os

from ..mcp_client import HttpTransportPolicy
from ..policy_base import ToolPolicy

ARM_ID = "google-mcp-security"
ENV_ENDPOINT = "GTI_MCP_ENDPOINT"
# Remote-armed catalog: https endpoints only, loopback refused. The
# upstream google/mcp-security GTI server is FastMCP-based - stdio by
# default, HTTP-capable by construction - and this arm targets
# operator-fronted https deployments of that official server.
TRANSPORT_POLICY = HttpTransportPolicy.remote_https()

# All 11 allowlisted tools are report/lookup reads; none dispatch
# actions. Verified against the current official tool inventory
# 2026-09-04 from the google/mcp-security server/gti source (36 tools
# across collections/files/intelligence/netloc/threat_profiles/urls;
# the mutating collection create/update family stays off this
# allowlist, and anything not listed is refused fail-closed). There is
# no dispatch tier for this arm.
ALLOWED_TOOLS = frozenset(
    {
        "search_iocs",
        "get_domain_report",
        "get_ip_address_report",
        "get_url_report",
        "get_file_report",
        "get_hunting_ruleset",
        "get_entities_related_to_a_hunting_ruleset",
        "get_file_behavior_report",
        "get_file_behavior_summary",
        "get_entities_related_to_a_domain",
        "get_entities_related_to_an_url",
    }
)

BLOCKED_TOOLS = frozenset()

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

_TOOL_POLICY = ToolPolicy(allowed=ALLOWED_TOOLS, blocked=BLOCKED_TOOLS)


def endpoint_url() -> str | None:
    from ..mcp_client import configured_http_url

    return configured_http_url(os.environ.get(ENV_ENDPOINT), TRANSPORT_POLICY)


def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Return the refusal reason for *tool*, or None to proceed."""
    reason = _TOOL_POLICY.refuse_reason(tool)
    if reason is not None:
        return reason
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None
