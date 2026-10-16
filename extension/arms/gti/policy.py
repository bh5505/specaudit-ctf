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

# All 32 allowlisted tools are report/lookup reads; none dispatch
# actions. Verified against the current official tool inventory
# 2026-09-06 from the google/mcp-security server/gti source (36 tools
# across collections/files/intelligence/netloc/threat_profiles/urls:
# 32 read lookups admitted below; the 4 mutating tools are exactly
# blocked and anything not listed is refused fail-closed). There is
# no dispatch tier for this arm.
ALLOWED_TOOLS = frozenset(
    {
        # intelligence lookups (admitted since 2026-09-04)
        "search_iocs",
        "get_hunting_ruleset",
        "get_entities_related_to_a_hunting_ruleset",
        # netloc reports
        "get_domain_report",
        "get_entities_related_to_a_domain",
        "get_ip_address_report",
        "get_entities_related_to_an_ip_address",
        # url reports
        "get_url_report",
        "get_entities_related_to_an_url",
        # file reports (analyse_file is NOT here - it uploads)
        "get_file_report",
        "get_entities_related_to_a_file",
        "get_file_behavior_report",
        "get_file_behavior_summary",
        "search_digital_threat_monitoring",
        # threat-profile reads (admitted 2026-09-06)
        "list_threat_profiles",
        "get_threat_profile",
        "get_threat_profile_recommendations",
        "get_threat_profile_associations_timeline",
        # collection reads (admitted 2026-09-06)
        "get_collection_report",
        "get_entities_related_to_a_collection",
        "search_threats",
        "search_campaigns",
        "search_threat_actors",
        "search_malware_families",
        "search_software_toolkits",
        "search_threat_reports",
        "search_vulnerabilities",
        "get_collection_timeline_events",
        "get_collection_mitre_tree",
        "get_collection_feature_matches",
        "get_collections_commonalities",
        "get_collection_rules",
    }
)

# Exactly the mutating surface, pinned from source 2026-09-06: the
# three collection writers, plus analyse_file whose upstream
# docstring is verbatim "Upload and analyse the file in VirusTotal."
# / "The file will be uploaded to VirusTotal and shared with the
# community." - an upload-and-share action, refused even if a
# configured server lists it.
BLOCKED_TOOLS = frozenset(
    {
        "create_collection",
        "update_collection_attributes",
        "update_iocs_in_collection",
        "analyse_file",
    }
)

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
