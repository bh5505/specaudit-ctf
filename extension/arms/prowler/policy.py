"""Exact-name allowlist and endpoint policy for the Prowler arm.

Upstream tool names are pinned from first-party source (verified
2026-09-06): the OSS Prowler MCP server lives at prowler-cloud/prowler
`mcp_server/` and mounts three sub-servers with namespaces prowler_hub_,
prowler_ and prowler_docs_ (server.py mounts); FastMCP 3.4.5 mount
semantics expose tools as ``<namespace>_<method>``. The hub namespace is
a read-only catalog (10 tools), docs is read-only (2 tools), and the
tenant namespace mixes 31 reads with 18 mutating tools (scan triggers,
mutelist/integration/provider writers, role setting) extracted per file
from ``mcp_server/prowler_mcp_server/prowler_app/tools/``. The
hosted-only ``prowler_cloud_`` namespace does not exist in the OSS
server at all (README: "Prowler Cloud-only management tools (hosted
Prowler MCP only)") and stays blocked wholesale.

Transport facts pinned the same day: the server CLI offers
``--transport {stdio,http}`` with ``--host`` default 127.0.0.1 and
``--port`` default 8000 (main.py), and FastMCP's "http" transport
serves streamable HTTP at /mcp (fastmcp 3.4.5 settings +
create_streamable_http_app). Upstream ships no TLS. The arm therefore
accepts an operator-configured https endpoint (self-hosted remote) or a
literal-loopback http endpoint (the first-party local default) — the
union policy; hostnames that resolve to loopback are refused by the
shared DNS pin.
"""

from __future__ import annotations

from ..mcp_client import HttpTransportPolicy
from ..policy_base import ToolPolicy

ARM_ID = "prowler-mcp"
ENV_ENDPOINT = "PROWLER_MCP_ENDPOINT"
# Union policy (stated EXPLICITLY, never via the shared client's
# implicit default): https for self-hosted remote deployments the
# operator fronts with TLS, and literal 127.0.0.1/[::1] http for the
# first-party OSS server whose local default is a plain-http loopback
# listener (no TLS story upstream). Plain http to any non-loopback
# host stays refused fail-closed by the shared gate.
TRANSPORT_POLICY = HttpTransportPolicy.remote_https_or_loopback()

# The server holds its own credentials (a Prowler API key in the
# server's .env for the tenant namespace; nothing at all for
# hub/docs). This client sends no credential, and install is gated by
# the endpoint env alone — the earlier AWS-credential gate is
# withdrawn on 2026-09-06 primary-source evidence: the MCP server
# never reads AWS credentials (hub/docs unauthenticated, tenant tools
# authenticate to api.prowler.com server-side).

# Read-only inventory, exact names (31 tenant reads + 12 catalog reads).
ALLOWED_TOOLS = frozenset(
    {
        # prowler_app reads (tenant data via api.prowler.com)
        "prowler_list_attack_paths_scans",
        "prowler_list_attack_paths_queries",
        "prowler_run_attack_paths_query",
        "prowler_get_attack_paths_cartography_schema",
        "prowler_get_compliance_overview",
        "prowler_get_compliance_framework_state_details",
        "prowler_list_finding_groups",
        "prowler_get_finding_group_details",
        "prowler_list_finding_group_resources",
        "prowler_search_security_findings",
        "prowler_get_finding_details",
        "prowler_get_findings_overview",
        "prowler_list_integrations",
        "prowler_get_integration",
        "prowler_get_jira_issue_types",
        "prowler_get_mutelist",
        "prowler_list_mute_rules",
        "prowler_get_mute_rule",
        "prowler_search_providers",
        "prowler_list_resources",
        "prowler_get_resource",
        "prowler_get_resources_overview",
        "prowler_get_resource_events",
        "prowler_list_roles",
        "prowler_get_role",
        "prowler_get_user_roles",
        "prowler_list_users",
        "prowler_get_user",
        "prowler_get_current_user",
        "prowler_list_scans",
        "prowler_get_scan",
        # prowler_hub reads (public check/compliance/provider catalog)
        "prowler_hub_list_checks",
        "prowler_hub_semantic_search_checks",
        "prowler_hub_get_check_details",
        "prowler_hub_get_check_code",
        "prowler_hub_get_check_fixer",
        "prowler_hub_list_compliances",
        "prowler_hub_semantic_search_compliances",
        "prowler_hub_get_compliance_details",
        "prowler_hub_list_providers",
        "prowler_hub_get_provider_services",
        # prowler_docs reads (documentation search)
        "prowler_docs_search",
        "prowler_docs_get_document",
    }
)

# Mutating inventory, exact names — refused even if the server lists
# them: scan triggers, mutelist writers, integration writers/providers,
# role setting. Everything not on either exact list is refused
# fail-closed as not-allowlisted, which is the containment for any
# future upstream mutating name.
BLOCKED_TOOLS = frozenset(
    {
        "prowler_trigger_scan",
        "prowler_schedule_daily_scan",
        "prowler_update_scan",
        "prowler_set_mutelist",
        "prowler_delete_mutelist",
        "prowler_create_mute_rule",
        "prowler_update_mute_rule",
        "prowler_delete_mute_rule",
        "prowler_connect_provider",
        "prowler_delete_provider",
        "prowler_create_amazon_s3_integration",
        "prowler_create_aws_security_hub_integration",
        "prowler_create_jira_integration",
        "prowler_update_integration",
        "prowler_delete_integration",
        "prowler_test_integration_connection",
        "prowler_send_findings_to_jira",
        "prowler_set_user_role",
    }
)

# Hosted-only namespace: absent from the OSS server (README pins it to
# the hosted Prowler MCP); blocked wholesale as defense-in-depth for
# operators pointing the arm at the hosted endpoint.
BLOCKED_PREFIXES = ("prowler_cloud_",)

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

_TOOL_POLICY = ToolPolicy(allowed=ALLOWED_TOOLS, blocked=BLOCKED_TOOLS)


def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Return the refusal reason for *tool*, or None to proceed."""
    if tool.startswith(BLOCKED_PREFIXES):
        return (
            f"tool {tool!r} is blocked (hosted cloud-management "
            "namespace, not part of the OSS server surface)"
        )
    reason = _TOOL_POLICY.refuse_reason(tool)
    if reason is not None:
        return reason
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None
