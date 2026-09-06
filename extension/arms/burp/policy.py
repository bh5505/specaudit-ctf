"""Allowlist and blocked-class rules for the Burp arm."""

from __future__ import annotations

from ..mcp_client import HttpTransportPolicy
from ..policy_base import DEFAULT_TOOL_PATTERN, ToolPolicy

ARM_ID = "burp-mcp"
ENV_ENDPOINT = "BURP_MCP_ENDPOINT"
# The upstream BApp serves SSE on a literal loopback address; this arm
# accepts only literal 127.0.0.1/[::1] endpoints (http or https).
TRANSPORT_POLICY = HttpTransportPolicy.loopback()
ALLOWED_TOOL_PATTERN = DEFAULT_TOOL_PATTERN

ALLOWED_TOOLS = frozenset(
    {
        "output_project_options",
        "output_user_options",
        "get_proxy_http_history",
        "get_proxy_http_history_regex",
        "get_proxy_websocket_history",
        "get_proxy_websocket_history_regex",
        "get_scanner_issues",
        "get_collaborator_interactions",
        "get_organizer_items",
        "get_organizer_items_regex",
        "url_encode",
        "url_decode",
        "base64_encode",
        "base64_decode",
        "generate_random_string",
    }
)

# Active request, UI mutation, config writes, and the live-editor read
# (operator UI state, not an audit artifact) stay off. The full
# current upstream surface was re-verified from source 2026-09-06
# (PortSwigger/mcp-server main): every tool name below exists; the
# reads added that day (regex history variants, organizer regex,
# output_user_options) are reads of the same proxy/organizer/config
# data already admitted — output_user_options rides the upstream
# credential filter (v1.3.0: "Broaden credential filter and fail
# closed on malformed JSON in options export"); this client's
# error-path keyword redaction stays on regardless, and export
# payload filtering rides the upstream credential filter.
# get_collaborator_interactions takes only an optional payloadId
# (upstream data class GetCollaboratorInteractions(val payloadId:
# String? = null)) — no pagination defaults to invent.
BLOCKED_TOOLS = frozenset(
    {
        "send_http1_request",
        "send_http2_request",
        "create_repeater_tab",
        "create_repeater_tab_http2",
        "send_to_intruder",
        "set_task_execution_engine_state",
        "set_proxy_intercept_state",
        "set_active_editor_contents",
        "set_project_options",
        "set_user_options",
        "generate_collaborator_payload",
        "get_active_editor_contents",
    }
)

PROFESSIONAL_ONLY = frozenset(
    {
        "get_scanner_issues",
        "generate_collaborator_payload",
        "get_collaborator_interactions",
    }
)

# Pagination only. Utilities take caller args so we do not invent payloads.
TOOL_DEFAULT_ARGS: dict[str, dict] = {
    "get_proxy_http_history": {"count": 200, "offset": 0},
    "get_proxy_http_history_regex": {"regex": ".*", "count": 200, "offset": 0},
    "get_proxy_websocket_history": {"count": 200, "offset": 0},
    "get_proxy_websocket_history_regex": {"regex": ".*", "count": 200, "offset": 0},
    "get_scanner_issues": {"count": 200, "offset": 0},
    "get_organizer_items": {"count": 200, "offset": 0},
    "get_organizer_items_regex": {"regex": ".*", "count": 200, "offset": 0},
}

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

# Shared name-shape/blocklist/allowlist checks plus the server-surface
# availability check; edition is output metadata only.
_TOOL_POLICY = ToolPolicy(allowed=ALLOWED_TOOLS, blocked=BLOCKED_TOOLS)


def detect_edition(tool_names: set[str]) -> str:
    """Return professional|community|unknown from a tools/list name set."""
    if not tool_names:
        return "unknown"
    pro = PROFESSIONAL_ONLY & tool_names
    if len(pro) == len(PROFESSIONAL_ONLY):
        return "professional"
    if not pro:
        return "community"
    return "unknown"


def merge_tool_args(tool: str, args: dict) -> dict:
    merged = dict(TOOL_DEFAULT_ARGS.get(tool, {}))
    merged.update(args)
    return merged


def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Allowlist policy + the connected server's own surface. There is no
    edition gating: tools the connected Burp does not expose are refused
    as unavailable (a Community server simply does not list the
    scanner/Collaborator tools)."""
    reason = _TOOL_POLICY.refuse_reason(tool)
    if reason is not None:
        return reason
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None
