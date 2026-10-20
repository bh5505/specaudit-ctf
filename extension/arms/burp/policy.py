"""Burp MCP tool metadata and argument defaults."""

from __future__ import annotations

from ..policy_base import DEFAULT_TOOL_PATTERN

ARM_ID = "burp-mcp"
ENV_ENDPOINT = "BURP_MCP_ENDPOINT"
ALLOWED_TOOL_PATTERN = DEFAULT_TOOL_PATTERN

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
    """Report malformed names or tools absent from the connected Burp server."""
    if not ALLOWED_TOOL_PATTERN.fullmatch(tool):
        return f"invalid tool name: {tool!r}"
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None
