"""Connected MCP server tool availability."""

from __future__ import annotations

from ..policy_base import DEFAULT_TOOL_PATTERN

ARM_ID = "prowler-mcp"
ENV_ENDPOINT = "PROWLER_MCP_ENDPOINT"
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Report malformed names or tools absent from the connected server."""
    if not DEFAULT_TOOL_PATTERN.fullmatch(tool):
        return f"invalid tool name: {tool!r}"
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None
