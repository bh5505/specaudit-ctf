"""Connected MCP server tool availability."""

from __future__ import annotations

from ..policy_base import DEFAULT_TOOL_PATTERN

import os

ARM_ID = "google-mcp-security"
ENV_ENDPOINT = "GTI_MCP_ENDPOINT"
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

def endpoint_url() -> str | None:
    from ..mcp_client import configured_http_url
    return configured_http_url(os.environ.get(ENV_ENDPOINT))


def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Report malformed names or tools absent from the connected server."""
    if not DEFAULT_TOOL_PATTERN.fullmatch(tool):
        return f"invalid tool name: {tool!r}"
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None
