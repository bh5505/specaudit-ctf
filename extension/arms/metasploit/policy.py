"""Metasploit MCP endpoint configuration."""

from __future__ import annotations

import os

ARM_ID = "metasploit-mcp"
ENV_ENDPOINT = "METASPLOIT_MCP_ENDPOINT"
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})


def endpoint_url() -> str | None:
    from ..mcp_client import configured_http_url

    return configured_http_url(os.environ.get(ENV_ENDPOINT))
