"""Burp-specific CallToolResult normalization.

The SSE/HTTP MCP client machinery (SseMcpSession, endpoint validation,
redaction, caps) lives in ``extension/arms/mcp_client.py`` and is shared
by all curated HTTP-MCP arms. This module re-exports it so existing
import paths keep working, and keeps the Burp result normalization
(Burp paginates long tool output with an end sentinel) here.
"""

from __future__ import annotations

import http.client  # noqa: F401 - monkeypatch anchor in tests
import json
from typing import Any

from ..mcp_client import (
    MAX_MCP_BYTES,
    MAX_MCP_ROWS,
    MCP_CALL_TIMEOUT,
    PROTOCOL_VERSION,
    SseMcpSession,
    configured_http_url,
    redact,
    resolve_sse_endpoint,
)

__all__ = [
    "MAX_MCP_BYTES",
    "MAX_MCP_ROWS",
    "MCP_CALL_TIMEOUT",
    "PROTOCOL_VERSION",
    "SseMcpSession",
    "configured_http_url",
    "normalize_call_result",
    "redact",
    "resolve_sse_endpoint",
]

_END_SENTINEL = "Reached end of items"


def normalize_call_result(result_obj: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Normalize a Burp CallToolResult into (data, meta)."""
    meta: dict[str, Any] = {"has_more": False}
    if not isinstance(result_obj, dict):
        return result_obj, meta
    if result_obj.get("isError"):
        content = result_obj.get("content") or []
        text = ""
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                text = str(first.get("text", ""))
        return {"error": redact(text) if text else "tool error", "isError": True}, meta

    content = result_obj.get("content")
    text = ""
    if isinstance(content, list) and content:
        parts = [
            str(block["text"])
            for block in content
            if isinstance(block, dict) and "text" in block
        ]
        text = "\n\n".join(parts)
    elif isinstance(result_obj.get("data"), (list, dict, str)):
        data = result_obj.get("data")
        if isinstance(data, list):
            if len(data) > MAX_MCP_ROWS:
                data = data[:MAX_MCP_ROWS]
                meta["clamped"] = True
                meta["max_rows"] = MAX_MCP_ROWS
            meta["total"] = len(data)
        return data, meta

    if not text:
        return result_obj, meta

    if _END_SENTINEL in text:
        meta["has_more"] = False
        lines = [ln for ln in text.splitlines() if _END_SENTINEL not in ln]
        text = "\n".join(lines).strip()
    else:
        meta["has_more"] = True

    chunks = [c.strip() for c in text.split("\n\n") if c.strip()]
    rows: list[Any] = []
    for chunk in chunks:
        try:
            rows.append(json.loads(chunk))
        except json.JSONDecodeError:
            rows.append(chunk)
    if len(rows) == 1 and not isinstance(rows[0], (list, dict)):
        only = rows[0]
        if (
            isinstance(only, str)
            and only.lstrip()[:1] in "{["
            and only.rstrip().endswith("(truncated)")
        ):
            meta["truncated_items"] = True
            meta["total"] = 1
            return rows, meta
        meta["total"] = 1
        meta["has_more"] = False
        return rows[0], meta
    if len(rows) > MAX_MCP_ROWS:
        rows = rows[:MAX_MCP_ROWS]
        meta["clamped"] = True
        meta["max_rows"] = MAX_MCP_ROWS
    meta["total"] = len(rows)
    if not rows:
        meta["has_more"] = False
    return rows, meta
