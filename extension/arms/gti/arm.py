"""Curated google-mcp-security (GTI) arm: read-only lookups over MCP."""

from __future__ import annotations

import os
from typing import Any, Callable, Mapping

from ...contract import (
    TRANSPORT_MCP,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import (
    MAX_MCP_ROWS,
    MCP_CALL_TIMEOUT,
    StreamableHttpClient,
    redact,
)
from .policy import (
    ALLOWED_TOOLS,
    ARM_ID,
    ENV_ENDPOINT,
    LIST_ACTIONS,
    TRANSPORT_POLICY,
    endpoint_url,
    refuse_reason,
)

SessionFactory = Callable[..., Any]


def _default_session_factory(url: str, timeout: float = MCP_CALL_TIMEOUT) -> Any:
    return StreamableHttpClient(url, timeout=timeout, policy=TRANSPORT_POLICY)


class GtiArm:
    """Specialized transport for catalog id google-mcp-security.

    Read-only threat-intelligence lookups over the shared streamable
    HTTP client. The upstream server holds the VT/Google API key
    (VT_APIKEY on the server side); this client needs only the endpoint.
    No dispatch tier exists for this arm - every upstream tool is a
    lookup.
    """

    ARM_ID = ARM_ID
    protocol = TRANSPORT_MCP

    def __init__(
        self,
        endpoint: str | None = None,
        timeout: float = MCP_CALL_TIMEOUT,
        session_factory: SessionFactory | None = None,
    ) -> None:
        self._explicit_endpoint = endpoint is not None
        self._endpoint_arg = endpoint
        self.timeout = timeout
        self._session_factory = session_factory or _default_session_factory

    def endpoint_url(self) -> str | None:
        if self._explicit_endpoint:
            from ..mcp_client import configured_http_url

            return configured_http_url(self._endpoint_arg, TRANSPORT_POLICY)
        return endpoint_url()

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID and self.endpoint_url() is not None

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        endpoint = self.endpoint_url()
        if spec.id != ARM_ID or endpoint is None:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        session = self._session_factory(endpoint, timeout=self.timeout)
        try:
            session.connect()
            tools = session.list_tools()
            names = {
                str(item.get("name"))
                for item in tools
                if isinstance(item, dict) and item.get("name")
            }
            if action in LIST_ACTIONS:
                return Result(
                    ok=True,
                    arm_id=spec.id,
                    action=action,
                    output={
                        "tools": [
                            item
                            for item in tools[:MAX_MCP_ROWS]
                            if isinstance(item, dict)
                        ],
                        "dispatch_tier": "none",
                    },
                    error=None,
                )
            reason = refuse_reason(action, names)
            if reason:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=reason,
                )
            result_obj = session.call_tool(action, payload)
            data = _normalize(result_obj)
            if isinstance(data, dict) and data.get("isError"):
                detail = redact(str(data.get("error") or "tool error"))
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output={"data": data},
                    error=detail,
                )
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={"data": data},
                error=None,
            )
        except Exception as exc:  # noqa: BLE001 - surface as Result, stay closed
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        finally:
            session.close()


def _normalize(result_obj: dict[str, Any]) -> Any:
    """Extract text/data from a CallToolResult; redact error text."""
    if not isinstance(result_obj, dict):
        return result_obj
    if result_obj.get("isError"):
        content = result_obj.get("content") or []
        text = ""
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                text = str(first.get("text", ""))
        return {"error": redact(text) if text else "tool error", "isError": True}
    content = result_obj.get("content")
    if isinstance(content, list) and content:
        parts = [
            str(block["text"])
            for block in content
            if isinstance(block, dict) and "text" in block
        ]
        if parts:
            return redact("\n\n".join(parts))[:512 * 1024]
    if "data" in result_obj:
        return result_obj["data"]
    return result_obj
