"""Curated Prowler arm: allowlisted MCP tools over HTTP+SSE."""

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
    MAX_MCP_BYTES,
    MAX_MCP_ROWS,
    MCP_CALL_TIMEOUT,
    SseMcpSession,
    configured_http_url,
    redact,
)
from .policy import (
    ARM_ID,
    ENV_ENDPOINT,
    LIST_ACTIONS,
    TRANSPORT_POLICY,
    credentials_present,
    refuse_reason,
)

SessionFactory = Callable[..., Any]


def _default_session_factory(url: str, timeout: float = MCP_CALL_TIMEOUT) -> Any:
    return SseMcpSession(url, timeout=timeout, policy=TRANSPORT_POLICY)


class ProwlerArm:
    """Specialized transport for catalog id prowler-mcp.

    SSE dialect on the remote-https transport policy (GTI-shaped, not
    the loopback Burp shape), with the highest credential burden of any
    curated arm: install requires both an endpoint and cloud
    credentials in the environment, and every output path runs through
    the shared redaction before it leaves the arm.
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
            raw = self._endpoint_arg
        else:
            raw = os.environ.get(ENV_ENDPOINT)
        return configured_http_url(raw, TRANSPORT_POLICY)

    def installed(self, spec: ArmSpec) -> bool:
        return (
            spec.id == ARM_ID
            and self.endpoint_url() is not None
            and credentials_present()
        )

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        endpoint = self.endpoint_url()
        if spec.id != ARM_ID or endpoint is None or not credentials_present():
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
                    output={"tools": _cap_rows(tools)},
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


def _cap_rows(rows: list[Any]) -> list[Any]:
    if len(rows) > MAX_MCP_ROWS:
        return rows[:MAX_MCP_ROWS]
    return rows


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
            text = redact("\n\n".join(parts))
            return text[:MAX_MCP_BYTES]
    if "data" in result_obj:
        return result_obj["data"]
    return result_obj
