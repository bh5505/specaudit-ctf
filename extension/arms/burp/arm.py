"""Curated Burp arm: allowlisted MCP tools over HTTP+SSE."""

from __future__ import annotations

import os
from typing import Any, Callable, Mapping

from ...contract import (
    TRANSPORT_MCP,
    ArmSpec,
    NotInstalledError,
    Result,
)
from .policy import (
    ARM_ID,
    ENV_ENDPOINT,
    LIST_ACTIONS,
    TRANSPORT_POLICY,
    detect_edition,
    merge_tool_args,
    refuse_reason,
)
from .sse import (
    MCP_CALL_TIMEOUT,
    SseMcpSession,
    configured_http_url,
    normalize_call_result,
    redact,
)

SessionFactory = Callable[..., Any]


def _default_session_factory(url: str, timeout: float = MCP_CALL_TIMEOUT) -> Any:
    return SseMcpSession(url, timeout=timeout, policy=TRANSPORT_POLICY)


class BurpArm:
    """Specialized transport for catalog id burp-mcp."""

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
            edition = detect_edition(names)
            if action in LIST_ACTIONS:
                return Result(
                    ok=True,
                    arm_id=spec.id,
                    action=action,
                    output={"edition": edition, "tools": tools},
                    error=None,
                )
            reason = refuse_reason(action, edition, names)
            if reason:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output={"edition": edition},
                    error=reason,
                )
            result_obj = session.call_tool(action, merge_tool_args(action, payload))
            data, meta = normalize_call_result(result_obj)
            if isinstance(data, dict) and data.get("isError"):
                detail = redact(str(data.get("error") or "tool error"))
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output={"edition": edition, "data": data, "meta": meta},
                    error=detail,
                )
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={"edition": edition, "data": data, "meta": meta},
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
