"""Curated metasploit arm: allowlisted listings and execution tools."""

from __future__ import annotations

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
    SseMcpSession,
    redact,
)
from .policy import (
    ARM_ID,
    LIST_ACTIONS,
    endpoint_url,
)

SessionFactory = Callable[..., Any]


def _default_session_factory(url: str, timeout: float = MCP_CALL_TIMEOUT) -> Any:
    return SseMcpSession(url, timeout=timeout)


class MetasploitArm:
    """Specialized transport for catalog id metasploit-mcp.

    The listing tools and the execution tools (run_exploit,
    run_auxiliary_module, run_post_module, generate_payload,
    send_session_command, terminate_session, start_listener, stop_job)
    all invoke through the operator-run loopback SSE server based on
    their real arguments and the endpoint configuration. The competent
    human operator is responsible for choosing targets and for how the
    tool is used. Upstream speaks legacy HTTP+SSE (verified 2026-08-24),
    so the shared SseMcpSession is the client and the session factory
    stays injectable for a later swap.
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

            return configured_http_url(self._endpoint_arg)
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
                        "tools": tools[:MAX_MCP_ROWS],
                        "actions": sorted(names),
                    },
                    error=None,
                )
            if action not in names:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=f"tool {action!r} is not available on the server",
                )
            result_obj = session.call_tool(action, payload)
            data = _normalize(result_obj)
            if isinstance(data, dict) and data.get("isError"):
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output={"data": data},
                    error=redact(str(data.get("error") or "tool error")),
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
