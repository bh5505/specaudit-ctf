"""Curated metasploit arm: allowlisted listings, scope-gated execution."""

from __future__ import annotations

import os
from typing import Any, Callable, Mapping

from ...contract import (
    TRANSPORT_MCP,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..dispatch import authorize, log_dispatch, stamp, target_in_scope
from ..mcp_client import (
    MAX_MCP_ROWS,
    MCP_CALL_TIMEOUT,
    SseMcpSession,
    redact,
)
from .policy import (
    ALLOWED_TOOLS,
    ARM_ID,
    DISPATCH_TOOLS,
    ENV_DISPATCH_SCOPE,
    LIST_ACTIONS,
    audit_target,
    endpoint_url,
    extract_targets,
)

SessionFactory = Callable[..., Any]


class MetasploitArm:
    """Specialized transport for catalog id metasploit-mcp.

    Read tier: the four list_* tools. Dispatch tier: the eight
    execution tools, gated by METASPLOIT_DISPATCH_SCOPE - host-bearing
    tools (run_exploit, run_auxiliary_module) require every RHOSTS/RHOST
    member to be inside the scope; session/job tools authorize on scope
    presence and audit session:<id>/job:<id>. Upstream speaks legacy
    HTTP+SSE (verified 2026-08-24), so the shared SseMcpSession is the
    client and the session factory stays injectable for a later swap.
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
        self._session_factory = session_factory or SseMcpSession

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
                        "read_tier": sorted(ALLOWED_TOOLS),
                        "dispatch_tier": sorted(DISPATCH_TOOLS),
                        "dispatch_armed": os.environ.get(
                            ENV_DISPATCH_SCOPE, ""
                        ).strip()
                        != "",
                    },
                    error=None,
                )
            if action in ALLOWED_TOOLS:
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
            if action in DISPATCH_TOOLS:
                if action not in names:
                    return Result(
                        ok=False,
                        arm_id=spec.id,
                        action=action,
                        output=None,
                        error=f"tool {action!r} is not available on the server",
                    )
                targets, refusal = extract_targets(payload)
                if refusal:
                    return Result(
                        ok=False,
                        arm_id=spec.id,
                        action=action,
                        output=None,
                        error=refusal,
                    )
                scope = None
                if targets is not None:
                    scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, None)
                    if scope is None:
                        return Result(
                            ok=False,
                            arm_id=spec.id,
                            action=action,
                            output=None,
                            error=refusal,
                        )
                    for host in targets:
                        if not target_in_scope(host, scope):
                            return Result(
                                ok=False,
                                arm_id=spec.id,
                                action=action,
                                output=None,
                                error=f"target {host!r} is outside the armed "
                                "dispatch scope",
                            )
                else:
                    scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, None)
                    if scope is None:
                        return Result(
                            ok=False,
                            arm_id=spec.id,
                            action=action,
                            output=None,
                            error=refusal,
                        )
                audited = audit_target(payload, targets)
                log_dispatch(ARM_ID, action, scope, audited)
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
                    output={
                        "dispatch": stamp(scope, audited),
                        "data": data,
                    },
                    error=None,
                )
            reason = "is not on the allowlist"
            if action in {"exploit", "run", "payload"}:
                reason = (
                    "is not an upstream tool name; the dispatch tier is "
                    f"{sorted(DISPATCH_TOOLS)}"
                )
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"tool {action!r} {reason}",
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
