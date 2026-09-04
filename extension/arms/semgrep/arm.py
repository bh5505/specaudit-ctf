"""Curated Semgrep arm: first-party CLI scans + MCP reads.

Primary integration point is the semgrep CLI (local rule scans with an
inline rule pack; the archived MCP adapter repo is implementation
minutiae). MCP reads over Streamable HTTP remain available when
SEMGREP_MCP_ENDPOINT names an operator-configured https endpoint on
the hardened transport.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
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
    configured_http_url,
    redact,
)
from .policy import (
    ALLOWED_TOOLS,
    ARM_ID,
    ARMING,
    CAVEATS,
    ENV_ENDPOINT,
    ENV_SCAN_ROOT,
    LIST_ACTIONS,
    MAX_FINDINGS,
    TIMEOUT_SECONDS,
    TRANSPORT_POLICY,
    refuse_reason,
    resolve_binary,
    resolve_target,
    scan_config_refusal,
    scan_root,
)

SessionFactory = Callable[..., Any]


def _default_session_factory(url: str, timeout: float = MCP_CALL_TIMEOUT) -> Any:
    return StreamableHttpClient(url, timeout=timeout, policy=TRANSPORT_POLICY)


class SemgrepArm:
    """Specialized transport for catalog id semgrep-mcp."""

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
        if spec.id != ARM_ID:
            return False
        # Either surface installs the arm: the CLI binary or the MCP
        # endpoint.
        return resolve_binary() is not None or self.endpoint_url() is not None

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        endpoint = self.endpoint_url()
        if endpoint is None and action in ("semgrep_scan", *LIST_ACTIONS):
            # No MCP endpoint: the first-party CLI is the surface.
            if action in LIST_ACTIONS:
                return self._cli_list_tools(spec, action)
            return self._cli_scan(spec, action, dict(args))
        if endpoint is None:
            if resolve_binary() is None:
                raise NotInstalledError(spec.id)
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=(
                    "MCP reads require SEMGREP_MCP_ENDPOINT; only "
                    "list_tools and semgrep_scan run on the CLI"
                ),
            )
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
            if reason is None and action == "semgrep_scan":
                reason = scan_config_refusal(payload)
            if reason:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=reason,
                )
            result_obj = session.call_tool(action, payload)
            data, meta = _normalize_call_result(result_obj)
            if isinstance(data, dict) and data.get("isError"):
                detail = redact(str(data.get("error") or "tool error"))
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output={"data": data, "meta": meta},
                    error=detail,
                )
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={"data": data, "meta": meta},
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

    def _cli_list_tools(self, spec: ArmSpec, action: str) -> Result:
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "surface": "cli",
                "read_actions": sorted(LIST_ACTIONS),
                "mcp_endpoint_actions": sorted(ALLOWED_TOOLS),
                "dispatch_actions": ["semgrep_scan"],
                "dispatch_armed": scan_root() is not None,
                "caveats": CAVEATS,
                "arming": ARMING,
            },
            error=None,
        )

    def _cli_scan(
        self, spec: ArmSpec, action: str, payload: dict[str, Any]
    ) -> Result:
        binary = resolve_binary()
        if binary is None:
            raise NotInstalledError(spec.id)
        refusal = scan_config_refusal(payload)
        if refusal:
            return Result(
                ok=False, arm_id=spec.id, action=action, output=None, error=refusal
            )
        target, refusal = resolve_target(payload)
        if refusal:
            return Result(
                ok=False, arm_id=spec.id, action=action, output=None, error=refusal
            )
        config_fd, config_path = tempfile.mkstemp(
            prefix="semgrep-config-", suffix=".yaml"
        )
        argv = [
            binary,
            "scan",
            "--config",
            config_path,
            "--json",
            "--metrics=off",
            target,
        ]
        try:
            with os.fdopen(config_fd, "w", encoding="utf-8") as fh:
                fh.write(str(payload["config"]))
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error="semgrep_scan timed out after %ss" % TIMEOUT_SECONDS,
                )
            except OSError as exc:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=redact(str(exc)),
                )
            if proc.returncode != 0:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=redact(
                        proc.stderr[-800:] or ("semgrep exited %s" % proc.returncode)
                    ),
                )
            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error="semgrep produced invalid JSON output",
                )
            results = report.get("results") or []
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={
                    "target": target,
                    "total": len(results),
                    "results": results[:MAX_FINDINGS],
                    "errors": (report.get("errors") or [])[:50],
                    "truncated": len(results) > MAX_FINDINGS,
                },
                error=None,
            )
        finally:
            try:
                os.unlink(config_path)
            except OSError:
                pass


def _cap_rows(rows: list[Any]) -> list[Any]:
    if len(rows) > MAX_MCP_ROWS:
        return rows[:MAX_MCP_ROWS]
    return rows


def _normalize_call_result(result_obj: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Normalize a CallToolResult into (data, meta), row-capped."""
    meta: dict[str, Any] = {"clamped": False}
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
    if isinstance(content, list) and content:
        parts = [
            str(block["text"])
            for block in content
            if isinstance(block, dict) and "text" in block
        ]
        text = "\n\n".join(parts)
        if text:
            rows: list[Any] = []
            for chunk in (c.strip() for c in text.split("\n\n") if c.strip()):
                try:
                    rows.append(json.loads(chunk))
                except json.JSONDecodeError:
                    rows.append(chunk)
            if len(rows) == 1:
                return rows[0], meta
            if len(rows) > MAX_MCP_ROWS:
                rows = rows[:MAX_MCP_ROWS]
                meta["clamped"] = True
                meta["max_rows"] = MAX_MCP_ROWS
            return rows, meta
    if isinstance(result_obj.get("data"), (list, dict, str)):
        data = result_obj["data"]
        if isinstance(data, list) and len(data) > MAX_MCP_ROWS:
            data = data[:MAX_MCP_ROWS]
            meta["clamped"] = True
            meta["max_rows"] = MAX_MCP_ROWS
        return data, meta
    return result_obj, meta
