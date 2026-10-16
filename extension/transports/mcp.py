"""Thin MCP JSON-RPC client (tools/call)."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Mapping, Sequence
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from ..contract import (
    TRANSPORT_MCP,
    ArmSpec,
    NotInstalledError,
    Result,
)

_MAX_BYTES = 1024 * 1024


class McpTransport:
    protocol = TRANSPORT_MCP

    def __init__(
        self,
        endpoints: Mapping[str, str] | None = None,
        stdio_cmds: Mapping[str, Sequence[str]] | None = None,
        token: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._endpoints = {
            key: value.strip()
            for key, value in (endpoints or {}).items()
            if value and value.strip()
        }
        # Preserve explicit empty list vs absent: empty argv means
        # "configured but not installed" (parity with CliTransport which
        # uses `is not None`). Discard only when value is None/missing.
        self._stdio_cmds = {
            key: list(value) for key, value in (stdio_cmds or {}).items() if value is not None
        }
        self.token = token
        self.timeout = timeout

    def installed(self, spec: ArmSpec) -> bool:
        if spec.id in self._endpoints:
            return True
        cmd = self._stdio_cmds.get(spec.id)
        return bool(cmd)

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        endpoint = self._endpoints.get(spec.id)
        stdio_cmd = self._stdio_cmds.get(spec.id)
        if not endpoint and not stdio_cmd:
            raise NotInstalledError(spec.id)
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": action, "arguments": dict(args)},
        }
        try:
            if endpoint:
                body = self._call_http(endpoint, payload)
            else:
                assert stdio_cmd is not None
                body = self._call_stdio(stdio_cmd, payload)
        except Exception as exc:  # noqa: BLE001 - surface as Result, stay closed
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=str(exc),
            )
        if not isinstance(body, dict):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="malformed JSON-RPC response",
            )
        if "error" in body and body["error"] is not None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=body.get("error"),
                error=_error_text(body.get("error")),
            )
        result = body.get("result")
        if not isinstance(result, dict):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=result,
                error="malformed tool result",
            )
        if result.get("isError"):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=result,
                error=_result_error_text(result),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=result,
            error=None,
        )

    def _call_http(self, endpoint: str, payload: dict[str, Any]) -> Any:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib_request.Request(
            endpoint, data=data, headers=headers, method="POST"
        )
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(_MAX_BYTES + 1)
        except HTTPError as exc:
            # HTTPError subclasses URLError, so this must be caught first.
            detail = exc.read(4096).decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
            raise RuntimeError(f"HTTP {exc.code}: {detail[:1000]}") from exc
        except URLError as exc:
            raise RuntimeError(f"MCP endpoint unreachable: {exc}") from exc
        if len(raw) > _MAX_BYTES:
            raise RuntimeError(f"response exceeds {_MAX_BYTES} bytes")
        return json.loads(raw.decode("utf-8"))

    def _call_stdio(self, argv: Sequence[str], payload: dict[str, Any]) -> Any:
        line = json.dumps(payload) + "\n"
        proc = subprocess.run(
            list(argv),
            input=line,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=self.timeout,
            check=False,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            raise RuntimeError(detail)
        # Guard total stdout size before parsing individual lines (first JSON line
        # check alone would miss large trailing output). Reuse _MAX_BYTES.
        if len(proc.stdout.encode("utf-8")) > _MAX_BYTES:
            raise RuntimeError(f"response exceeds {_MAX_BYTES} bytes")
        for candidate in proc.stdout.splitlines():
            stripped = candidate.strip()
            if stripped.startswith("{"):
                parsed = json.loads(stripped)
                if len(stripped.encode("utf-8")) > _MAX_BYTES:
                    raise RuntimeError(f"response exceeds {_MAX_BYTES} bytes")
                return parsed
        raise RuntimeError("no JSON-RPC response")


def _error_text(error: Any) -> str:
    if isinstance(error, dict):
        message = error.get("message")
        if message:
            return str(message)
        return json.dumps(error, sort_keys=True)
    return str(error)


def _result_error_text(result: Any) -> str:
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and first.get("text"):
                return str(first["text"])
    return "tool error"
