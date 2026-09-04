"""Curated caldera arm: allowlisted REST reads, gated operation scheduling."""

from __future__ import annotations

import json
import os
from typing import Any, Mapping
from urllib import error as urllib_error
from urllib import request as urllib_request

from ...contract import (
    TRANSPORT_MCP,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..dispatch import authorize, log_dispatch, stamp
from ..mcp_client import MAX_MCP_BYTES, redact
from .policy import (
    ALLOWED_VIEWS,
    ARM_ID,
    CALL_TIMEOUT,
    CAVEATS,
    DISPATCH_ACTIONS,
    ENV_API_KEY,
    ENV_DISPATCH_SCOPE,
    MAX_RESPONSE_CHARS,
    SCAN_TIMEOUT,
    api_key,
    endpoint_url,
    operation_refusal,
    view_params,
)


class CalderaArm:
    """Specialized transport for catalog id caldera.

    Read tier: exact allowlisted v2 GET endpoints with the documented
    `KEY` auth header; the three {id} views take one UUID argument.
    Dispatch tier: POST /api/operations/<name>/schedule, authorized by
    CALDERA_DISPATCH_SCOPE presence (targets are operation-internal),
    logged and stamped. The POST body is an empty JSON object and the
    schedule endpoint form is provisional: it matches neither verified
    official write route (PATCH /api/v2/operations/{id}, legacy PUT
    /api/rest index schedule), pending live-server verification.
    """

    ARM_ID = ARM_ID
    protocol = TRANSPORT_MCP

    def __init__(
        self,
        endpoint: str | None = None,
        call_timeout: float = CALL_TIMEOUT,
        scan_timeout: float = SCAN_TIMEOUT,
        urlopen=None,
    ) -> None:
        self._explicit = endpoint
        self.call_timeout = call_timeout
        self.scan_timeout = scan_timeout
        self._urlopen = urlopen or urllib_request.urlopen

    def base_url(self) -> str | None:
        if self._explicit is not None:
            from ..mcp_client import HttpTransportPolicy, configured_http_url

            return configured_http_url(self._explicit, HttpTransportPolicy.general_http())
        return endpoint_url()

    def installed(self, spec: ArmSpec) -> bool:
        return (
            spec.id == ARM_ID
            and self.base_url() is not None
            and api_key() is not None
        )

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        base = self.base_url()
        if spec.id != ARM_ID or base is None or api_key() is None:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in ALLOWED_VIEWS:
            params, refusal = view_params(action, payload)
            if refusal is not None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
            return self._get(spec, action, base, params)
        if action in DISPATCH_ACTIONS:
            extra = {k: v for k, v in payload.items() if k != "operation"}
            if extra:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error="schedule_operation takes only args.operation",
                )
            refusal = operation_refusal(payload)
            if refusal:
                return Result(
                    ok=False, arm_id=spec.id, action=action, output=None,
                    error=refusal,
                )
            scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, None)
            if scope is None:
                return Result(
                    ok=False, arm_id=spec.id, action=action, output=None,
                    error=refusal,
                )
            log_dispatch(ARM_ID, action, scope, None)
            return self._post_schedule(spec, action, base, payload, scope)
        if action in ("list_tools", "tools/list"):
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={
                    "read_views": sorted(ALLOWED_VIEWS),
                    "dispatch_actions": sorted(DISPATCH_ACTIONS),
                    "dispatch_armed": os.environ.get(
                        ENV_DISPATCH_SCOPE, ""
                    ).strip()
                    != "",
                    "caveats": CAVEATS,
                },
                error=None,
            )
        return Result(
            ok=False,
            arm_id=spec.id,
            action=action,
            output=None,
            error=f"action {action!r} is not on any tier "
            "(exact read endpoints and gated schedule_operation only)",
        )

    def _headers(self, content_type: str | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": "specaudit-ctf-extension/1.0",
            "Accept": "application/json",
            # Upstream auth_svc reads the literal header name KEY.
            "KEY": api_key() or "",
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _get(
        self, spec: ArmSpec, action: str, base: str, params: dict[str, str]
    ) -> Result:
        path = ALLOWED_VIEWS[action]
        for key, value in params.items():
            path = path.replace("{" + key + "}", _quote(value))
        url = base.rstrip("/") + path
        req = urllib_request.Request(
            url, headers=self._headers(), method="GET"
        )
        try:
            parsed = self._read(req, self.call_timeout)
        except _HttpFailure as exc:
            return Result(
                ok=False, arm_id=spec.id, action=action, output=None,
                error=str(exc),
            )
        return Result(
            ok=True, arm_id=spec.id, action=action, output=parsed, error=None
        )

    def _post_schedule(
        self,
        spec: ArmSpec,
        action: str,
        base: str,
        payload: dict,
        scope,
    ) -> Result:
        name = payload["operation"].strip()
        url = base.rstrip("/") + f"/api/operations/{_quote(name)}/schedule"
        body = b"{}"
        req = urllib_request.Request(
            url,
            data=body,
            headers=self._headers("application/json"),
            method="POST",
        )
        try:
            parsed = self._read(req, self.scan_timeout)
        except _HttpFailure as exc:
            return Result(
                ok=False, arm_id=spec.id, action=action, output=None,
                error=str(exc),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"dispatch": stamp(scope, None), "result": parsed},
            error=None,
        )

    def _read(self, req, timeout: float) -> Any:
        try:
            with self._urlopen(req, timeout=timeout) as resp:
                raw = resp.read(MAX_MCP_BYTES + 1)
                if len(raw) > MAX_MCP_BYTES:
                    raise RuntimeError("response exceeds cap")
        except urllib_error.HTTPError as exc:
            raise _HttpFailure(self._http_error_text(exc)) from exc
        except (urllib_error.URLError, OSError) as exc:
            raise _HttpFailure(redact(f"endpoint unreachable: {exc}")) from exc
        except RuntimeError as exc:
            raise _HttpFailure(str(exc)) from exc
        text = raw.decode("utf-8", errors="replace")[:MAX_RESPONSE_CHARS]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return redact(text)

    def _http_error_text(self, exc: urllib_error.HTTPError) -> str:
        try:
            detail = exc.read(2048).decode("utf-8", errors="replace")
        except OSError:
            detail = str(exc)
        return redact(f"HTTP {exc.code}: {detail[:800]}")


def _quote(name: str) -> str:
    from urllib import parse as urllib_parse

    return urllib_parse.quote(name, safe="")


class _HttpFailure(Exception):
    """Internal: a failed REST call, message already redacted."""
