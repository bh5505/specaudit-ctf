"""Curated zaproxy arm: allowlisted native-API reads, gated scan dispatch."""

from __future__ import annotations

import json
import os
from typing import Any, Mapping
from urllib import error as urllib_error
from urllib import parse as urllib_parse
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
    clean_view_params,
    dispatch_target_refusal,
    endpoint_url,
)


class ZapArm:
    """Specialized transport for catalog id zaproxy.

    Read tier: exact allowlisted ``/JSON/*/view/`` GET endpoints with
    per-action parameter whitelists - the native API's read surface.
    Dispatch tier: ``ascan_scan`` / ``spider_scan`` POSTs, authorized
    by an armed ZAP_DISPATCH_SCOPE containing the target host, logged,
    and stamped. Every other native API endpoint is on no tier.
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
        return spec.id == ARM_ID and self.base_url() is not None

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        base = self.base_url()
        if spec.id != ARM_ID or base is None:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in ALLOWED_VIEWS:
            return self._view(spec, action, payload, base)
        if action in DISPATCH_ACTIONS:
            return self._dispatch_scan(spec, action, payload, base)
        if action in ("list_tools", "tools/list"):
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={
                    "read_views": sorted(ALLOWED_VIEWS),
                    "dispatch_actions": sorted(DISPATCH_ACTIONS),
                    "dispatch_armed": os.environ.get(ENV_DISPATCH_SCOPE, "").strip()
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
            error=f"action {action!r} is not on the allowlist "
            "(exact view endpoints and gated scan actions only)",
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "specaudit-ctf-extension/1.0",
            "Accept": "application/json",
        }
        key = os.environ.get(ENV_API_KEY, "").strip()
        if key:
            headers["X-ZAP-API-Key"] = key
        return headers

    def _view(
        self, spec: ArmSpec, action: str, payload: dict, base: str
    ) -> Result:
        params, refusal = clean_view_params(action, payload)
        if refusal is not None:
            return Result(
                ok=False, arm_id=spec.id, action=action, output=None, error=refusal
            )
        url = base.rstrip("/") + ALLOWED_VIEWS[action]
        if params:
            url += "?" + urllib_parse.urlencode(params)
        try:
            data = self._fetch(url, self.call_timeout)
        except _HttpFailure as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=str(exc),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=data,
            error=None,
        )

    def _dispatch_scan(
        self, spec: ArmSpec, action: str, payload: dict, base: str
    ) -> Result:
        extra = {k: v for k, v in payload.items() if k != "url"}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="scan actions take only args.url (fixed endpoint)",
            )
        target, refusal = dispatch_target_refusal(payload)
        if target is None:
            return Result(
                ok=False, arm_id=spec.id, action=action, output=None, error=refusal
            )
        scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, target)
        if scope is None:
            return Result(
                ok=False, arm_id=spec.id, action=action, output=None, error=refusal
            )
        log_dispatch(ARM_ID, action, scope, target)
        url = base.rstrip("/") + DISPATCH_ACTIONS[action]
        body = urllib_parse.urlencode({"url": target}).encode("utf-8")
        headers = self._headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib_request.Request(url, data=body, headers=headers, method="POST")
        try:
            with self._urlopen(req, timeout=self.scan_timeout) as resp:
                raw = resp.read(MAX_MCP_BYTES + 1)
                if len(raw) > MAX_MCP_BYTES:
                    raise RuntimeError("response exceeds cap")
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
        except urllib_error.HTTPError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=self._http_error_text(exc),
            )
        except (urllib_error.URLError, OSError, ValueError, RuntimeError) as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(f"scan dispatch failed: {exc}"),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"dispatch": stamp(scope, target), "result": parsed},
            error=None,
        )

    def _fetch(self, url: str, timeout: float) -> Any:
        req = urllib_request.Request(url, headers=self._headers(), method="GET")
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


class _HttpFailure(Exception):
    """Internal: a failed native-API read, message already redacted."""
