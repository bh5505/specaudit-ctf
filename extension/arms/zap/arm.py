"""Direct requests to the operator-configured ZAP native API."""

from __future__ import annotations

import json
import os
from typing import Any, Mapping
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from ...contract import TRANSPORT_MCP, ArmSpec, NotInstalledError, Result
from ..mcp_client import MAX_MCP_BYTES, redact
from .policy import (
    ARM_ID, CALL_TIMEOUT, CAVEATS, ENV_API_KEY, MAX_RESPONSE_CHARS,
    endpoint_url, request_parts,
)


class ZapArm:
    """Send a chosen native API request to a configured ZAP instance."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_MCP

    def __init__(self, endpoint: str | None = None, call_timeout: float = CALL_TIMEOUT,
                 urlopen=None) -> None:
        self._explicit = endpoint
        self.call_timeout = call_timeout
        self._urlopen = urlopen if urlopen is not None else urllib_request.build_opener(_NoRedirect()).open

    def base_url(self) -> str | None:
        if self._explicit is not None:
            from ..mcp_client import configured_http_url
            return configured_http_url(self._explicit)
        return endpoint_url()

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID and self.base_url() is not None

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        base = self.base_url()
        if spec.id != ARM_ID or base is None:
            raise NotInstalledError(spec.id)
        if action in ("list_tools", "tools/list"):
            return Result(True, spec.id, action, {
                "actions": ["request", "list_tools", "tools/list"],
                "input": "request {path, method?, params?}",
                "caveats": CAVEATS,
            })
        if action != "request":
            return Result(False, spec.id, action, error=f"unknown action {action!r}; use request")
        path, method, params, refusal = request_parts(dict(args))
        if refusal:
            return Result(False, spec.id, action, error=refusal)
        assert path is not None and method is not None and params is not None
        url = base.rstrip("/") + path
        encoded = urllib_parse.urlencode(params)
        data = None
        if method in ("GET", "HEAD"):
            if encoded:
                url += ("&" if "?" in url else "?") + encoded
        else:
            data = encoded.encode("utf-8")
        headers = {
            "User-Agent": "specaudit-ctf-extension/1.0",
            "Accept": "application/json",
        }
        key = os.environ.get(ENV_API_KEY, "").strip()
        if key:
            headers["X-ZAP-API-Key"] = key
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib_request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._urlopen(req, timeout=self.call_timeout) as resp:
                raw = resp.read(MAX_MCP_BYTES + 1)
                if len(raw) > MAX_MCP_BYTES:
                    raise RuntimeError("response exceeds cap")
        except urllib_error.HTTPError as exc:
            return Result(False, spec.id, action, error=self._http_error_text(exc))
        except (urllib_error.URLError, OSError, ValueError, RuntimeError) as exc:
            return Result(False, spec.id, action, error=redact(f"ZAP API request failed: {exc}"))
        text = raw.decode("utf-8", errors="replace")[:MAX_RESPONSE_CHARS]
        try:
            output = json.loads(text)
        except json.JSONDecodeError:
            output = redact(text)
        return Result(True, spec.id, action, output)

    @staticmethod
    def _http_error_text(exc: urllib_error.HTTPError) -> str:
        try:
            detail = exc.read(2048).decode("utf-8", errors="replace")
        except OSError:
            detail = str(exc)
        return redact(f"HTTP {exc.code}: {detail[:800]}")


class _NoRedirect(urllib_request.HTTPRedirectHandler):
    """Keep the configured ZAP API credential on its original endpoint."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None
