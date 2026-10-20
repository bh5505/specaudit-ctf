"""Direct requests to the operator-configured Caldera REST API."""

from __future__ import annotations

import json
from typing import Any, Mapping
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from ...contract import TRANSPORT_MCP, ArmSpec, NotInstalledError, Result
from ..mcp_client import MAX_MCP_BYTES, redact
from .policy import (
    ARM_ID, CALL_TIMEOUT, CAVEATS, MAX_RESPONSE_CHARS,
    api_key, endpoint_url, request_parts,
)


class CalderaArm:
    """Send a chosen REST request to a configured Caldera instance."""

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
        return spec.id == ARM_ID and self.base_url() is not None and api_key() is not None

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        base = self.base_url()
        key = api_key()
        if spec.id != ARM_ID or base is None or key is None:
            raise NotInstalledError(spec.id)
        if action in ("list_tools", "tools/list"):
            return Result(True, spec.id, action, {
                "actions": ["request", "list_tools", "tools/list"],
                "input": "request {path, method?, query?, json?}",
                "caveats": CAVEATS,
            })
        if action != "request":
            return Result(False, spec.id, action, error=f"unknown action {action!r}; use request")
        path, method, query, json_body, refusal = request_parts(dict(args))
        if refusal:
            return Result(False, spec.id, action, error=refusal)
        assert path is not None and method is not None and query is not None
        url = base.rstrip("/") + path
        if query:
            url += ("&" if "?" in url else "?") + urllib_parse.urlencode(query)
        data = None
        headers = {
            "User-Agent": "specaudit-ctf-extension/1.0",
            "Accept": "application/json",
            "KEY": key,
        }
        if json_body is not None:
            try:
                data = json.dumps(json_body).encode("utf-8")
            except (TypeError, ValueError, UnicodeError):
                return Result(False, spec.id, action, error="request json must be JSON-serializable")
            headers["Content-Type"] = "application/json"
        req = urllib_request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._urlopen(req, timeout=self.call_timeout) as resp:
                raw = resp.read(MAX_MCP_BYTES + 1)
                if len(raw) > MAX_MCP_BYTES:
                    raise RuntimeError("response exceeds cap")
        except urllib_error.HTTPError as exc:
            return Result(False, spec.id, action, error=self._http_error_text(exc))
        except (urllib_error.URLError, OSError, ValueError, RuntimeError) as exc:
            return Result(False, spec.id, action, error=redact(f"Caldera API request failed: {exc}"))
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
    """Keep the configured API credential on its original endpoint."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None
