"""Connection and request input for the operator-configured ZAP native API."""

from __future__ import annotations

import os
from urllib import parse as urllib_parse

ARM_ID = "zaproxy"
ENV_ENDPOINT = "ZAP_API_ENDPOINT"
ENV_API_KEY = "ZAP_API_KEY"
CALL_TIMEOUT = 30.0
MAX_RESPONSE_CHARS = 512 * 1024
CAVEATS = (
    "Requests go to the configured ZAP API endpoint. The operator chooses "
    "the API path, method, parameters, and any scan target."
)


def endpoint_url() -> str | None:
    """Return a usable ZAP API base URL, else None."""
    from ..mcp_client import configured_http_url

    return configured_http_url(os.environ.get(ENV_ENDPOINT))


def request_parts(args: dict) -> tuple[str | None, str | None, dict[str, str] | None, str | None]:
    """Validate HTTP request shape, without restricting ZAP API operations."""
    if set(args) - {"path", "method", "params"}:
        return None, None, None, "request takes args.path, optional args.method and args.params"
    path = args.get("path")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return None, None, None, "request path must start with one slash on the configured ZAP endpoint"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in path):
        return None, None, None, "request path contains control characters"
    parsed = urllib_parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None, None, None, "request path must stay on the configured ZAP endpoint"
    method = args.get("method", "GET")
    if not isinstance(method, str) or not method.isalpha() or method.upper() != method:
        return None, None, None, "request method must be an uppercase HTTP token"
    params = args.get("params", {})
    if not isinstance(params, dict) or any(
        not isinstance(key, str) or not key or any(ord(ch) < 0x20 for ch in key)
        or not isinstance(value, (str, int, float, bool))
        for key, value in params.items()
    ):
        return None, None, None, "request params must map names to scalar values"
    return path, method, {key: str(value) for key, value in params.items()}, None
