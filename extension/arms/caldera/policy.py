"""Connection and request input for the operator-configured Caldera API."""

from __future__ import annotations

import os
from urllib import parse as urllib_parse

ARM_ID = "caldera"
ENV_ENDPOINT = "CALDERA_ENDPOINT"
ENV_API_KEY = "CALDERA_API_KEY"
MAX_RESPONSE_CHARS = 512 * 1024
CALL_TIMEOUT = 30.0
CAVEATS = (
    "Requests go to the configured Caldera API endpoint. The operator "
    "chooses the path, method, query, and JSON body."
)


def endpoint_url() -> str | None:
    from ..mcp_client import configured_http_url

    return configured_http_url(os.environ.get(ENV_ENDPOINT))


def api_key() -> str | None:
    key = os.environ.get(ENV_API_KEY, "").strip()
    return key or None


def request_parts(args: dict) -> tuple[str | None, str | None, dict[str, str] | None, object, str | None]:
    """Validate HTTP request shape without restricting Caldera API operations."""
    if set(args) - {"path", "method", "query", "json"}:
        return None, None, None, None, "request takes args.path and optional args.method, args.query, args.json"
    path = args.get("path")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return None, None, None, None, "request path must start with one slash on the configured Caldera endpoint"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in path):
        return None, None, None, None, "request path contains control characters"
    parsed = urllib_parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None, None, None, None, "request path must stay on the configured Caldera endpoint"
    method = args.get("method", "GET")
    if not isinstance(method, str) or not method.isalpha() or method.upper() != method:
        return None, None, None, None, "request method must be an uppercase HTTP token"
    query = args.get("query", {})
    if not isinstance(query, dict) or any(
        not isinstance(key, str) or not key or any(ord(ch) < 0x20 for ch in key)
        or not isinstance(value, (str, int, float, bool))
        for key, value in query.items()
    ):
        return None, None, None, None, "request query must map names to scalar values"
    return path, method, {key: str(value) for key, value in query.items()}, args.get("json"), None
