"""Read views and dispatch actions for the zaproxy arm (native API)."""

from __future__ import annotations

import os
from urllib import parse as urllib_parse

ARM_ID = "zaproxy"
ENV_ENDPOINT = "ZAP_API_ENDPOINT"
ENV_API_KEY = "ZAP_API_KEY"
ENV_DISPATCH_SCOPE = "ZAP_DISPATCH_SCOPE"

# Read tier: exact allowlisted view endpoints (native JSON API GETs).
# Every param key is whitelisted per action; nothing else is forwarded.
ALLOWED_VIEWS = {
    "version": "/JSON/core/view/version/",
    "hosts": "/JSON/core/view/hosts/",
    "urls": "/JSON/core/view/urls/",
    "sites": "/JSON/core/view/sites/",
    "alerts": "/JSON/alert/view/alerts/",
    "alerts_summary": "/JSON/alert/view/alertsSummary/",
    "messages": "/JSON/core/view/messages/",
    "pscan_records": "/JSON/pscan/view/recordsToScan/",
    "ascan_status": "/JSON/ascan/view/status/",
    "ascan_policies": "/JSON/ascan/view/scanPolicies/",
    "spider_status": "/JSON/spider/view/status/",
    "contexts": "/JSON/context/view/contextList/",
}

# Per-action parameter whitelist. start/count are digits-only;
# baseurl must be an http(s) URL.
VIEW_PARAMS = {
    "alerts": ("baseurl", "start", "count"),
    "alerts_summary": ("baseurl",),
    "messages": ("start", "count"),
    "hosts": ("start", "count"),
    "urls": ("start", "count"),
}

# Dispatch tier: scan launches against a target URL.
DISPATCH_ACTIONS = {
    "ascan_scan": "/JSON/ascan/action/scan/",
    "spider_scan": "/JSON/spider/action/scan/",
}

# Everything else on the native API (other actions, mutations, shutdown,
# coreAction, network changes, users, snapshots) is not on any tier.

MAX_RESPONSE_CHARS = 512 * 1024
CALL_TIMEOUT = 30.0
SCAN_TIMEOUT = 120.0


def endpoint_url() -> str | None:
    """Return a validated http(s) base URL, else None."""
    from ..mcp_client import configured_http_url

    return configured_http_url(os.environ.get(ENV_ENDPOINT))


def clean_view_params(action: str, args: dict) -> tuple[dict | None, str | None]:
    """Whitelist and validate the params forwarded to a view endpoint.

    Returns (params, None) to proceed or (None, refusal) to fail closed.
    """
    allowed = VIEW_PARAMS.get(action, ())
    cleaned: dict[str, str] = {}
    for key, value in args.items():
        if key not in allowed:
            return None, f"parameter {key!r} is not allowed for {action!r}"
        if key in ("start", "count"):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None, f"parameter {key!r} must be a non-negative integer"
            cleaned[key] = str(value)
        elif key == "baseurl":
            if not isinstance(value, str) or not value.strip():
                return None, "parameter 'baseurl' must be a non-empty string"
            parsed = urllib_parse.urlparse(value.strip())
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                return None, "parameter 'baseurl' must be an http(s) URL"
            cleaned[key] = value.strip()
        else:
            return None, f"parameter {key!r} is not allowed for {action!r}"
    return cleaned, None


def dispatch_target_refusal(args: dict) -> tuple[str | None, str | None]:
    """Extract and validate the scan target URL from args."""
    raw = args.get("url")
    if not isinstance(raw, str) or not raw.strip():
        return None, "scan actions require a target URL in args.url"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return None, "scan target contains control characters"
    parsed = urllib_parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, "scan target must be an http(s) URL"
    return target, None
