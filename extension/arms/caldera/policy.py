"""Tier rules for the caldera arm (MITRE Caldera REST API)."""

from __future__ import annotations

import os
import re

ARM_ID = "caldera"
ENV_ENDPOINT = "CALDERA_ENDPOINT"
ENV_API_KEY = "CALDERA_API_KEY"
ENV_DISPATCH_SCOPE = "CALDERA_DISPATCH_SCOPE"

# Read tier: exact allowlisted GET endpoints (moderate-confidence
# inventory from the 2026-08-23 research pass; tighten when upstream
# docs are reachable again).
ALLOWED_VIEWS = {
    "abilities": "/api/abilities",
    "adversaries": "/api/adversaries",
    "agents": "/api/agents",
    "operations": "/api/operations",
    "results": "/api/results",
}

# Dispatch tier: schedule an operation profile against agents. Targets
# are the agents inside the operation, not an invoke argument, so
# dispatch authorizes on scope presence and audits target=unknown.
DISPATCH_ACTIONS = frozenset({"schedule_operation"})

_OPERATION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]*[A-Za-z0-9_-]$")

MAX_RESPONSE_CHARS = 512 * 1024
CALL_TIMEOUT = 30.0
SCAN_TIMEOUT = 60.0


def endpoint_url() -> str | None:
    from ..mcp_client import configured_http_url

    return configured_http_url(os.environ.get(ENV_ENDPOINT))


def api_key() -> str | None:
    key = os.environ.get(ENV_API_KEY, "").strip()
    return key or None


def operation_refusal(payload: dict) -> str | None:
    name = payload.get("operation")
    if not isinstance(name, str) or not name.strip():
        return "schedule_operation requires an operation id in args.operation"
    if not _OPERATION_NAME_RE.match(name.strip()):
        return "operation id must match [A-Za-z0-9 _-]"
    return None
