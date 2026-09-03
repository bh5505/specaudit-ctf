"""Tier rules for the caldera arm (MITRE Caldera REST API)."""

from __future__ import annotations

import os
import re

ARM_ID = "caldera"
ENV_ENDPOINT = "CALDERA_ENDPOINT"
ENV_API_KEY = "CALDERA_API_KEY"
ENV_DISPATCH_SCOPE = "CALDERA_DISPATCH_SCOPE"

# Read tier: exact allowlisted v2 GET endpoints, verified against
# upstream mitre/caldera master on 2026-09-03 (v5.3.0 the latest tag;
# the documented v2 app is mounted at /api/v2). The operation REPORT is
# POST-only upstream and is excluded from this GET tier; the per-
# operation chain below (operation / operation_links / operation_facts)
# is its read-side replacement. The former legacy "results" view
# (/api/results) matched no documented route in either surface and was
# dropped rather than kept on faith.
ALLOWED_VIEWS = {
    "abilities": "/api/v2/abilities",
    "adversaries": "/api/v2/adversaries",
    "agents": "/api/v2/agents",
    "operations": "/api/v2/operations",
    "operations_summary": "/api/v2/operations/summary",
    "operation": "/api/v2/operations/{id}",
    "operation_links": "/api/v2/operations/{id}/links",
    "operation_facts": "/api/v2/facts/{operation_id}",
}

# Per-view argument whitelist: views without an entry take no
# arguments; the three {id} views take exactly one UUID-valued key
# (zap's digit-scoped scanId precedent). Fail closed on shape.
VIEW_PARAMS = {
    "operation": ("id",),
    "operation_links": ("id",),
    "operation_facts": ("operation_id",),
}

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

CAVEATS = (
    "v2 REST surface (mounted at /api/v2). The operation report is "
    "POST-only upstream and excluded from the read tier (use the "
    "per-operation views). The schedule_operation dispatch path is "
    "provisional pending upstream verification."
)

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


def view_params(action: str, payload: dict) -> tuple[dict[str, str], None] | tuple[None, str]:
    """Validate a read-view call's args; return (params, None) or (None, refusal).

    No-param views refuse any args; {id} views take exactly their one
    UUID-valued key. Fail closed on shape before any URL is built.
    """
    allowed = VIEW_PARAMS.get(action)
    if allowed is None:
        if payload:
            return None, "view actions take no arguments (fixed endpoints)"
        return {}, None
    key = allowed[0]
    extra = {k: v for k, v in payload.items() if k != key}
    if extra:
        return None, f"{action} takes only args.{key} (a UUID)"
    raw = payload.get(key)
    if not isinstance(raw, str) or not _UUID_RE.fullmatch(raw.strip()):
        return None, f"{action} requires an operation UUID in args.{key}"
    return {key: raw.strip()}, None
