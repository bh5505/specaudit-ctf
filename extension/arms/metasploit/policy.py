"""Two-tier rules for the metasploit-mcp arm (GH05TCREW/MetasploitMCP).

Upstream speaks legacy HTTP+SSE by default (README, verified 2026-08-24
consult), so this arm rides the shared SseMcpSession (burp path).
"""

from __future__ import annotations

import os
from urllib import parse as urllib_parse

from ..policy_base import ToolPolicy

ARM_ID = "metasploit-mcp"
ENV_ENDPOINT = "METASPLOIT_MCP_ENDPOINT"
ENV_DISPATCH_SCOPE = "METASPLOIT_DISPATCH_SCOPE"

# Read tier: module/payload/session/job listings.
ALLOWED_TOOLS = frozenset(
    {
        "list_exploits",
        "list_payloads",
        "list_active_sessions",
        "list_listeners",
    }
)

# Dispatch tier: execution surfaces. run_exploit / run_auxiliary_module
# carry host targets (RHOSTS/RHOST) that are scope-matched; the
# scope-presence tools (no host key) are run_post_module,
# generate_payload, send_session_command, terminate_session,
# start_listener, stop_job - they authorize on scope presence and
# audit the session or job id. Residual risk: send_session_command
# runs a command inside an existing session and scope presence cannot
# verify which host that session is on - operators who do not accept
# that simply leave the arm unarmed.
DISPATCH_TOOLS = frozenset(
    {
        "run_exploit",
        "run_auxiliary_module",
        "run_post_module",
        "generate_payload",
        "send_session_command",
        "terminate_session",
        "start_listener",
        "stop_job",
    }
)

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

# Target-bearing option names, closed set.
TARGET_KEYS = ("RHOSTS", "RHOST")
SESSION_KEYS = ("SESSION", "SESSION_ID", "JOB_ID", "LPORT")

_TOOL_POLICY = ToolPolicy(allowed=ALLOWED_TOOLS | DISPATCH_TOOLS, blocked=frozenset())


def endpoint_url() -> str | None:
    from ..mcp_client import configured_http_url

    return configured_http_url(os.environ.get(ENV_ENDPOINT))


def extract_targets(payload: dict) -> tuple[list[str] | None, str | None]:
    """Extract host targets from the closed RHOSTS/RHOST key set.

    Returns (targets, refusal). Every member of every target value must
    be individually scope-matchable, so ranges and CIDR values are
    refused (the caller must enumerate). None targets means the action
    authorizes on scope presence only (session/job tools).
    """
    if not any(key in payload for key in TARGET_KEYS):
        return None, None
    found: list[str] = []
    for key in TARGET_KEYS:
        value = payload.get(key)
        if value is None:
            continue
        members = (
            value.replace(",", " ").split()
            if isinstance(value, str)
            else [value]
        )
        for member in members:
            text = str(member).strip()
            if not text:
                continue
            if "/" in text or text.startswith("-"):
                return None, (
                    f"{key} values must be enumerated hosts, not ranges "
                    f"or flags: {text}"
                )
            if "-" in text and _looks_like_range(text):
                return None, f"{key} values must be enumerated hosts, not ranges: {text}"
            parsed = urllib_parse.urlparse(text if "://" in text else "//" + text)
            host = parsed.hostname or text
            if " " in host or "@" in host:
                return None, f"{key} value is not a host: {text}"
            # Unbracketed IPv6 urlparse-mangles to a fragment; require
            # brackets so the audited target is the executed target.
            if ":" in text and not text.startswith("["):
                return None, (
                    f"{key} IPv6 targets must be bracketed: {text}"
                )
            found.append(host)
    if not found:
        return None, "RHOSTS/RHOST present but no enumerable target"
    return found, None


def _looks_like_range(text: str) -> bool:
    parts = text.split("-")
    return len(parts) == 2 and all(p.replace(".", "").isdigit() for p in parts)


def audit_target(payload: dict, targets: list[str] | None) -> str | None:
    """Canonical audit target: hosts, else session:<id> / job:<id>."""
    if targets:
        return ",".join(targets)
    for key in ("SESSION", "SESSION_ID", "JOB_ID"):
        if key in payload:
            kind = "job" if key.startswith("JOB") else "session"
            return f"{kind}:{payload[key]}"
    return None
