"""Namespace allowlist and credential rules for the Prowler arm.

Upstream prowler-mcp tool names are namespaced but not yet pinned in
public docs (verified 2026-08-23: prefixes prowler_, prowler_cloud_,
prowler_hub_, prowler_docs_). This policy is therefore prefix-based and
deliberately narrow: findings/docs/hub reads only, the cloud
scan-orchestration namespace blocked entirely, and mutation keywords
refused on sight. Exact names should be pinned here once upstream
documents them. (This is why the arm does not use the exact-name
ToolPolicy from policy_base: namespaces, not names, are the unit
of allowance here.)
"""

from __future__ import annotations

import re

from ..mcp_client import HttpTransportPolicy
from ..policy_base import DEFAULT_TOOL_PATTERN

ARM_ID = "prowler-mcp"
ENV_ENDPOINT = "PROWLER_MCP_ENDPOINT"
# Remote-https endpoint, stated EXPLICITLY (the shared client defaults
# to the same policy when none is passed — the arm does not rely on
# that default). Loopback and plain-http endpoints are refused
# fail-closed by the shared gate; Prowler reads surface cloud findings,
# so the arm is treated as an egress-capable remote surface.
TRANSPORT_POLICY = HttpTransportPolicy.remote_https()

# Install also requires cloud credentials in the environment. AWS is the
# documented first cloud; add more when upstream surfaces them.
CREDENTIAL_ENVS = ("AWS_ACCESS_KEY_ID", "AWS_PROFILE")

ALLOWED_PREFIXES = ("prowler_", "prowler_docs_", "prowler_hub_")

# Scan orchestration against live cloud accounts stays off this arm.
BLOCKED_PREFIXES = ("prowler_cloud_",)

# Even inside allowed namespaces, anything that smells like a mutation
# or a live cloud-scan trigger (the upstream prowler_scan_* family) is
# refused: this arm surfaces findings, it does not dispatch scans.
BLOCKED_KEYWORD_RE = re.compile(
    r"(write|remediat|fix|delete|updat|creat|deploy|trigger|start|stop"
    r"|scan|run|exec|launch)",
    re.IGNORECASE,
)

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})


def credentials_present() -> bool:
    import os

    return any(os.environ.get(name) for name in CREDENTIAL_ENVS)


def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Return the refusal reason for *tool*, or None to proceed."""
    if not DEFAULT_TOOL_PATTERN.match(tool):
        return f"invalid tool name: {tool!r}"
    if tool.startswith(BLOCKED_PREFIXES):
        return f"tool {tool!r} is blocked (cloud scan orchestration namespace)"
    if BLOCKED_KEYWORD_RE.search(tool):
        return f"tool {tool!r} is blocked (mutation or scan-dispatch keyword)"
    if not tool.startswith(ALLOWED_PREFIXES):
        return f"tool {tool!r} is not on the namespace allowlist"
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None
