"""Allowlist, blocked class, and egress rules for the Semgrep arm."""

from __future__ import annotations

from typing import Any, Mapping

from ..mcp_client import HttpTransportPolicy
from ..policy_base import ToolPolicy

ARM_ID = "semgrep-mcp"
ENV_ENDPOINT = "SEMGREP_MCP_ENDPOINT"
# Remote-armed catalog: https endpoints only, loopback refused.
TRANSPORT_POLICY = HttpTransportPolicy.remote_https()

# Upstream semgrep-mcp (r2c) exposes 7 tools. Only local-rule scan and
# findings/AST/language reads are allowed.
ALLOWED_TOOLS = frozenset(
    {
        "semgrep_scan",
        "semgrep_findings",
        "get_abstract_syntax_tree",
        "supported_languages",
        "semgrep_rule_schema",
    }
)

# security_check runs broader agent-driven checks and
# semgrep_scan_with_custom_rule accepts caller-authored rule injection;
# both stay off this arm.
BLOCKED_TOOLS = frozenset({"security_check", "semgrep_scan_with_custom_rule"})

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

_TOOL_POLICY = ToolPolicy(allowed=ALLOWED_TOOLS, blocked=BLOCKED_TOOLS)

# Registry refs and URLs would make scans egress; scans must carry an
# inline rule pack (the "pinned local rule pack" doctrine).
_REGISTRY_PREFIXES = ("p/", "registry://")
_URL_PREFIXES = ("http://", "https://")
_BANNED_CONFIG_VALUES = frozenset({"auto", "default"})


def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Return the refusal reason for *tool*, or None to proceed."""
    reason = _TOOL_POLICY.refuse_reason(tool)
    if reason is not None:
        return reason
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None


def scan_config_refusal(args: Mapping[str, Any]) -> str | None:
    """Egress gate: semgrep_scan must carry an inline rule pack.

    The upstream ``config`` parameter is inline rule YAML/JSON. Refuse
    registry shorthands, URLs, and the "auto"/"default" values that
    would fall back to the semgrep registry. Omitting the parameter is
    also refused: an implicit registry default is still egress.
    """
    config = args.get("config")
    if not isinstance(config, str) or not config.strip():
        return "semgrep_scan requires an inline rule pack in args.config"
    if "\x00" in config:
        return "semgrep_scan config contains NUL"
    stripped = config.strip()
    # A registry ref or URL is a single-line token; a multi-line value is
    # an inline YAML/JSON rule body and must not be prefix-matched (a
    # body can legitimately start with "p:" or contain URLs in refs).
    if "\n" in stripped or "\r" in stripped:
        return None
    lowered = stripped.lower()
    if lowered in _BANNED_CONFIG_VALUES:
        return f"semgrep_scan config {stripped!r} would pull the registry"
    if lowered.startswith(_URL_PREFIXES):
        return "semgrep_scan config must be inline rules, not a URL"
    if lowered.startswith(_REGISTRY_PREFIXES):
        return "semgrep_scan config must be inline rules, not a registry ref"
    return None
