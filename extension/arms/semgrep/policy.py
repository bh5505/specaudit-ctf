"""Semgrep command and MCP action definitions."""

from __future__ import annotations

import os
from typing import Any, Mapping

from ..policy_base import DEFAULT_TOOL_PATTERN

ARM_ID = "semgrep-mcp"
ENV_ENDPOINT = "SEMGREP_MCP_ENDPOINT"
# Primary integration point: the first-party semgrep CLI (the MCP
# adapter repo is archived - implementation minutiae; the CLI is the
# stable surface). NPSL: invoke the operator's binary, never bundle.
ENV_BIN = "SEMGREP_BIN"
TIMEOUT_SECONDS = 120.0
MAX_FINDINGS = 500

CAVEATS = (
    "Primary surface is the semgrep CLI; scans run locally with an "
    "rule config supplied in args.config; --metrics=off on every scan. "
    "MCP tools are available via SEMGREP_MCP_ENDPOINT."
)


def resolve_binary() -> str | None:
    """Return the semgrep path: SEMGREP_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        from pathlib import Path

        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("semgrep")


def resolve_target(payload: "Mapping[str, Any]") -> "tuple[str | None, str | None]":
    """Resolve the operator's scan target path, defaulting to cwd."""
    from pathlib import Path

    raw_target = payload.get("target")
    if raw_target in (None, ""):
        return str(Path.cwd()), None
    if not isinstance(raw_target, str) or "\x00" in raw_target:
        return None, "target must be a path string"
    target = Path(raw_target).expanduser().resolve()
    if not target.exists():
        return None, "target does not exist"
    return str(target), None

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})


def refuse_reason(tool: str, available: set[str]) -> str | None:
    """Report malformed names or tools absent from the connected server."""
    if not DEFAULT_TOOL_PATTERN.fullmatch(tool):
        return f"invalid tool name: {tool!r}"
    if tool not in available:
        return f"tool {tool!r} is not available on the server"
    return None


def scan_config_refusal(args: Mapping[str, Any]) -> str | None:
    """Check that a configured rule selector can be passed to Semgrep."""
    config = args.get("config")
    if not isinstance(config, str) or not config.strip():
        return "semgrep_scan requires args.config"
    if "\x00" in config:
        return "semgrep_scan config contains NUL"
    return None
