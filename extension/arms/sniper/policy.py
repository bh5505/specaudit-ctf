"""Argument assembly for the operator-installed Sniper CLI."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "sniper"
ENV_BIN = "SNIPER_BIN"

ALLOWED_ACTIONS = frozenset({"scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MODES = frozenset({"normal", "stealth", "web", "fullportonly", "discover", "port"})
CLOSED_SCAN_KEYS = frozenset({"target", "mode", "options"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "The named target does not bound 90+ sub-tools (nmap, nuclei, "
    "and others). Community sniper must run as root (EUID -ne 0 exits 1). "
    "Each scan performs check_online telemetry "
    "(version + machine-id). Scans can use composite egress and require root."
)


def resolve_binary() -> str | None:
    """Return the binary path: SNIPER_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("sniper")


def extra_scan_keys(payload: dict) -> frozenset[str]:
    return frozenset(payload) - CLOSED_SCAN_KEYS


def mode_refusal(payload: dict) -> str | None:
    raw = payload.get("mode")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a mode in args.mode"
    mode = raw.strip()
    if mode.startswith("-"):
        return "mode must not be flag-shaped"
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in mode):
        return "mode must be one argument without control characters"
    return None


def target_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a target in args.target"
    target = raw.strip()
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in target):
        return "scan target must be one argument without control characters"
    if target.startswith("-"):
        return "scan target must not be flag-shaped"
    return None


def options_refusal(payload: dict) -> str | None:
    options = payload.get("options")
    if options is None:
        return None
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        return "scan options must be a list of argv strings"
    if any(not item or "\x00" in item for item in options):
        return "scan options must be nonempty argv strings without NUL bytes"
    return None


def argv_for(binary: str, target: str, mode: str, options: list[str] | None = None) -> list[str]:
    """Pass the selected target, mode, and optional upstream flags as argv."""
    return [binary, "-t", target, "-m", mode, *(options or [])]
