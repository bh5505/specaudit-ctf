"""Tier rules for the osmedeus arm. The scan -t argv is provisional pending upstream flag pinning."""

from __future__ import annotations

import os
import re
from pathlib import Path

ARM_ID = "osmedeus"
ENV_BIN = "OSMEDEUS_BIN"
ENV_DISPATCH_SCOPE = "OSMEDEUS_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset(['assets'])
DISPATCH_ACTIONS = frozenset(['scan'])

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000

def target_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a target in args.target"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "scan target contains control characters"
    if " " in target:
        return "scan target must be a hostname or http(s) URL"
    # Flag-shaped values must never ride fixed argv (cross-review finding).
    if target.startswith("-"):
        return "scan target must not be flag-shaped"
    from urllib.parse import urlparse

    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return "scan target must be an http(s) URL or hostname"
    else:
        # Unbracketed IPv6 mangles under urlparse; require brackets so the
        # audited target is the executed target (cross-review finding).
        if ":" in target and not target.startswith("["):
            return "IPv6 targets must be bracketed"
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.[]:")
        if not target or any(ch not in allowed for ch in target.lower()):
            return "scan target must be an http(s) URL or hostname"
    return None


def resolve_binary() -> str | None:
    """Return the binary path: OSMEDEUS_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("osmedeus")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv per action; no caller-controlled fragment."""
    if action == "assets":
        return [binary, "assets"]
    target = payload.get("target")
    if not isinstance(target, str) or not target.strip():
        return None
    return [binary, "scan", "-t", target.strip()]
