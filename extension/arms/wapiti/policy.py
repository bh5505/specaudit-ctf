"""Dispatch-only rules for the wapiti arm.

Upstream wapiti has no read-only mode: every invocation scans a target
(-u URL) and sends HTTP traffic. This arm therefore has no read tier;
its single action is dispatch-class and refused by default.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib import parse as urllib_parse

ARM_ID = "wapiti"
ENV_BIN = "WAPITI_BIN"
ENV_DISPATCH_SCOPE = "WAPITI_DISPATCH_SCOPE"

DISPATCH_ACTIONS = frozenset({"scan"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000


def resolve_binary() -> str | None:
    """Return the wapiti binary path: WAPITI_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which(ARM_ID)


def target_refusal(args: dict) -> tuple[str | None, str | None]:
    """Extract and validate the scan target URL from args."""
    raw = args.get("url")
    if not isinstance(raw, str) or not raw.strip():
        return None, "wapiti scan requires a target URL in args.url"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return None, "wapiti scan target contains control characters"
    parsed = urllib_parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, "wapiti scan target must be an http(s) URL"
    return target, None


def argv_for(binary: str, target: str) -> list[str]:
    """Fixed argv: JSON output format; no caller-controlled flags."""
    return [binary, "-u", target, "-f", "json"]
