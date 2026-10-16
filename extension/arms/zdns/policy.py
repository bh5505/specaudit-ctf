"""Dispatch-only rules for the zdns arm: live DNS resolution is the whole surface."""

from __future__ import annotations

import os
import re
from pathlib import Path

ARM_ID = "zdns"
ENV_BIN = "ZDNS_BIN"
ENV_DISPATCH_SCOPE = "ZDNS_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset([])
DISPATCH_ACTIONS = frozenset(['lookup'])

TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_CHARS = 200_000

RECORD_TYPES = frozenset({"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR"})


def lookup_refusal(payload: dict) -> str | None:
    rtype = payload.get("record_type", "A")
    if rtype not in RECORD_TYPES:
        return f"record_type must be one of {sorted(RECORD_TYPES)}"
    domain = payload.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        return "lookup requires a domain in args.domain"
    d = domain.strip()
    if "\x00" in d or "\r" in d or "\n" in d or " " in d or "/" in d:
        return "domain contains invalid characters"
    # Flag-shaped values must never ride fixed argv (cross-review finding).
    if d.startswith("-"):
        return "domain must not be flag-shaped"
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if not d or any(ch not in allowed for ch in d.lower()):
        return "domain must be a hostname"
    return None


def resolve_binary() -> str | None:
    """Return the binary path: ZDNS_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("zdns")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv per action; no caller-controlled fragment."""
    rtype = payload.get("record_type", "A")
    domain = payload.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        return None
    return [binary, str(rtype), domain.strip()]
