"""Rules for the zdns arm: live DNS resolution is the whole surface."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "zdns"
ENV_BIN = "ZDNS_BIN"

ALLOWED_ACTIONS = frozenset(['lookup'])

TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_CHARS = 200_000

def lookup_refusal(payload: dict) -> str | None:
    rtype = payload.get("record_type", "A")
    if not isinstance(rtype, str) or not rtype.strip() or any(ch.isspace() or ord(ch) < 0x20 for ch in rtype):
        return "record_type must be one nonempty argv token"
    domain = payload.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        return "lookup requires a domain in args.domain"
    d = domain.strip()
    if any(ch.isspace() or ord(ch) < 0x20 for ch in d):
        return "domain must be one nonempty argv token"
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
