"""Dispatch-only rules for the page-fetch arm: bounded fetch with SSRF guards upstream of the binary."""

from __future__ import annotations

import os
import re
from pathlib import Path

ARM_ID = "page-fetch"
ENV_BIN = "PAGE_FETCH_BIN"
ENV_DISPATCH_SCOPE = "PAGE_FETCH_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset([])
DISPATCH_ACTIONS = frozenset(['fetch'])

TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_CHARS = 200_000

from urllib import parse as urllib_parse


def target_refusal(payload: dict) -> str | None:
    raw = payload.get("url")
    if not isinstance(raw, str) or not raw.strip():
        return "fetch requires a target URL in args.url"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "fetch target contains control characters"
    parsed = urllib_parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "fetch target must be an http(s) URL"
    return None


def resolve_binary() -> str | None:
    """Return the binary path: PAGE_FETCH_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("page-fetch")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv per action; no caller-controlled fragment.

    Scope truth: only the initial URL is scope-checked (host + scheme are
    the effective control; URI path prefixes are best-effort). Redirect
    follows, the name's resolution at fetch time, and third-party
    subresource fetches during rendering are NOT re-checked — an armed
    scope must be considered reachable from anything its hosts redirect
    or reference to, including metadata IPs. Private and metadata hosts
    are allowed only when deliberately scoped.
    """
    target = payload.get("url")
    if not isinstance(target, str) or not target.strip():
        return None
    # Provisional argv: bare URL argument (upstream flag semantics were
    # not pinnable in the 2026-08-23 research pass).
    return [binary, target.strip()]
