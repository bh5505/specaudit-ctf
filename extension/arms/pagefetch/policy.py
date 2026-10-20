"""Rules for the page-fetch arm: bounded fetch with SSRF guards upstream of the binary."""

from __future__ import annotations

import os
import re
from pathlib import Path

ARM_ID = "page-fetch"
ENV_BIN = "PAGE_FETCH_BIN"

ALLOWED_ACTIONS = frozenset(['fetch'])

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
    """Fixed argv per action; no caller-controlled fragment — the URL
    never touches argv at all.

    Upstream (detectify/page-fetch, main.go verified 2026-09-05) reads
    URLs from stdin ONLY (bufio scanner, one per line); there is no URL
    flag and no positional handling, and a positional URL is silently
    ignored with exit 0 — so argv stays bare and the validated URL is
    fed as the single stdin line by the arm (the zgrab2 pattern).

    Redirect follows, the name's resolution at fetch time, and
    third-party subresource fetches during rendering are NOT re-checked:
    fetching a URL must be considered reachable from anything its hosts
    redirect or reference to, including metadata IPs.
    """
    if action not in ALLOWED_ACTIONS:
        return None
    target = payload.get("url")
    if not isinstance(target, str) or not target.strip():
        return None
    return [binary]
