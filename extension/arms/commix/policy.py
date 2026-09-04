"""Dispatch-only rules for the commix arm.

Upstream commix is an active command-injection prober with no module
listing and no report-reading mode (verified 2026-08-23). Every action
is dispatch-class.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib import parse as urllib_parse

ARM_ID = "commix"
ENV_BIN = "COMMIX_BIN"
ENV_DISPATCH_SCOPE = "COMMIX_DISPATCH_SCOPE"

DISPATCH_ACTIONS = frozenset({"scan"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000


def resolve_binary() -> str | None:
    """Return the commix entry path: COMMIX_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which(ARM_ID)


def target_refusal(args: dict) -> tuple[str | None, str | None]:
    """Extract and validate the probe target URL from args."""
    raw = args.get("url")
    if not isinstance(raw, str) or not raw.strip():
        return None, "commix scan requires a target URL in args.url"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return None, "commix scan target contains control characters"
    parsed = urllib_parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, "commix scan target must be an http(s) URL"
    return target, None


def argv_for(binary: str, target: str) -> list[str]:
    """Fixed argv: --batch answers every interactive prompt non-interactively.

    --ignore-stdin (a hidden upstream option, verified against commix
    4.1-0kali1 source 2026-09-04): when stdin is not a tty, commix
    switches to parsing TARGETS from stdin and silently ignores -u —
    a subprocess-captured scan would exit 0 having scanned nothing.
    The fixed literal disables that; the target still rides -u only.
    """
    return [binary, "--batch", "--ignore-stdin", "-u", target]
