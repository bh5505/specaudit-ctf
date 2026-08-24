"""Tier rules for the vuls arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "vuls"
ENV_BIN = "VULS_BIN"
ENV_DISPATCH_SCOPE = "VULS_DISPATCH_SCOPE"

# Local database reads only. Fixed argv: plain subcommands, no flags -
# flags like --refresh-cve reach the network.
ALLOWED_ACTIONS = frozenset({"report", "summary"})

# Host scanning is dispatch-class. Target servers live in the vuls
# config, not in invoke args, so dispatch authorizes on scope presence
# and the audit line records target=unknown.
DISPATCH_ACTIONS = frozenset({"scan"})

# fetch pulls CVE feeds over the network; it is egress, not attack
# dispatch, and sits on no tier (same rule as semgrep registry refs).
BLOCKED_ACTIONS = frozenset({"fetch", "tui", "server", "config", "init"})

TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_CHARS = 200_000


def resolve_binary() -> str | None:
    """Return the vuls binary path: VULS_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which(ARM_ID)
