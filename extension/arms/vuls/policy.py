"""Action rules for the vuls arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "vuls"
ENV_BIN = "VULS_BIN"

# Straightforward upstream subcommands. Each runs with a fixed argv of
# [binary, action] and no caller-supplied flags; targets and refresh
# behavior come from the vuls config. The operator selects the action.
ALLOWED_ACTIONS = frozenset({"report", "summary", "scan", "fetch"})

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


def argv_for(binary: str, action: str) -> list[str]:
    """Build the fixed argv for a supported action; no caller flags."""
    return [binary, action]
