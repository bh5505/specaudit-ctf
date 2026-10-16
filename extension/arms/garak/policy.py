"""Fixed-argv and target-binding rules for the garak arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "garak"
ENV_BIN = "GARAK_BIN"
ENV_TARGET = "GARAK_TARGET"
ENV_REPORT_DIR = "GARAK_REPORT_DIR"

# Listing and report reading only. Open-ended probe dispatch (running
# probes against the bound target) stays off this arm.
ALLOWED_ACTIONS = frozenset({"list_probes", "list_detectors", "report"})

# Confirmed upstream flags (garak README): --list_probes /
# --list_detectors list without running a scan.
FIXED_ARGV = {
    "list_probes": ("--list_probes",),
    "list_detectors": ("--list_detectors",),
}

TIMEOUT_SECONDS = 30.0
MAX_OUTPUT_CHARS = 200_000


def resolve_binary() -> str | None:
    """Return the garak binary path: GARAK_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which(ARM_ID)


def target_bound() -> bool:
    """Install requires an explicit target binding; no free-floating arm."""
    return bool(os.environ.get(ENV_TARGET, "").strip())


def report_dir() -> tuple[Path | None, str | None]:
    """Resolve GARAK_REPORT_DIR; unset is a refusal (no invented default).

    The directory is operator-chosen (garak writes reports wherever it
    runs, often outside this clone), so containment is trust in the
    operator's env - same doctrine as the endpoint envs. The one hard
    refusal is a filesystem or drive root, an obvious footgun that can
    slurp the widest possible *.jsonl set.
    """
    raw = os.environ.get(ENV_REPORT_DIR)
    if not raw or not raw.strip():
        return None, "GARAK_REPORT_DIR is required for the report action"
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        return None, f"GARAK_REPORT_DIR is not a directory: {path}"
    if path == path.anchor or path.parent == path:
        return None, "GARAK_REPORT_DIR must not be a filesystem root"
    return path, None


def argv_for(binary: str, action: str) -> list[str]:
    """Fixed argv; no caller-supplied fragment ever reaches it."""
    return [binary, *FIXED_ARGV[action]]
