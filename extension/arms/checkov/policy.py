"""Checkov command construction and scan-target resolution."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "checkov"
ENV_BIN = "CHECKOV_BIN"
ENV_SCAN_ROOT = "CHECKOV_SCAN_ROOT"

ALLOWED_ACTIONS = frozenset({"scan"})

# --soft-fail makes the exit code 0 even when findings exist —
# findings are the PRODUCT of the scan and live in the JSON output;
# without it checkov 3.x exits 1 on any finding and the arm would
# misread planted violations as tool failure. (Measured against
# checkov 3.3.16 in the lab, 2026-09-05: the argv carries no `scan`
# subcommand — current checkov rejects it — and --soft-fail flips the
# findings exit from 1 to 0.)
FIXED_ARGV_TAIL = (
    "--framework",
    "terraform",
    "-o",
    "json",
    "--soft-fail",
)

TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_ROWS = 200
MAX_OUTPUT_CHARS = 200_000


def default_scan_root() -> Path:
    """Packaged synthetic range root used when no target is supplied."""
    from ...range.runner import default_range_root

    return default_range_root()


def resolve_binary() -> str | None:
    """Return the checkov binary path: CHECKOV_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which(ARM_ID)


def resolve_scan_root(target: object = None) -> tuple[Path | None, str | None]:
    """Resolve the operator-selected directory, with the demo range as default."""
    raw = target if target is not None else os.environ.get(ENV_SCAN_ROOT)
    if raw is not None and (not isinstance(raw, str) or not raw.strip()):
        return None, "scan target must be a nonempty path"
    try:
        root = Path(raw).expanduser().resolve() if raw else default_scan_root().resolve()
    except (OSError, ValueError):
        return None, "scan target could not be resolved"
    if not root.is_dir():
        return None, f"scan target is not a directory: {root}"
    return root, None


def argv_for(binary: str, root: Path) -> list[str]:
    """Build the scan command without shell interpolation."""
    return [binary, "-d", str(root), *FIXED_ARGV_TAIL]
