"""Arguments for garak listing, scanning, and report reading."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "garak"
ENV_BIN = "GARAK_BIN"
ENV_REPORT_DIR = "GARAK_REPORT_DIR"

ALLOWED_ACTIONS = frozenset({"list_probes", "list_detectors", "scan", "report"})

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


def report_dir() -> tuple[Path | None, str | None]:
    """Resolve the operator-selected report directory."""
    raw = os.environ.get(ENV_REPORT_DIR)
    if not raw or not raw.strip():
        return None, "GARAK_REPORT_DIR is required for the report action"
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        return None, f"GARAK_REPORT_DIR is not a directory: {path}"
    return path, None


def argv_for(binary: str, action: str) -> list[str]:
    """Fixed argv; no caller-supplied fragment ever reaches it."""
    return [binary, *FIXED_ARGV[action]]


def scan_argv(binary: str, args: dict) -> tuple[list[str] | None, str | None]:
    """Translate supported garak scan options into separate argv elements."""
    fields = {"target_type": "--target_type", "target_name": "--target_name", "spec": "--spec", "config": "--config"}
    extra = set(args) - set(fields)
    if extra:
        return None, f"unsupported garak scan arguments: {', '.join(sorted(extra))}"
    if not isinstance(args.get("target_type"), str) or not args["target_type"].strip():
        return None, "scan requires args.target_type"
    cmd = [binary]
    for key, flag in fields.items():
        if key not in args:
            continue
        value = args[key]
        if not isinstance(value, str) or not value.strip() or value.strip().startswith("-"):
            return None, f"scan {key} must be a nonempty, non-flag string"
        if any(ord(char) < 0x20 for char in value):
            return None, f"scan {key} contains control characters"
        cmd.extend([flag, value.strip()])
    return cmd, None
