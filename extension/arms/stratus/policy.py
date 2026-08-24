"""Tier rules for the stratus-red-team arm (DataDog stratus)."""

from __future__ import annotations

import os
import re
from pathlib import Path

ARM_ID = "stratus-red-team"
ENV_BIN = "STRATUS_BIN"
ENV_DISPATCH_SCOPE = "STRATUS_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset(['list'])
DISPATCH_ACTIONS = frozenset(['warmup', 'detonate', 'revert'])

TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_CHARS = 200_000

# Detonation args: the attacker technique id (e.g. aws.exfiltration.s3).
_TECHNIQUE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def technique_refusal(payload: dict) -> str | None:
    value = payload.get("technique")
    if not isinstance(value, str) or not value.strip():
        return "dispatch actions require a technique id in args.technique"
    if not _TECHNIQUE_RE.match(value.strip()):
        return "technique id must match [a-z0-9._-]"
    return None


def resolve_binary() -> str | None:
    """Return the binary path: STRATUS_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("stratus")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv per action; no caller-controlled fragment."""
    if action == "list":
        return [binary, "list"]
    technique = payload.get("technique")
    if not isinstance(technique, str) or not technique.strip():
        return None
    return [binary, action, technique.strip()]
