"""Fixed-argv rules for the mitreattack-python arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "mitreattack-python"
ENV_BIN = "MITREATTACK_BIN"
DEFAULT_BIN_NAME = "attack-to-excel"

# Local STIX conversion only. download_attack_stix is network egress
# and is deliberately not on any tier.
ALLOWED_ACTIONS = frozenset({"to_excel"})

TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_CHARS = 200_000


def resolve_binary() -> str | None:
    """Return the attack-to-excel path: MITREATTACK_BIN, else PATH."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which(DEFAULT_BIN_NAME)


def input_refusal(args: dict) -> str | None:
    """Egress gate: the STIX input must be an existing local bundle."""
    raw = args.get("input")
    if not isinstance(raw, str) or not raw.strip():
        return "to_excel requires a local STIX bundle path in args.input"
    text = raw.strip()
    if "://" in text:
        return "to_excel input must be a local file, not a URL"
    path = Path(text).expanduser()
    if not path.is_file():
        return f"to_excel input is not an existing file: {text}"
    if path.suffix.lower() not in (".json", ".stix", ".stix2", ".jsonc"):
        return f"to_excel input must be a STIX JSON bundle: {path.suffix!r}"
    return None


def argv_for(binary: str, args: dict) -> list[str]:
    """Fixed argv: the console script plus the validated local bundle."""
    return [binary, str(Path(args["input"].strip()).expanduser())]
