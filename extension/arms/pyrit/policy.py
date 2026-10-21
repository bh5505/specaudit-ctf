"""CLI rules for the pyrit arm (first-party pyrit_scan only)."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "pyrit"
ENV_BIN = "PYRIT_BIN"

ALLOWED_ACTIONS = frozenset({"list_scenarios", "scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "Requires operator PyRIT config (~/.pyrit). Community MCP wrappers "
    "are unused. First-party pyrit_scan only. Scan spends model tokens "
    "on the operator-configured endpoints."
)


def scenario_refusal(payload: dict) -> str | None:
    """Operator-selected scenario: one data argv token.

    Only technical guards stay here: nonempty string without NUL/CR/LF,
    plus a flag-shape guard so a positional scenario cannot be mistaken
    for an upstream flag. No fixed name pattern constrains the operator.
    """
    raw = payload.get("scenario")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a scenario in args.scenario"
    scenario = raw.strip()
    if "\x00" in scenario or "\r" in scenario or "\n" in scenario:
        return "scenario contains control characters"
    if scenario.startswith("-"):
        return "scenario must not be flag-shaped"
    return None


def target_refusal(payload: dict) -> str | None:
    """Operator-selected target: one data argv token (--target <raw>).

    Only technical guards stay here: the value must be a nonempty string
    without NUL/CR/LF controls. Eligibility (where the operator may point
    the tool) is the operator's decision, not the tool's. Separate argv
    (no shell) carries the raw value through to pyrit_scan.
    """
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a target in args.target"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "target contains control characters"
    return None


def resolve_binary() -> str | None:
    """Return the pyrit_scan path: PYRIT_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("pyrit_scan")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv frozen from first-party pyrit_scan --help (PyRIT 1.0.1).

    Docs: https://microsoft.github.io/PyRIT/1.0.1/scanner/pyrit-scan
    list_scenarios -> --list-scenarios; scan -> positional scenario --target NAME.
    """
    if action == "list_scenarios":
        return [binary, "--list-scenarios"]
    if action == "scan":
        scenario = payload.get("scenario")
        target = payload.get("target")
        if not isinstance(scenario, str) or not scenario.strip():
            return None
        if not isinstance(target, str) or not target.strip():
            return None
        return [binary, scenario.strip(), "--target", target.strip()]
    return None
