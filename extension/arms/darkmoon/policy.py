"""CLI rules for the dark-moon arm (shell launcher only)."""

from __future__ import annotations

import os
import re
from pathlib import Path

ARM_ID = "dark-moon"
ENV_BIN = "DARK_MOON_BIN"

ALLOWED_ACTIONS = frozenset({"log", "campaign", "run"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000

SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

CAVEATS = (
    "Autonomous multi-agent pentest; the MCP gateway still launches "
    "Nuclei/sqlmap/NetExec/etc. inside Docker (composite egress). "
    "Unknown MCP tool names are why this arm wraps the CLI, not MCP."
)


def session_id_refusal(payload: dict) -> str | None:
    raw = payload.get("session_id")
    if not isinstance(raw, str) or not raw.strip():
        return "log requires a session id in args.session_id"
    session_id = raw.strip()
    if session_id.startswith("-"):
        return "session_id must not be flag-shaped"
    if not SESSION_ID_RE.fullmatch(session_id):
        return "session_id must match [A-Za-z0-9_-]{1,64}"
    return None


def target_refusal(payload: dict) -> str | None:
    """Operator-selected target: one data argv token (TARGET: <raw>).

    Only technical guards stay here: the value must be a nonempty string
    without NUL/CR/LF controls. Eligibility (where the operator may point
    the tool) is the operator's decision, not the tool's. Separate argv
    (no shell) carries the raw value through to the launcher.
    """
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "campaign/run requires a target in args.target"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "target contains control characters"
    return None


def resolve_binary() -> str | None:
    """Return the launcher path: DARK_MOON_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("darkmoon") or shutil.which("darkmoon.sh")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv per action; no caller-controlled fragment."""
    if action == "log":
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id.strip():
            return None
        return [binary, "--log", session_id.strip()]
    if action in ("campaign", "run"):
        target = payload.get("target")
        if not isinstance(target, str) or not target.strip():
            return None
        # Upstream: ./darkmoon.sh "TARGET: example.com" — one argv token.
        return [binary, f"TARGET: {target.strip()}"]
    return None
