"""Exact-allowlist rules for the detection-in-the-cloud read arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "detection-in-the-cloud"

ALLOWED_ACTIONS = frozenset({"playbook", "list_playbooks", "list_rules"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_PLAYBOOK_BYTES = 64 * 1024 * 1024
PLAYBOOK_SUFFIXES = (".json", ".yaml", ".yml", ".md")
MAX_RESULTS = 200

ARG_KEYS: dict[str, frozenset[str]] = {
    "playbook": frozenset({"playbook_dir", "name"}),
    "list_playbooks": frozenset({"playbook_dir", "limit"}),
    "list_rules": frozenset({"playbook_dir", "category"}),
}

CAVEATS = (
    "pages pinned to the corresponding definition revisions",
    "a rule listing is never read as operating effectiveness",
    "companion methodology, not a second detection engine",
)

ARMING = "pass args.playbook_dir (path to a local directory containing detection playbook files)"


def playbook_dir_refusal(raw: object) -> tuple[str | None, str | None]:
    """Validate a caller-supplied playbook directory.  Returns (path, refusal)."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local playbook directory in args.playbook_dir"
    text = raw.strip()
    if "://" in text:
        return None, "args.playbook_dir must be a local path, not a URL"
    path = Path(text).expanduser().resolve()
    if path == path.anchor or path.parent == path:
        return None, "args.playbook_dir must not be a filesystem root"
    if not path.exists():
        return None, f"args.playbook_dir does not exist: {text}"
    if not path.is_dir():
        return None, f"args.playbook_dir is not a directory: {text}"
    return str(path), None


def args_refusal(action: str, payload: dict) -> str | None:
    """Refuse unknown or missing caller arguments per action."""
    allowed = ARG_KEYS.get(action)
    if allowed is None:
        return f"action {action!r} is not on the read allowlist"
    extra = sorted(set(payload) - allowed)
    if extra:
        return (
            f"detection-in-the-cloud {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"playbook_dir"} <= set(payload):
        return "this action requires a local playbook directory in args.playbook_dir"
    if action == "playbook" and not str(payload.get("name") or "").strip():
        return "playbook requires args.name"
    return None


def limit_refusal(raw: object) -> tuple[int | None, str | None]:
    """Validate an optional result limit."""
    if raw is None:
        return None, None
    if isinstance(raw, str) and raw.isdigit():
        raw = int(raw)
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None, "args.limit must be a positive integer"
    if raw < 1 or raw > MAX_RESULTS:
        return None, f"args.limit must be between 1 and {MAX_RESULTS}"
    return raw, None
