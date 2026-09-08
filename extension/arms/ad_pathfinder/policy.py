"""Exact-allowlist rules for the ad-pathfinder read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "ad-pathfinder"

# Read tier: lookups over an exported AD path JSON file. There is no
# dispatch tier: the arm is an in-process stdlib reader with no
# subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"path", "list_paths", "list_datasources"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_EXPORT_BYTES = 64 * 1024 * 1024
EXPORT_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "path": frozenset({"export", "path_id", "source", "target"}),
    "list_paths": frozenset({"export", "limit"}),
    "list_datasources": frozenset({"export"}),
}

CAVEATS = (
    "offline read tier over an operator-supplied local AD path export",
    "a missing datasource field reads as 'not assessed', never clean",
    "no real hashes or credentials are stored or returned",
    "a blocked path does not mean demonstrated compromise",
)

ARMING = (
    "pass args.export (an existing local JSON or YAML file path "
    "containing AD path results)"
)


def export_refusal(
    raw: object, *, max_bytes: int = MAX_EXPORT_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local export path.

    Egress gate: the export must be an existing local file with a
    supported suffix; URLs are refused. Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local export path in args.export"
    text = raw.strip()
    if "://" in text:
        return None, "args.export must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.export contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.export is not an existing file: {text}"
    if path.suffix.lower() not in EXPORT_SUFFIXES:
        return None, (
            f"args.export must be a JSON or YAML file, got suffix {path.suffix!r}"
        )
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.export could not be read: {exc}"
    if size > max_bytes:
        return None, (
            f"args.export exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller file"
        )
    return path, None


def args_refusal(action: str, payload: dict) -> str | None:
    """Refuse unknown or missing caller arguments per action."""
    allowed = ARG_KEYS.get(action)
    if allowed is None:
        return f"action {action!r} is not on the read allowlist"
    extra = sorted(set(payload) - allowed)
    if extra:
        return (
            f"ad-pathfinder {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if "export" not in payload:
        return "this action requires a local export path in args.export"
    if action == "path":
        has_path_id = isinstance(payload.get("path_id"), str) and payload["path_id"].strip()
        has_source = isinstance(payload.get("source"), str) and payload["source"].strip()
        has_target = isinstance(payload.get("target"), str) and payload["target"].strip()
        if not has_path_id and not (has_source and has_target):
            return "path requires either args.path_id or both args.source and args.target"
    return None


def limit_refusal(raw: object) -> tuple[int | None, str | None]:
    """Validate and cap a caller-supplied result limit.

    Returns (limit, None) or (None, refusal).
    """
    if raw is None:
        return MAX_RESULTS, None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, "args.limit must be a positive integer"
    if value < 1:
        return None, "args.limit must be a positive integer"
    capped = min(value, MAX_RESULTS)
    return capped, None
