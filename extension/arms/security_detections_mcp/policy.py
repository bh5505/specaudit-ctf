"""Exact-allowlist rules for the security-detections-mcp read arm.

Curated local rule reads over pinned detection indexes.  No rule
generation, index mutation, deployment, or hosted fallback on the read
path.  Every result is source-attributable.  Per-corpus licensing must
be reviewed by the operator before use.
"""

from __future__ import annotations

from pathlib import Path

ARM_ID = "security-detections-mcp"

ALLOWED_ACTIONS = frozenset({"list_rules", "search_rules", "get_rule"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_INDEX_BYTES = 64 * 1024 * 1024
INDEX_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200

ARG_KEYS: dict[str, frozenset[str]] = {
    "list_rules": frozenset({"index"}),
    "search_rules": frozenset({"index", "query", "limit"}),
    "get_rule": frozenset({"index", "rule_id"}),
}

CAVEATS = (
    "offline read tier over operator-supplied local detection indexes",
    "no rule generation, index mutation, deployment, or hosted fallback",
    "every result is source-attributable to the pinned index",
    "per-corpus licensing must be reviewed before use",
)

ARMING = (
    "pass args.index (path to a local detection-rule index file in JSON "
    "or YAML); the operator must review corpus licensing before first use"
)


def index_refusal(raw: object, *, max_bytes: int = MAX_INDEX_BYTES) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local index path.  Egress gate."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local index path in args.index"
    text = raw.strip()
    if "://" in text:
        return None, "args.index must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.index contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.index is not an existing file: {text}"
    if path.suffix.lower() not in INDEX_SUFFIXES:
        return None, f"args.index must be a JSON or YAML file, got suffix {path.suffix!r}"
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.index could not be read: {exc}"
    if size > max_bytes:
        return None, (
            f"args.index exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller index"
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
            f"security-detections-mcp {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"index"} <= set(payload):
        return "this action requires a local index path in args.index"
    if action == "get_rule" and not str(payload.get("rule_id") or "").strip():
        return "get_rule requires args.rule_id"
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
