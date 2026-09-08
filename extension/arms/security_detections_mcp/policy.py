"""Exact-allowlist rules for the security-detections-mcp read arm.

Curated local rule reads over operator-supplied frozen detection indexes.  No rule
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
MAX_RECORDS = 10_000
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 64

ARG_KEYS: dict[str, frozenset[str]] = {
    "list_rules": frozenset({"index", "limit"}),
    "search_rules": frozenset({"index", "query", "limit"}),
    "get_rule": frozenset({"index", "rule_id"}),
}

CAVEATS = (
    "offline read tier over operator-supplied local detection indexes",
    "no rule generation, index mutation, deployment, or hosted fallback",
    "data-action results identify the exact input bytes but do not establish "
    "source revision, custody, or authenticity",
    "per-corpus revision and licensing must be reviewed before use",
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
        return None, "args.index is not an existing file"
    if path.suffix.lower() not in INDEX_SUFFIXES:
        return None, f"args.index must be a JSON or YAML file, got suffix {path.suffix!r}"
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.index could not be read"
    if size > max_bytes:
        return None, (
            f"args.index exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller index"
        )
    return path, None


def args_refusal(action: str, payload: dict) -> str | None:
    """Refuse unknown or missing caller arguments per action."""
    if any(not isinstance(key, str) for key in payload):
        return "caller argument names must be strings"
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
    if action == "get_rule":
        rule_id = payload.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return "get_rule requires args.rule_id as a non-empty string"
    if action == "search_rules":
        query = payload.get("query")
        if not isinstance(query, str) or not query.strip():
            return "search_rules requires args.query as a non-empty string"
    if action in {"list_rules", "search_rules"}:
        _, refusal = limit_refusal(payload.get("limit"))
        if refusal:
            return refusal
    return None


def limit_refusal(raw: object) -> tuple[int | None, str | None]:
    """Validate an optional result limit."""
    if raw is None:
        return None, None
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None, "args.limit must be a positive integer"
    if raw < 1 or raw > MAX_RESULTS:
        return None, f"args.limit must be between 1 and {MAX_RESULTS}"
    return raw, None
