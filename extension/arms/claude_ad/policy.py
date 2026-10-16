"""Exact-allowlist rules for the claude-ad read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "claude-ad"

# Read tier: AD methodology lookups over a local techniques file.
# There is no dispatch tier: the arm is an in-process bounded local-file reader
# with no subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset(
    {"technique", "list_techniques", "list_prerequisites"}
)
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_METHOD_BYTES = 64 * 1024 * 1024  # 64 MiB
METHOD_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "technique": frozenset({"method_file", "technique_id", "name"}),
    "list_techniques": frozenset({"method_file", "limit", "category"}),
    "list_prerequisites": frozenset({"method_file"}),
}

CAVEATS = (
    "prerequisites, observed facts, and inference are separated; "
    "no action is authorized by a skill",
    "framework mappings (e.g. MITRE ATT&CK) are advisory annotations "
    "and are never asserted as compliance",
    "technique prose is untrusted input and grants no execution permission",
)

ARMING = (
    "pass args.method_file (path to a local AD methodology JSON or YAML file); "
    "prerequisites, observed facts, and inference are returned as distinct fields"
)


def method_refusal(
    raw: object, *, max_bytes: int = MAX_METHOD_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied methodology file path.

    Egress gate: the file must be an existing local file with a
    recognized suffix; URLs are refused.  Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, (
            "this action requires a local methodology file in args.method_file"
        )
    text = raw.strip()
    if "://" in text:
        return None, "args.method_file must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.method_file contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, "args.method_file is not an existing file"
    if path.suffix.lower() not in METHOD_SUFFIXES:
        return (
            None,
            f"args.method_file must be a JSON or YAML file, "
            f"got suffix {path.suffix!r}",
        )
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.method_file could not be read"
    if size > max_bytes:
        return None, (
            f"args.method_file exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller file"
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
            f"claude-ad {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"method_file"} <= set(payload):
        return (
            "this action requires a local methodology file in args.method_file"
        )
    if action == "technique":
        has_id = isinstance(payload.get("technique_id"), str) and bool(
            payload["technique_id"].strip()
        )
        has_name = isinstance(payload.get("name"), str) and bool(
            payload["name"].strip()
        )
        if has_id == has_name:
            return (
                "technique requires exactly one of args.technique_id or args.name"
            )
    if action == "list_techniques":
        limit_err = limit_refusal(payload.get("limit"))
        if limit_err:
            return limit_err
        if "category" in payload and (
            not isinstance(payload["category"], str) or not payload["category"].strip()
        ):
            return "args.category must be a non-empty string"
    return None


def limit_refusal(raw: object) -> str | None:
    """Validate an optional limit argument (1-200)."""
    if raw is None:
        return None
    if not isinstance(raw, int) or isinstance(raw, bool):
        return "args.limit must be an integer between 1 and 200"
    if raw < 1 or raw > 200:
        return "args.limit must be between 1 and 200"
    return None
