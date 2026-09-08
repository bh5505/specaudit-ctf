"""Tier rules for the rubeus CLI arm: deweaponized AD telemetry reads.

This arm reads from a local JSON file containing deweaponized Active
Directory telemetry data.  No real tickets, hashes, or secrets are
distributed.  Legitimate administration is not automatically classified
as compromise.
"""

from __future__ import annotations

from pathlib import Path

ARM_ID = "rubeus"

# Read tier: exact lookups and summaries over a local telemetry file.
# There is no dispatch tier: the arm is an in-process stdlib reader
# with no subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"telemetry", "list_telemetry", "list_indicators"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_TELEMETRY_BYTES = 64 * 1024 * 1024  # 64 MiB
TELEMETRY_SUFFIX = ".json"
MAX_RESULTS = 200

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "telemetry": frozenset({"telemetry_file", "event_id"}),
    "list_telemetry": frozenset({"telemetry_file", "limit", "category"}),
    "list_indicators": frozenset({"telemetry_file", "indicator_type"}),
}

CAVEATS = (
    "reads deweaponized AD telemetry from a local JSON file only",
    "no real Kerberos tickets, NTLM hashes, or secrets are distributed",
    "legitimate administration is not automatically classified as compromise",
    "positive, benign, and missing-telemetry variants are graded separately",
)

ARMING = (
    "pass args.telemetry_file (path to a local deweaponized AD "
    "telemetry JSON file)"
)


def telemetry_refusal(
    raw: object, *, max_bytes: int = MAX_TELEMETRY_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local telemetry file path.

    Egress gate: the file must be an existing local file with a
    .json suffix; URLs are refused.  Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, (
            "this action requires a local telemetry file path in "
            "args.telemetry_file"
        )
    text = raw.strip()
    if "://" in text:
        return None, "args.telemetry_file must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.telemetry_file contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.telemetry_file is not an existing file: {text}"
    if path.suffix.lower() != TELEMETRY_SUFFIX:
        return None, (
            f"args.telemetry_file must be a JSON file, "
            f"got suffix {path.suffix!r}"
        )
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.telemetry_file could not be read: {exc}"
    if size > max_bytes:
        return None, (
            f"args.telemetry_file exceeds the {max_bytes} byte read cap "
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
            f"rubeus {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if "telemetry_file" not in payload:
        return (
            "this action requires a local telemetry file path in "
            "args.telemetry_file"
        )
    if action == "telemetry":
        eid = payload.get("event_id")
        if not isinstance(eid, str) or not eid.strip():
            return "telemetry requires an event_id in args.event_id"
    return None


def limit_refusal(raw: object) -> int | str:
    """Validate and return the list limit (1..MAX_RESULTS) or a refusal."""
    if raw is None:
        return MAX_RESULTS
    if not isinstance(raw, int):
        return f"args.limit must be an integer (1-{MAX_RESULTS})"
    if raw < 1 or raw > MAX_RESULTS:
        return f"args.limit must be between 1 and {MAX_RESULTS}"
    return raw
