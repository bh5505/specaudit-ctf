"""Exact-allowlist rules for the vulnify read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "vulnify"

# Read tier: exact lookups over a local vulnerability feed. There is no
# dispatch tier: the arm is an in-process bounded local-file reader with no
# subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"lookup", "list_vulns"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_FEED_BYTES = 64 * 1024 * 1024
FEED_SUFFIXES = (".json", ".jsonl", ".yaml", ".yml")
MAX_RESULTS = 200
MAX_RECORDS = 10_000
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 64

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "lookup": frozenset({"feed", "cve_id", "name"}),
    "list_vulns": frozenset({"feed", "limit"}),
}

CAVEATS = (
    "offline read tier over an operator-supplied local vulnerability feed snapshot",
    "exact lookups only, no enumeration beyond list_vulns",
    "unknown or stale data in the feed stays explicitly opaque — "
    "the arm does not augment or refresh records",
    "results identify exact snapshot bytes and normalized records but do not "
    "establish upstream revision, attribution, or data rights",
    "no network or database mutation occurs during a lookup",
)

ARMING = (
    "pass args.feed (path to a local vulnerability feed file); "
    "every record traces to the supplied snapshot's exact-byte digest"
)


def feed_refusal(
    raw: object, *, max_bytes: int = MAX_FEED_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local feed path.

    Egress gate: the feed must be an existing local file with a
    recognised suffix; URLs are refused.  Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local vulnerability feed path in args.feed"
    text = raw.strip()
    if "://" in text:
        return None, "args.feed must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.feed contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, "args.feed is not an existing file"
    if path.suffix.lower() not in FEED_SUFFIXES:
        return None, f"args.feed must be a vulnerability feed file, got suffix {path.suffix!r}"
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.feed could not be read"
    if size > max_bytes:
        return None, (
            f"args.feed exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller feed"
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
            f"vulnify {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if "feed" not in payload:
        return "this action requires a local vulnerability feed path in args.feed"
    if action == "lookup":
        for key in ("cve_id", "name"):
            if key in payload and (
                not isinstance(payload[key], str) or not payload[key].strip()
            ):
                return f"args.{key} must be a non-empty string when provided"
        has_cve = isinstance(payload.get("cve_id"), str) and bool(
            payload["cve_id"].strip()
        )
        has_name = isinstance(payload.get("name"), str) and bool(
            payload["name"].strip()
        )
        if not has_cve and not has_name:
            return "lookup requires at least one of args.cve_id or args.name"
    return None


def limit_refusal(raw: object) -> tuple[int | None, str | None]:
    """Validate an optional limit argument (1–MAX_RESULTS)."""
    if raw is None:
        return MAX_RESULTS, None
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None, f"args.limit must be an integer between 1 and {MAX_RESULTS}"
    if raw < 1 or raw > MAX_RESULTS:
        return None, f"args.limit must be between 1 and {MAX_RESULTS}"
    return raw, None
