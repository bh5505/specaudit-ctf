"""Exact-allowlist rules for the vulnify read arm.

True merge of two implementations:
  * main's feed-based reader (args.feed; json/jsonl/yaml; single cve_id/name
    lookup; list_vulns) — the base, wired into the trusted-observation layer;
  * the feature-branch snapshot/batch layer (args.bundle_path + args.cve_ids
    list over a frozen local JSON snapshot, Finding-E curated fallback, custody
    receipt).
Both interfaces coexist; `lookup` dispatches on which caller arg is present.
"""

from __future__ import annotations

from pathlib import Path

ARM_ID = "vulnify"

# Read tier: exact lookups over a local vulnerability feed or snapshot. There
# is no dispatch tier: the arm is an in-process bounded local-file reader with
# no subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"lookup", "list_vulns"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_FEED_BYTES = 64 * 1024 * 1024
FEED_SUFFIXES = (".json", ".jsonl", ".yaml", ".yml")
MAX_RESULTS = 200
MAX_RECORDS = 10_000
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 64

# Feature-branch snapshot/batch layer bounds.
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
BUNDLE_SUFFIXES = (".json",)
DEMO_BUNDLE_NAME = "demo-vulnerability-snapshot.json"

# Per-action caller-argument contracts (everything else is refused). `lookup`
# admits both the feed interface (feed + cve_id/name) and the batch interface
# (bundle_path + cve_ids); `list_vulns` is feed-only.
ARG_KEYS: dict[str, frozenset[str]] = {
    "lookup": frozenset({"feed", "cve_id", "name", "cve_ids", "bundle_path"}),
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
    "batch lookups (args.cve_ids) read a frozen operator-supplied local JSON "
    "snapshot and emit a JSON custody receipt to stderr",
)

ARMING = (
    "pass args.feed (path to a local vulnerability feed file) for single "
    "lookups and list_vulns, or args.bundle_path (a frozen local JSON "
    "snapshot) with args.cve_ids for batch lookups; every record traces to "
    "the supplied snapshot's exact-byte digest"
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


def bundle_refusal(raw: object, *, max_bytes: int = MAX_BUNDLE_BYTES) -> tuple[Path | None, str | None]:
    """Validate a bounded caller-supplied local JSON snapshot path (batch layer)."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "lookup requires a local JSON snapshot path in args.bundle_path"
    text = raw.strip()
    if "://" in text:
        return None, "args.bundle_path must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.bundle_path contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.bundle_path is not an existing file: {text}"
    if path.suffix.lower() not in BUNDLE_SUFFIXES:
        return None, "args.bundle_path must name a JSON file"
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.bundle_path could not be read: {exc}"
    if size > max_bytes:
        return None, f"args.bundle_path exceeds the {max_bytes} byte read cap ({size} bytes)"
    return path, None


def demo_bundle_path() -> Path:
    return Path(__file__).resolve().parent / "data" / DEMO_BUNDLE_NAME


def args_refusal(action: str, payload: dict) -> str | None:
    """Refuse unknown or missing caller arguments per action.

    `lookup` admits two interfaces: the batch interface (args.cve_ids list
    over args.bundle_path) and the feed interface (args.feed with at least one
    of args.cve_id / args.name). `list_vulns` is feed-only.
    """
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
    if action == "lookup":
        if "cve_ids" in payload:
            raw_ids = payload.get("cve_ids")
            if not isinstance(raw_ids, list):
                return "args.cve_ids must be a list of CVE identifiers"
            if "bundle_path" not in payload:
                return "lookup with args.cve_ids requires args.bundle_path"
            return None
        if "feed" not in payload:
            return "this action requires a local vulnerability feed path in args.feed"
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
    if "feed" not in payload:
        return "this action requires a local vulnerability feed path in args.feed"
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
