"""Exact-allowlist rules for the attack-stix-data read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "attack-stix-data"

# Read tier: exact lookups over a local STIX bundle. There is no
# dispatch tier: the arm is an in-process stdlib reader with no
# subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"technique", "software", "group", "relationships"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_CHARS = 200_000
DESCRIPTION_CHARS = 1_500
BUNDLE_SUFFIXES = (".json", ".stix", ".stix2")

DEMO_BUNDLE_NAME = "demo-enterprise-sample.json"

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "technique": frozenset({"bundle", "id", "name"}),
    "software": frozenset({"bundle", "name"}),
    "group": frozenset({"bundle", "name"}),
    "relationships": frozenset({"bundle", "id", "name", "type"}),
}

CAVEATS = (
    "offline read tier over an operator-supplied local STIX bundle",
    "exact lookups only, no enumeration",
    "the shipped demo bundle is a small verbatim ATT&CK sample, "
    "not a current corpus (see NOTICE.md)",
)

ARMING = (
    "pass args.bundle (an existing local STIX 2.1 JSON bundle path); "
    "the sampled demo bundle ships at extension/arms/attackstix/data/"
    + DEMO_BUNDLE_NAME
)


def demo_bundle_path() -> Path:
    return Path(__file__).resolve().parent / "data" / DEMO_BUNDLE_NAME


def bundle_refusal(
    raw: object, *, max_bytes: int = MAX_BUNDLE_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local bundle path.

    Egress gate: the bundle must be an existing local file with a STIX
    suffix; URLs are refused. Returns (path, None) or (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local STIX bundle path in args.bundle"
    text = raw.strip()
    if "://" in text:
        return None, "args.bundle must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.bundle contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.bundle is not an existing file: {text}"
    if path.suffix.lower() not in BUNDLE_SUFFIXES:
        return None, f"args.bundle must be a STIX bundle file, got suffix {path.suffix!r}"
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.bundle could not be read: {exc}"
    if size > max_bytes:
        return None, (
            f"args.bundle exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller bundle"
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
            f"attack-stix-data {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"bundle"} <= set(payload):
        return "this action requires a local STIX bundle path in args.bundle"
    if action in ("technique", "relationships"):
        given = ("id" in payload) + ("name" in payload)
        if given != 1:
            return f"{action} requires exactly one of args.id or args.name"
    if action in ("software", "group") and not str(payload.get("name") or "").strip():
        return f"{action} requires args.name"
    return None
