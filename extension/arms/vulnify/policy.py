"""Exact-allowlist rules for the vulnify local snapshot arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "vulnify"
ALLOWED_ACTIONS = frozenset({"lookup"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
ARG_KEYS = {"lookup": frozenset({"bundle_path", "cve_ids"})}

MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_CHARS = 200_000
BUNDLE_SUFFIXES = (".json",)
DEMO_BUNDLE_NAME = "demo-vulnerability-snapshot.json"

CAVEATS = (
    "offline read tier over a frozen operator-supplied local JSON snapshot",
    "exact CVE identifiers only; no search, enumeration, network, or database mutation",
    "missing enrichment remains null rather than being inferred",
    "every lookup outcome writes a JSON custody receipt to stderr",
    "the shipped snapshot is deterministic fake test data, not a current vulnerability corpus",
)
ARMING = "pass args.bundle_path naming an existing local JSON snapshot"


def demo_bundle_path() -> Path:
    return Path(__file__).resolve().parent / "data" / DEMO_BUNDLE_NAME


def bundle_refusal(raw: object, *, max_bytes: int = MAX_BUNDLE_BYTES) -> tuple[Path | None, str | None]:
    """Validate a bounded caller-supplied local JSON snapshot path."""
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


def args_refusal(action: str, payload: dict) -> str | None:
    allowed = ARG_KEYS.get(action)
    if allowed is None:
        return f"action {action!r} is not on the read allowlist"
    extra = sorted(set(payload) - allowed)
    if extra:
        return "vulnify lookup takes only args.bundle_path, args.cve_ids " + f"(unexpected: {', '.join(extra)})"
    if "bundle_path" not in payload:
        return "lookup requires args.bundle_path"
    if "cve_ids" not in payload:
        return "lookup requires args.cve_ids"
    return None
