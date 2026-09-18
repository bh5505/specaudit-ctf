"""Exact-allowlist rules for the agentseal read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "agentseal"

# Read tier: analysis over a local static fixture file.  There is no
# dispatch tier: the arm is an in-process bounded local-file reader with no
# subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"analyze", "list_scenarios"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_FIXTURE_BYTES = 64 * 1024 * 1024
FIXTURE_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200
MAX_RECORDS = 10_000
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 64

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "analyze": frozenset({"fixture", "scenario_id", "limit"}),
    "list_scenarios": frozenset({"fixture", "limit"}),
}

CAVEATS = (
    "offline boundary must be verified — no registry or network calls",
    "every result cites specific configuration evidence",
    "no active modes exposed; read-only static fixture analysis",
)

ARMING = "pass args.fixture (path to a local static analysis fixture file)"


def fixture_refusal(
    raw: object, *, max_bytes: int = MAX_FIXTURE_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local fixture path.

    Egress gate: the fixture must be an existing local file with an
    accepted suffix; URLs are refused.  Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local fixture path in args.fixture"
    text = raw.strip()
    if "://" in text:
        return None, "args.fixture must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.fixture contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, "args.fixture is not an existing file"
    if path.suffix.lower() not in FIXTURE_SUFFIXES:
        return (
            None,
            f"args.fixture must be a static analysis fixture, got suffix {path.suffix!r}",
        )
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.fixture could not be read"
    if size > max_bytes:
        return None, (
            f"args.fixture exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller fixture"
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
            f"agentseal {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"fixture"} <= set(payload):
        return "this action requires a local fixture path in args.fixture"
    if "scenario_id" in payload:
        scenario_id = payload["scenario_id"]
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            return "args.scenario_id must be a non-empty string"
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
