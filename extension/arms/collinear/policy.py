"""Exact-allowlist rules for the collinear read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "collinear"

ALLOWED_ACTIONS = frozenset({"scenario", "list_scenarios", "verify"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_SCENARIOS_BYTES = 64 * 1024 * 1024
SCENARIOS_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200

ARG_KEYS: dict[str, frozenset[str]] = {
    "scenario": frozenset({"scenarios_file", "scenario_id", "name"}),
    "list_scenarios": frozenset({"scenarios_file", "limit"}),
    "verify": frozenset({"scenarios_file", "scenario_id", "submission"}),
}

CAVEATS = (
    "learner and model cannot read expected findings or trace keys",
    "forged or truncated evidence fails closed",
    "task/environment/verifier separation maintained at all times",
)

ARMING = (
    "pass args.scenarios_file (path to a local scenarios file); "
    "expected findings and trace keys are instructor-held and never returned to the read path"
)


def scenarios_refusal(raw: object, *, max_bytes: int = MAX_SCENARIOS_BYTES) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied scenarios file path.  Egress gate."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local scenarios file in args.scenarios_file"
    text = raw.strip()
    if "://" in text:
        return None, "args.scenarios_file must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.scenarios_file contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.scenarios_file is not an existing file: {text}"
    if path.suffix.lower() not in SCENARIOS_SUFFIXES:
        return None, f"args.scenarios_file must be a JSON or YAML file, got suffix {path.suffix!r}"
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.scenarios_file could not be read: {exc}"
    if size > max_bytes:
        return None, (
            f"args.scenarios_file exceeds the {max_bytes} byte read cap "
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
            f"collinear {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"scenarios_file"} <= set(payload):
        return "this action requires a local scenarios file in args.scenarios_file"
    if action == "scenario":
        sid = str(payload.get("scenario_id") or "").strip()
        name = str(payload.get("name") or "").strip()
        if not sid and not name:
            return "scenario requires args.scenario_id or args.name"
    if action == "verify":
        if not str(payload.get("scenario_id") or "").strip():
            return "verify requires args.scenario_id"
        if "submission" not in payload:
            return "verify requires args.submission"
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
