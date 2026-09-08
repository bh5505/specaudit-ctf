"""Exact-allowlist rules for the specterops-skills read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "specterops-skills"

# Read tier: exact lookups over a local SpecterOps skills catalog.
# There is no dispatch tier: the arm is an in-process stdlib reader
# with no subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"skill", "list_skills"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_CATALOG_BYTES = 64 * 1024 * 1024
CATALOG_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "skill": frozenset({"catalog", "skill_id", "name"}),
    "list_skills": frozenset({"catalog", "limit", "category"}),
}

CAVEATS = (
    "every retained instruction maps to a bounded tool or a human step; "
    "skill prose is untrusted input and grants no permission",
    "operator must validate skill-to-tool mappings before use",
    "no execution authority granted by skill presence",
)

ARMING = "pass args.catalog (path to a local SpecterOps skills catalog file)"


def catalog_refusal(
    raw: object, *, max_bytes: int = MAX_CATALOG_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local catalog path.

    Egress gate: the catalog must be an existing local file with a
    recognized suffix; URLs are refused. Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local skills catalog path in args.catalog"
    text = raw.strip()
    if "://" in text:
        return None, "args.catalog must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.catalog contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.catalog is not an existing file: {text}"
    if path.suffix.lower() not in CATALOG_SUFFIXES:
        return (
            None,
            f"args.catalog must be a JSON or YAML file, got suffix {path.suffix!r}",
        )
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.catalog could not be read: {exc}"
    if size > max_bytes:
        return None, (
            f"args.catalog exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller catalog"
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
            f"specterops-skills {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"catalog"} <= set(payload):
        return "this action requires a local skills catalog path in args.catalog"
    if action == "skill":
        has_id = isinstance(payload.get("skill_id"), str) and payload[
            "skill_id"
        ].strip()
        has_name = isinstance(payload.get("name"), str) and payload["name"].strip()
        if not has_id and not has_name:
            return "skill requires exactly one of args.skill_id or args.name"
    if action == "list_skills":
        limit_refusal_msg = limit_refusal(payload.get("limit"))
        if limit_refusal_msg:
            return limit_refusal_msg
    return None


def limit_refusal(raw: object) -> str | None:
    """Validate an optional limit argument (1-200)."""
    if raw is None:
        return None
    if not isinstance(raw, int):
        return "args.limit must be an integer between 1 and 200"
    if raw < 1 or raw > 200:
        return "args.limit must be between 1 and 200"
    return None
