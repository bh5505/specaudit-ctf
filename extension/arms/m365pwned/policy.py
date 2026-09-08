"""Exact-allowlist rules for the m365pwned synthetic consent arm."""

from __future__ import annotations

ARM_ID = "m365pwned"

ALLOWED_ACTIONS = frozenset({"case_study", "list_case_studies", "list_permissions"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_CASE_BYTES = 64 * 1024 * 1024
MAX_RESULTS = 200

ARG_KEYS: dict[str, frozenset[str]] = {
    "case_study": frozenset({"cases_file", "case_id", "name"}),
    "list_case_studies": frozenset({"cases_file", "limit"}),
    "list_permissions": frozenset({"cases_file", "case_id"}),
}

CAVEATS = (
    "All case studies are synthetic; no real tenant, mailbox, or file is accessed.",
    "Permission claims are derived from curated synthetic scenarios and need "
    "verification against the relevant API owner documentation before "
    "operational use.",
    "This arm is an educational read-only reference, not an active consent "
    "or data-access probe.",
)

ARMING = "pass args.cases_file (path to a local JSON file containing synthetic case studies)"


def cases_file_refusal(raw: object) -> tuple[str | None, str | None]:
    """Validate a caller-supplied cases file path.  Returns (path, refusal)."""
    import os
    from pathlib import Path

    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local cases file in args.cases_file"
    text = raw.strip()
    if "://" in text:
        return None, "args.cases_file must be a local path, not a URL"
    path = Path(text).expanduser().resolve()
    if path == path.anchor or path.parent == path:
        return None, "args.cases_file must not be a filesystem root"
    if not path.exists():
        return None, f"args.cases_file does not exist: {text}"
    if not path.is_file():
        return None, f"args.cases_file is not a file: {text}"
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return None, f"could not stat cases file: {exc}"
    if size > MAX_CASE_BYTES:
        return None, f"args.cases_file exceeds {MAX_CASE_BYTES} byte cap"
    return str(path), None


def args_refusal(action: str, payload: dict) -> str | None:
    """Refuse unknown or missing caller arguments per action."""
    allowed = ARG_KEYS.get(action)
    if allowed is None:
        return f"action {action!r} is not on the read allowlist"
    extra = sorted(set(payload) - allowed)
    if extra:
        return (
            f"m365pwned {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if "cases_file" not in payload:
        return "this action requires a local cases file in args.cases_file"
    if action == "case_study":
        has_id = bool(str(payload.get("case_id") or "").strip())
        has_name = bool(str(payload.get("name") or "").strip())
        if not has_id and not has_name:
            return "case_study requires args.case_id or args.name to identify a case"
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
