"""Exact-allowlist rules for the m365pwned consent-case reader."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "m365pwned"

ALLOWED_ACTIONS = frozenset({"case_study", "list_case_studies", "list_permissions"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_CASE_BYTES = 64 * 1024 * 1024
MAX_RESULTS = 200
CASE_SUFFIXES = (".json", ".yaml", ".yml")

ARG_KEYS: dict[str, frozenset[str]] = {
    "case_study": frozenset({"cases_file", "case_id", "name"}),
    "list_case_studies": frozenset({"cases_file", "limit"}),
    "list_permissions": frozenset({"cases_file", "case_id"}),
}

CAVEATS = (
    "the input contract is for synthetic cases, but an arbitrary operator file "
    "is not independently proven synthetic; no Microsoft 365 tenant, mailbox, "
    "or tenant-hosted file API is accessed",
    "permission claims come from the caller file and need verification against "
    "the relevant API-owner documentation before operational use",
    "This arm is an educational read-only reference, not an active consent "
    "or data-access probe.",
)

ARMING = (
    "pass args.cases_file (path to a local JSON or YAML file containing "
    "case studies intended to be synthetic; the arm does not prove provenance)"
)


def cases_file_refusal(raw: object) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied cases file path.  Returns (path, refusal)."""
    import os
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local cases file in args.cases_file"
    text = raw.strip()
    if "://" in text:
        return None, "args.cases_file must be a local path, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.cases_file contains control characters"
    path = Path(text).expanduser().resolve()
    if path == Path(path.anchor) or path.parent == path:
        return None, "args.cases_file must not be a filesystem root"
    if not path.exists():
        return None, "args.cases_file does not exist"
    if not path.is_file():
        return None, "args.cases_file is not a file"
    if path.suffix.lower() not in CASE_SUFFIXES:
        return None, "args.cases_file must be a JSON or YAML file"
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, "could not stat cases file"
    if size > MAX_CASE_BYTES:
        return None, f"args.cases_file exceeds {MAX_CASE_BYTES} byte cap"
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
            f"m365pwned {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if "cases_file" not in payload:
        return "this action requires a local cases file in args.cases_file"
    if action == "case_study":
        has_id = isinstance(payload.get("case_id"), str) and bool(payload["case_id"].strip())
        has_name = isinstance(payload.get("name"), str) and bool(payload["name"].strip())
        if has_id == has_name:
            return "case_study requires exactly one of args.case_id or args.name"
    if action == "list_case_studies":
        _limit, refusal = limit_refusal(payload.get("limit"))
        if refusal:
            return refusal
    if action == "list_permissions" and (
        not isinstance(payload.get("case_id"), str) or not payload["case_id"].strip()
    ):
        return "list_permissions requires a non-empty args.case_id"
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
