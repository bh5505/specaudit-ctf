"""Fixed-argv rules for the gpohound CLI arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "gpohound"

# Read tier: exact lookups over a local GPO policy evidence file.
# There is no dispatch tier: the arm is an in-process stdlib reader
# with no subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"policy", "list_policies", "list_links"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024  # 64 MiB
EVIDENCE_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "policy": frozenset({"evidence", "policy_id", "name"}),
    "list_policies": frozenset({"evidence", "limit", "status"}),
    "list_links": frozenset({"evidence", "gpo_id"}),
}

CAVEATS = (
    "filtered-out policy is NOT effective access",
    "security filters and WMI filters are not fully covered and "
    "should be validated separately",
    "no shared-graph writes; this is a read-only evidence arm",
)

ARMING = (
    "pass args.evidence (path to a local GPO policy evidence file in "
    "JSON or YAML)"
)


def evidence_refusal(
    raw: object, *, max_bytes: int = MAX_EVIDENCE_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local evidence path.

    Egress gate: the evidence must be an existing local file with a
    JSON/YAML suffix; URLs are refused.  Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local GPO evidence path in args.evidence"
    text = raw.strip()
    if "://" in text:
        return None, "args.evidence must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.evidence contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, "args.evidence is not an existing file"
    if path.suffix.lower() not in EVIDENCE_SUFFIXES:
        return None, (
            f"args.evidence must be a JSON or YAML file, "
            f"got suffix {path.suffix!r}"
        )
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.evidence could not be read"
    if size > max_bytes:
        return None, (
            f"args.evidence exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller evidence file"
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
            f"gpohound {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"evidence"} <= set(payload):
        return "this action requires a local GPO evidence path in args.evidence"
    if action == "policy":
        pid = payload.get("policy_id")
        name = payload.get("name")
        has_pid = isinstance(pid, str) and bool(pid.strip())
        has_name = isinstance(name, str) and bool(name.strip())
        if has_pid == has_name:
            return "policy requires exactly one of args.policy_id or args.name"
    if action == "list_links":
        if not isinstance(payload.get("gpo_id"), str) or not payload["gpo_id"].strip():
            return "list_links requires args.gpo_id"
    if action == "list_policies":
        result = limit_refusal(payload.get("limit"))
        if isinstance(result, str):
            return result
        if "status" in payload and (
            not isinstance(payload["status"], str) or not payload["status"].strip()
        ):
            return "args.status must be a non-empty string"
    return None


def limit_refusal(raw: object) -> int | str:
    """Validate and return the list limit (1..MAX_RESULTS) or a refusal."""
    if raw is None:
        return MAX_RESULTS
    if not isinstance(raw, int) or isinstance(raw, bool):
        return f"args.limit must be an integer (1-{MAX_RESULTS})"
    if raw < 1 or raw > MAX_RESULTS:
        return f"args.limit must be between 1 and {MAX_RESULTS}"
    return raw
