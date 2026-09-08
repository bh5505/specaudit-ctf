"""Exact-allowlist rules for the numasec finding lifecycle read arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "numasec"

# Read tier: finding lifecycle reads over a local finding ledger.
# There is no dispatch tier: the arm is an in-process stdlib reader
# with no subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"finding", "list_findings", "list_transitions"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_LEDGER_BYTES = 64 * 1024 * 1024
LEDGER_SUFFIXES = (".json", ".jsonl")
MAX_RESULTS = 200

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "finding": frozenset({"ledger", "finding_id"}),
    "list_findings": frozenset({"ledger", "limit", "status"}),
    "list_transitions": frozenset({"ledger", "finding_id"}),
}

CAVEATS = (
    "status changes are attributable and reversible — every transition "
    "records an actor and a reason",
    "no model-only status change creates a verified finding; only an "
    "explicit operator-attributed transition with a reason can mark a "
    "finding as verified",
    "every change has an actor and reason — transitions lacking either "
    "are rejected as malformed",
    "the ledger is an opaque local snapshot; the arm does not augment "
    "or refresh records",
    "offline read tier — no mutation, no network, no subprocess",
    "source and snapshot digests should appear in evidence metadata",
)

ARMING = (
    "pass args.ledger (path to a local finding lifecycle JSON/JSONL file); "
    "every record traces to a pinned snapshot digest"
)


def ledger_refusal(
    raw: object, *, max_bytes: int = MAX_LEDGER_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local ledger path.

    Egress gate: the ledger must be an existing local file with a
    recognised suffix; URLs are refused.  Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local finding ledger path in args.ledger"
    text = raw.strip()
    if "://" in text:
        return None, "args.ledger must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.ledger contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.ledger is not an existing file: {text}"
    if path.suffix.lower() not in LEDGER_SUFFIXES:
        return None, (
            f"args.ledger must be a finding lifecycle file (.json or .jsonl), "
            f"got suffix {path.suffix!r}"
        )
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"args.ledger could not be read: {exc}"
    if size > max_bytes:
        return None, (
            f"args.ledger exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller ledger"
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
            f"numasec {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if "ledger" not in payload:
        return "this action requires a local finding ledger path in args.ledger"
    if action in ("finding", "list_transitions"):
        fid = payload.get("finding_id")
        if not isinstance(fid, str) or not fid.strip():
            return f"{action} requires a non-empty string in args.finding_id"
    return None


def limit_refusal(raw: object) -> tuple[int | None, str | None]:
    """Validate an optional limit argument (1–MAX_RESULTS)."""
    if raw is None:
        return MAX_RESULTS, None
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None, "args.limit must be an integer between 1 and 200"
    if raw < 1 or raw > MAX_RESULTS:
        return None, f"args.limit must be between 1 and {MAX_RESULTS}"
    return raw, None
