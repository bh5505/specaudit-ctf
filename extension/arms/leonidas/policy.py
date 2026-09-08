"""Fixed-argv rules for the leonidas CLI arm."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "leonidas"

# Read tier: exact lookups over a local Leonidas corpus.  There is no
# dispatch tier: the arm is an in-process stdlib reader with no
# subprocess, no endpoint, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"technique", "list_techniques"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_CORPUS_BYTES = 64 * 1024 * 1024  # 64 MiB
CORPUS_SUFFIXES = (".json", ".yaml", ".yml")
MAX_RESULTS = 200
MAX_RECORDS = 10_000
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 64

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "technique": frozenset({"corpus", "technique_id", "name"}),
    "list_techniques": frozenset({"corpus", "limit"}),
}

CAVEATS = (
    "first-party reader over an operator-supplied declarative compatibility corpus",
    "executor bodies are treated as inert text and never executed",
    "the arm obtains or uses no cloud credentials; operator corpora must exclude secrets",
    "the input digest does not establish upstream revision, schema equivalence, or rights",
)

ARMING = (
    "pass args.corpus (path to a local Leonidas corpus file in "
    "JSON or YAML)"
)


def corpus_refusal(
    raw: object, *, max_bytes: int = MAX_CORPUS_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local corpus path.

    Egress gate: the corpus must be an existing local file with a
    JSON/YAML suffix; URLs are refused.  Returns (path, None) or
    (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local Leonidas corpus path in args.corpus"
    text = raw.strip()
    if "://" in text:
        return None, "args.corpus must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.corpus contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, "args.corpus is not an existing file"
    if path.suffix.lower() not in CORPUS_SUFFIXES:
        return None, (
            f"args.corpus must be a JSON or YAML file, "
            f"got suffix {path.suffix!r}"
        )
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.corpus could not be read"
    if size > max_bytes:
        return None, (
            f"args.corpus exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller corpus"
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
            f"leonidas {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if not {"corpus"} <= set(payload):
        return "this action requires a local Leonidas corpus path in args.corpus"
    if action == "technique":
        given = sum(
            1
            for key in ("technique_id", "name")
            if isinstance(payload.get(key), str) and payload[key].strip()
        )
        if given != 1:
            return "technique requires exactly one of args.technique_id or args.name"
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
